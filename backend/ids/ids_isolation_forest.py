"""
IDS — Isolation Forest anomaly detector (method #2).

Unsupervised ML detector trained ONLY on clean TRAIN (70% of normal.csv), using
the SAME chronological split as the heuristic (method #1) — the no-leak protocol
in ids_heuristic.py — but its OWN featurization and model shape, chosen honestly
for what isolation forest is actually good at.

Why NOT the per-(CAN_ID, 1s-window) featurization of ids_features.py?
  A single injected frame is invisible at window granularity: one clean window
  carries ~1950 frames, so one (or even an 8-frame) spoof moves the window-wide
  rate/gap/delta aggregates by ~0.05%. A forest trained on those aggregates is
  structurally blind to the single-frame spoofs that the red-team manifests
  (dataset /injection_manifest_1/2/3.json) actually contain. Per-id profiling
  (one forest per CAN-ID) fixes the "washed-out average" but still cannot see a
  single frame inside its own 1s bin.

Design chosen here (the honest best for this data), in three decisions:

  1. PER-FRAME (not per-window, not per-ID) — the unit of detection is the single
     frame, which is what the manifests inject.

  2. Z-SCORE features against each ID's own clean baseline. A CAN byte means
     something different per CAN_ID, so each frame is expressed as a deviation of
     its payload bytes and inter-arrival gap from that ID's clean value/gap
     distribution. Clean frames are ~N(0,1) on every coordinate; a spoof blows up
     one or more bytes to |z| of tens or hundreds.

  3. CONCENTRATED (3 features, not 9). Feeding 8 raw per-byte z-scores + gap_z
     into one global forest DILUTES the signal: a spoof alters only 1-3 bytes, so
     6-7 coordinates stay ~0 and the average path length barely moves (verified
     empirically — max|z| of 494 was still scoring "normal"). Aggregating the
     payload deviation into *height* (max_abs_z), *breadth* (n_over_2) and keeping
     the *rhythm* (gap_z) concentrates the anomaly so the forest isolates it.

Per-frame feature vector (3 numeric):
  gap_z     : (gap - period_mean) / max(period_std, EPS)     [DoS burst -> very -]
  max_abs_z : max over the 8 payload bytes of |byte_z|        [spoof magnitude]
  n_over_2  : how many payload bytes have |byte_z| > 2        [spoof breadth]

  Unknown CAN_ID handling (out-of-band, mirrors heuristic test1): a frame whose
  ID has no clean baseline has no z-score and is flagged by a plain membership
  test, NOT by the forest. The manifests contain only known IDs, so this rule is
  inert for the manifest evaluation — the forest is judged purely on its own
  payload/rhythm isolation of known IDs.

Pipeline (same no-leak protocol as the heuristic):
  1. TRAIN/VALID/TEST-normal split (shared helpers, ids_heuristic.load_normal_split).
  2. Learn per-ID clean baseline (period mean/std + per-byte value mean/std) from TRAIN.
  3. Extract PER-FRAME z-score features for TRAIN, fit one global IsolationForest.
  4. Calibrate one decision threshold on VALID (target FPR ~ 0).
  5. Evaluate:
       - TEST-normal FPR (honest generalization, not just VALID).
       - the 4 whole attack files (frame-level coverage, continuity with method #1).
       - the 3 red-team injection manifests (single injected frames) — the HONEST
         test the heuristic used, so methods #1 and #2 are 1:1 comparable.

Run:  .venv/bin/python backend/ids/ids_isolation_forest.py
"""
from __future__ import annotations

import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ids_heuristic import (
    ATTACK_LABELS,
    BCOLS,
    DATA,
    _parse_hex_byte,
    load_normal_split,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_PATH = os.path.join(HERE, "ids_isolation_forest.joblib")

# Manifests (red-team injection test) live next to the normalized dataset.
_MANIFEST_DIR = os.path.dirname(DATA)
MANIFEST_PATHS = [os.path.join(_MANIFEST_DIR, f"injection_manifest_{i}.json")
                  for i in range(1, 4)]

# Floor for a zero/near-zero clean std before forming z-scores. A truly STATIC
# byte has clean std = 0; floored to EPS it becomes a near-perfect discriminator
# (any deviation -> huge |z|), while genuinely DYNAMIC bytes keep their real
# (large) std so their chatter stays ~0. Same floor for gap std.
EPS = 0.5

# A payload byte is counted as "deviating" once |z| exceeds this (breadth).
OVER_THRESH = 2.0

# Numeric per-frame features fed to the forest (order is fixed and stable).
FEATURES = ["gap_z", "max_abs_z", "n_over_2"]


# --- baseline learning -------------------------------------------------------

def learn_baseline(train: pd.DataFrame) -> pd.DataFrame:
    """Per-ID clean baseline: period mean/std + per-byte value mean/std.

    Learned ONLY from clean TRAIN (never attack data).
    """
    bts = train[BCOLS].map(_parse_hex_byte).astype("int64").to_numpy()
    rows = []
    for cid, g in train.groupby("CAN_ID", sort=False):
        g = g.sort_values("Timestamp")
        ts = g["Timestamp"].to_numpy()
        dt = np.diff(ts)
        pm = float(np.median(dt)) if len(dt) else np.nan
        ps = float(np.std(dt)) if len(dt) else np.nan

        rec = {"CAN_ID": str(cid), "period_mean": pm, "period_std": ps}
        cols = bts[g.index.to_numpy()].astype(float)
        for i in range(8):
            rec[f"byte{i}_mean"] = float(cols[:, i].mean())
            rec[f"byte{i}_std"] = float(cols[:, i].std())
        rows.append(rec)
    return pd.DataFrame(rows)


def _baseline_maps(baseline: pd.DataFrame):
    per = {r.CAN_ID: r for r in baseline.itertuples()}
    known = set(baseline["CAN_ID"].astype(str))
    return per, known


def _z(value: float, mean: float, std: float) -> float:
    """(value - mean) / max(std, EPS), NaN-safe."""
    if mean is None or std is None or np.isnan(mean) or np.isnan(std):
        return 0.0
    return float((value - mean) / max(std, EPS))


def _payload_zs(pay: np.ndarray, row) -> np.ndarray:
    """The 8 per-byte z-scores of a payload against a baseline row (or zeros)."""
    if row is None:
        return np.zeros(8)
    return np.array([
        _z(float(pay[i]), getattr(row, f"byte{i}_mean"),
           getattr(row, f"byte{i}_std"))
        for i in range(8)
    ])


def _frame_features(pay: np.ndarray, gap: float | None, row) -> dict:
    """Concentrated per-frame feature dict for one frame (payload + gap)."""
    zs = _payload_zs(pay, row)
    if row is None or gap is None:
        gap_z = 0.0
    else:
        gap_z = _z(gap, row.period_mean, row.period_std)
    return {
        "gap_z": gap_z,
        "max_abs_z": float(np.max(np.abs(zs))) if len(zs) else 0.0,
        "n_over_2": float(np.sum(np.abs(zs) > OVER_THRESH)),
    }


# --- featurization -----------------------------------------------------------

def extract_frame_features(df: pd.DataFrame,
                           baseline: pd.DataFrame) -> tuple[pd.DataFrame, np.ndarray]:
    """Return (features DataFrame, unknown_mask) for per-frame scoring.

    features: one row per frame with FEATURES columns.
    unknown_mask: True where the frame's CAN_ID has no baseline (foreign id);
    flagged out-of-band by the caller, not the forest.
    """
    per, _known = _baseline_maps(baseline)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    bts = df[BCOLS].map(_parse_hex_byte).astype("int64").to_numpy()
    cids = df["CAN_ID"].astype(str).to_numpy()
    ts = df["Timestamp"].to_numpy()
    n = len(df)

    data = {f: np.zeros(n) for f in FEATURES}
    unknown = np.zeros(n, dtype=bool)
    prev_ts: dict[str, float] = {}

    for i in range(n):
        c = cids[i]
        row = per.get(c)
        if row is None:
            unknown[i] = True
            prev_ts[c] = ts[i]
            continue
        gap = ts[i] - prev_ts[c] if c in prev_ts else None
        f = _frame_features(bts[i], gap, row)
        for k in FEATURES:
            data[k][i] = f[k]
        prev_ts[c] = ts[i]

    feat = pd.DataFrame(data)
    feat.insert(0, "can_id", cids)
    return feat, unknown


# --- model -------------------------------------------------------------------

class GlobalIsolationForest:
    """One global IsolationForest + one decision threshold + known-ID set."""

    def __init__(self, model: IsolationForest, threshold: float,
                 known_ids: set[str]):
        self.model = model
        self.threshold = threshold
        self.known_ids = known_ids

    def _X(self, feat: pd.DataFrame) -> np.ndarray:
        return feat[FEATURES].astype(float).to_numpy()

    def score(self, feat: pd.DataFrame) -> np.ndarray:
        return self.model.decision_function(self._X(feat))

    def predict(self, feat: pd.DataFrame,
                unknown_mask: np.ndarray | None = None) -> pd.DataFrame:
        out = feat.copy()
        out["score"] = self.score(feat)
        out["anomaly"] = (out["score"] < self.threshold).astype(int)
        if unknown_mask is not None:
            out.loc[unknown_mask, "anomaly"] = 1  # foreign id -> anomaly (out-of-band)
        return out

    def to_dict(self) -> dict:
        return {"model": self.model, "threshold": self.threshold,
                "known_ids": self.known_ids}


def save_model(gif: GlobalIsolationForest, path: str = ARTIFACT_PATH) -> None:
    """Persist as a plain dict (sklearn model + scalar threshold + id set) so the
    artifact reloads from anywhere without a custom-class pickling dependency."""
    joblib.dump(gif.to_dict(), path)


def load_model(path: str = ARTIFACT_PATH) -> GlobalIsolationForest:
    """Load the persisted detector and rebuild the wrapper."""
    d = joblib.load(path)
    return GlobalIsolationForest(d["model"], d["threshold"], d["known_ids"])


def fit(train_feat: pd.DataFrame, n_estimators: int = 300,
        random_state: int = 0) -> IsolationForest:
    X = train_feat[FEATURES].astype(float).to_numpy()
    model = IsolationForest(n_estimators=n_estimators, contamination="auto",
                            random_state=random_state, n_jobs=-1)
    model.fit(X)
    return model


def calibrate(model: GlobalIsolationForest, val_feat: pd.DataFrame) -> None:
    """Set one global threshold = min VALID decision score (strict FPR=0 on VALID)."""
    sc = model.score(val_feat)
    model.threshold = float(np.min(sc[np.isfinite(sc)]))


# --- evaluation -------------------------------------------------------------

def _runs(flagged: list[int]) -> list[tuple[int, int]]:
    spans: list[list[int]] = []
    for w in flagged:
        if spans and w == spans[-1][1] + 1:
            spans[-1][1] = w
        else:
            spans.append([w, w])
    return [(s, e) for s, e in spans]


def _attack_file_summary(model: GlobalIsolationForest,
                         baseline: pd.DataFrame, label: str) -> dict:
    path = os.path.join(DATA, f"{label}.csv")
    dtype = {"CAN_ID": str, **{c: str for c in BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + BCOLS, dtype=dtype)
    feat, unk = extract_frame_features(df, baseline)
    pred = model.predict(feat, unk)
    n = len(pred)
    flagged = sorted(int(i) for i in pred.index[pred["anomaly"] > 0])
    spans = _runs(flagged)
    covered = sum(e - s + 1 for s, e in spans)
    return {"label": label, "frames": n, "flagged": len(flagged),
            "events": len(spans), "coverage": covered / n}


# --- red-team injection (manifests) ------------------------------------------

def _clean_stream() -> pd.DataFrame:
    path = os.path.join(DATA, "normal.csv")
    dtype = {"CAN_ID": str, **{c: str for c in BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + BCOLS, dtype=dtype)
    return df.sort_values("Timestamp").reset_index(drop=True)


def _clean_per_id(clean: pd.DataFrame):
    ts_by_id: dict[str, np.ndarray] = {}
    pay_by_id: dict[str, np.ndarray] = {}
    for cid, g in clean.groupby("CAN_ID", sort=False):
        g = g.sort_values("Timestamp")
        ts_by_id[str(cid)] = g["Timestamp"].to_numpy()
        pay_by_id[str(cid)] = (g[BCOLS].map(_parse_hex_byte)
                               .astype("int64").to_numpy())
    return ts_by_id, pay_by_id


def _prev_clean(ts_arr, pay_arr, t):
    if ts_arr is None or len(ts_arr) == 0:
        return None, None
    idx = int(np.searchsorted(ts_arr, t, side="right")) - 1
    if idx < 0:
        return None, None
    return float(ts_arr[idx]), pay_arr[idx]


def evaluate_manifests(model: GlobalIsolationForest, baseline: pd.DataFrame,
                       per, clean) -> dict:
    """Red-team injection test: how many single injected frames the forest flags.

    Mirrors ids_injection.run_eval semantics: burst records group by
    (attack, trial) and count once if ANY frame is flagged; scatter records each
    count individually.
    """
    ts_by_id, pay_by_id = _clean_per_id(clean)
    agg = {a: {"detected": 0, "total": 0} for a in ATTACK_LABELS}

    for path in MANIFEST_PATHS:
        with open(path) as f:
            manifest = json.load(f)

        groups: dict[tuple, list[dict]] = {}
        order: list[tuple] = []
        for rec in manifest:
            a = rec["attack"]
            if rec["mode"] == "burst":
                key = (a, rec["trial"], "burst")
            else:
                key = (a, rec["trial"], f"scatter:{rec['i']}")
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(rec)

        burst_hits: dict[tuple[str, int], int] = {}
        for key in order:
            a = key[0]
            recs = sorted(groups[key], key=lambda r: r["i"])
            prev_ts = None
            prev_pay = None
            hit = 0
            for rec in recs:
                cid = str(rec["CAN_ID"])
                row = per.get(cid)
                if prev_ts is None:
                    p_ts, p_pay = _prev_clean(ts_by_id.get(cid),
                                              pay_by_id.get(cid),
                                              float(rec["timestamp"]))
                else:
                    p_ts, p_pay = prev_ts, prev_pay
                pay = np.array([_parse_hex_byte(rec[c]) for c in BCOLS],
                               dtype="int64")
                gap = (float(rec["timestamp"]) - p_ts) if p_ts is not None else None
                f = _frame_features(pay, gap, row)
                vec = np.array([[f[k] for k in FEATURES]], dtype=float)
                sc = model.model.decision_function(vec)[0]
                hit = hit or int(sc < model.threshold)
                prev_ts = float(rec["timestamp"])
                prev_pay = pay
            if recs[0]["mode"] == "burst":
                k = (a, recs[0]["trial"])
                burst_hits[k] = burst_hits.get(k, 0) or hit
            else:
                agg[a]["detected"] += hit
                agg[a]["total"] += 1

        for (a, _t), v in burst_hits.items():
            agg[a]["detected"] += v
            agg[a]["total"] += 1

    return agg


def main() -> None:
    print("KORAK 1 – Učitaj + podeli normal.csv (zajednički sa heuristikom)")
    t, v, te = load_normal_split()
    print(f"  TRAIN : {len(t):>9,}  VALID : {len(v):>9,}  TEST : {len(te):>9,}")

    print("\nKORAK 2 – nauči per-ID baseline (perioda + po-bajtu mean/std) iz TRAIN")
    baseline = learn_baseline(t.reset_index(drop=True))
    per, known = _baseline_maps(baseline)
    print(f"  baseline ids : {len(baseline)}")

    print("\nKORAK 3 – per-frame z-score featurizacija + globalni IsolationForest")
    t_feat, _ = extract_frame_features(t.reset_index(drop=True), baseline)
    print(f"  TRAIN frames : {len(t_feat):,}   features: {FEATURES}")
    model = fit(t_feat)
    gif = GlobalIsolationForest(model, float("inf"), known)
    print(f"  model        : 1 global IsolationForest ({len(FEATURES)} features)")

    print("\nKORAK 4 – kalibracija praga na VALID (cilj FPR≈0)")
    v_feat, v_unk = extract_frame_features(v.reset_index(drop=True), baseline)
    calibrate(gif, v_feat)
    v_pred = gif.predict(v_feat, v_unk)
    v_flag = int((v_pred["anomaly"] > 0).sum())
    print(f"  VALID frames : {len(v_feat):,}")
    print(f"  VALID FPR    : {v_flag}/{len(v_feat):,} "
          f"({v_flag/max(len(v_feat),1)*100:.4f}%)")
    print(f"  threshold    : {gif.threshold:.6f}")

    print("\nKORAK 5a – TEST-normal FPR (iskrena generalizacija)")
    te_feat, te_unk = extract_frame_features(te.reset_index(drop=True), baseline)
    te_pred = gif.predict(te_feat, te_unk)
    te_flag = int((te_pred["anomaly"] > 0).sum())
    print(f"  TEST frames  : {len(te_feat):,}")
    print(f"  TEST FPR     : {te_flag}/{len(te_feat):,} "
          f"({te_flag/max(len(te_feat),1)*100:.4f}%)")

    print("\nKORAK 5b – čitavi napad-fajlovi (frame-level coverage, kontinuitet)")
    print(f"{'label':<12}{'frames':>10}{'flagged':>10}{'events':>8}{'coverage':>10}")
    for lbl in ATTACK_LABELS:
        r = _attack_file_summary(gif, baseline, lbl)
        print(f"{r['label']:<12}{r['frames']:>10,}{r['flagged']:>10,}"
              f"{r['events']:>8}{r['coverage']:>10.2%}")

    print("\nKORAK 6 – red-team injection (3 manifesta) — PRAVI test, 1:1 sa heuristikom")
    clean = _clean_stream()
    agg = evaluate_manifests(gif, baseline, per, clean)
    print(f"{'napad':<6}{'detected':>9}{'total':>7}{'detection':>11}")
    for a in ATTACK_LABELS:
        d = agg[a]["detected"]
        tot = agg[a]["total"]
        print(f"{a:<6}{d:>9}{tot:>7}{d/max(tot,1)*100:>10.1f}%")

    print("\nKORAK 7 – perzistiranje modela + known_ids")
    save_model(gif)
    with open(os.path.join(HERE, "ids_if_known_ids.txt"), "w") as fh:
        fh.write("\n".join(sorted(known)))
    print(f"  model -> {ARTIFACT_PATH}")


if __name__ == "__main__":
    main()
