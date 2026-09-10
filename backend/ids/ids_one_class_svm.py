"""
IDS — One-Class SVM anomaly detector (method #3).

Unsupervised ML detector trained ONLY on clean TRAIN (70% of normal.csv), using
the SAME chronological split + no-leak protocol as the heuristic (method #1) and
the Isolation Forest (method #2), and the SAME per-frame z-score features as
method #2 (ids_isolation_forest.py). Methods #2 and #3 differ only in the
decision model, so they are 1:1 comparable on the same red-team manifests.

Shared with Isolation Forest (imported, not re-implemented):
  * learn_baseline          per-ID clean baseline (period + per-byte mean/std)
  * extract_frame_features  per-frame z-score features (gap_z, max_abs_z, n_over_2)
  * _frame_features         single-frame feature builder (for injection probing)
  * FEATURES, EPS, OVER_THRESH, MANIFEST_PATHS, _clean_stream, _clean_per_id,
    _prev_clean, evaluate_manifests, _runs

Why a One-Class SVM here, and how it differs from Isolation Forest:
  * OneClassSVM fits a single tight boundary (in RBF kernel space) around the
    clean density and scores a frame by its SIGNED distance to that boundary
    (score_samples: >0 inlier, <0 outlier). Isolation Forest instead isolates
    points by average path length. The SVM's decision is smoother and directly
    monotonic with "distance from normal", which suits the z-score features.

Two things SVM needs that IF does not (both handled here):
  1. SCALE — SVM is sensitive to feature scale. The z-score features are ~N(0,1)
     for clean but max_abs_z / n_over_2 have heavy upper tails (spoils -> tens/
     hundreds). We standardize using the CLEAN TRAIN robust mean/std so the
     boundary is learned in a scale-free space (robust, since clean has outliers
     too). The same scaler is applied to VALID/TEST/attack/manifest frames.
  2. nu — the upper bound on training error (and fraction of support vectors).
     sklearn's default nu=0.5 assumes ~50% outliers; our TRAIN is 100% clean, so
     nu must be SMALL (we use 0.001) or the SVM will happily label half the clean
     data as anomalous. A tiny nu also yields fewer support vectors, which keeps
     the O(n*n_sv) scoring tractable over the multi-million-frame attack files.

Thresholding: calibrate one decision threshold on clean VALID so FPR ~ 0 (min
VALID score_samples), exactly like the forest's min decision score. Then evaluate
on TEST-normal (honest FPR) and the 3 red-team manifests (the real test).

Run:  .venv/bin/python backend/ids/ids_one_class_svm.py
"""
from __future__ import annotations

import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from sklearn.svm import OneClassSVM

from ids_isolation_forest import (
    BCOLS,
    DATA,
    FEATURES,
    MANIFEST_PATHS,
    _clean_per_id,
    _clean_stream,
    _frame_features,
    _parse_hex_byte,
    _prev_clean,
    _runs,
    _baseline_maps,
    extract_frame_features,
    learn_baseline,
)
from ids_heuristic import ATTACK_LABELS, load_normal_split

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_PATH = os.path.join(HERE, "ids_one_class_svm.joblib")

# One-Class SVM hyper-parameters (RBF kernel). Not a knobs-fest: `nu` is chosen
# because training is all-clean (must be small), `gamma` is chosen to be
# scale-aware and modest so the boundary is smooth, not a per-point bubble.
NU = 0.001
GAMMA = 0.25  # 1/(4*f)d-ish influence radius in standardized space

# RBF OneClassSVM is O(n^2..n^3); 692k frames is infeasible AND unnecessary —
# OCSVM only needs a representative clean sample to learn the density boundary.
# We subsample TRAIN (stratified per CAN_ID so no id is dropped) to this many
# frames before fitting. The scaler is fitted on the same subsample.
N_TRAIN_SUBSAMPLE = 80_000

# Whole-file coverage (KORAK 5b) scores every frame against all support vectors;
# for a RBF OCSVM that is O(n * n_sv) and becomes minutes-per-file over the
# ~3-4M-frame attack recordings. Coverage is a continuity metric (the real test
# is the manifest red-team run), so we score a deterministic capped prefix of
# each attack file and report it as "first N frames". None = score all frames.
ATTACK_COVERAGE_CAP = 1_500_000


class GlobalOneClassSVM:
    """One global OneClassSVM + a scaler + one decision threshold."""

    def __init__(self, model: OneClassSVM, scaler: RobustScaler,
                 threshold: float, known_ids: set[str]):
        self.model = model
        self.scaler = scaler
        self.threshold = threshold
        self.known_ids = known_ids

    def _X(self, feat: pd.DataFrame) -> np.ndarray:
        X = feat[FEATURES].astype(float).to_numpy()
        return self.scaler.transform(X)

    def score(self, feat: pd.DataFrame) -> np.ndarray:
        # signed distance to the boundary: >0 inlier (normal), <0 outlier
        return self.model.score_samples(self._X(feat))

    def score_row(self, X: np.ndarray) -> np.ndarray:
        """Score a raw (n_samples, n_features) matrix (scaler applied)."""
        return self.model.score_samples(self.scaler.transform(X))

    def predict(self, feat: pd.DataFrame,
                unknown_mask: np.ndarray | None = None) -> pd.DataFrame:
        out = feat.copy()
        out["score"] = self.score(feat)
        out["anomaly"] = (out["score"] < self.threshold).astype(int)
        if unknown_mask is not None:
            out.loc[unknown_mask, "anomaly"] = 1  # foreign id -> anomaly (out-of-band)
        return out

    def to_dict(self) -> dict:
        return {"model": self.model, "scaler": self.scaler,
                "threshold": self.threshold, "known_ids": self.known_ids}


def save_model(gif: GlobalOneClassSVM, path: str = ARTIFACT_PATH) -> None:
    joblib.dump(gif.to_dict(), path)


def load_model(path: str = ARTIFACT_PATH) -> GlobalOneClassSVM:
    d = joblib.load(path)
    return GlobalOneClassSVM(d["model"], d["scaler"], d["threshold"],
                             d["known_ids"])


def fit(train_feat: pd.DataFrame, nu: float = NU, gamma: float = GAMMA,
        random_state: int = 0, n_subsample: int = N_TRAIN_SUBSAMPLE
        ) -> tuple[OneClassSVM, RobustScaler]:
    """Fit one global OneClassSVM on standardized clean TRAIN features.

    TRAIN is subsampled (stratified per CAN_ID, capped at n_subsample) because
    a 692k-frame RBF SVM is both infeasible and pointless — the density boundary
    is fully defined by a representative clean sample. The same subsample fits
    the RobustScaler.
    """
    X_full = train_feat[FEATURES].astype(float).to_numpy()
    if len(X_full) > n_subsample:
        rng = np.random.default_rng(random_state)
        keep = np.zeros(len(X_full), dtype=bool)
        cids = train_feat["can_id"].to_numpy()
        for cid in np.unique(cids):
            idx = np.where(cids == cid)[0]
            if len(idx) <= max(1, n_subsample // len(np.unique(cids))):
                keep[idx] = True
            else:
                keep[rng.choice(idx, size=max(1, n_subsample // len(np.unique(cids))),
                                replace=False)] = True
        # cap to n_subsample if stratification overshoots slightly
        X = X_full[keep]
    else:
        X = X_full

    scaler = RobustScaler().fit(X)
    Xs = scaler.transform(X)
    model = OneClassSVM(kernel="rbf", gamma=gamma, nu=nu,
                        shrinking=True, cache_size=500, max_iter=200_000)
    model.fit(Xs)
    return model, scaler


def calibrate(model: GlobalOneClassSVM, val_feat: pd.DataFrame) -> None:
    """Threshold = min clean VALID score_samples (strict FPR=0 on VALID)."""
    sc = model.score(val_feat)
    model.threshold = float(np.min(sc[np.isfinite(sc)]))


def _attack_file_summary(model: GlobalOneClassSVM,
                         baseline: pd.DataFrame, label: str) -> dict:
    path = os.path.join(DATA, f"{label}.csv")
    dtype = {"CAN_ID": str, **{c: str for c in BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + BCOLS, dtype=dtype)
    total = len(df)
    if ATTACK_COVERAGE_CAP and total > ATTACK_COVERAGE_CAP:
        df = df.head(ATTACK_COVERAGE_CAP)  # deterministic prefix; coverage sample
    feat, unk = extract_frame_features(df, baseline)
    pred = model.predict(feat, unk)
    n = len(pred)
    flagged = sorted(int(i) for i in pred.index[pred["anomaly"] > 0])
    spans = _runs(flagged)
    covered = sum(e - s + 1 for s, e in spans)
    return {"label": label, "frames": n, "total_frames": total,
            "flagged": len(flagged),
            "events": len(spans), "coverage": covered / n}


def main() -> None:
    print("KORAK 1 – Učitaj + podeli normal.csv (zajednički sa heuristikom + forestom)")
    t, v, te = load_normal_split()
    print(f"  TRAIN : {len(t):>9,}  VALID : {len(v):>9,}  TEST : {len(te):>9,}")

    print("\nKORAK 2 – nauči per-ID baseline (perioda + po-bajtu mean/std) iz TRAIN")
    baseline = learn_baseline(t.reset_index(drop=True))
    per, known = _baseline_maps(baseline)
    print(f"  baseline ids : {len(baseline)}")

    print("\nKORAK 3 – per-frame z-score featurizacija + trening One-Class SVM")
    t_feat, _ = extract_frame_features(t.reset_index(drop=True), baseline)
    print(f"  TRAIN frames : {len(t_feat):,}   features: {FEATURES}")
    model, scaler = fit(t_feat)
    gsvm = GlobalOneClassSVM(model, scaler, float("-inf"), known)
    print(f"  model        : 1 global OneClassSVM (RBF, nu={NU}, gamma={GAMMA})")

    print("\nKORAK 4 – kalibracija praga na VALID (cilj FPR≈0)")
    v_feat, v_unk = extract_frame_features(v.reset_index(drop=True), baseline)
    calibrate(gsvm, v_feat)
    v_pred = gsvm.predict(v_feat, v_unk)
    v_flag = int((v_pred["anomaly"] > 0).sum())
    print(f"  VALID frames : {len(v_feat):,}")
    print(f"  VALID FPR    : {v_flag}/{len(v_feat):,} "
          f"({v_flag/max(len(v_feat),1)*100:.4f}%)")
    print(f"  threshold    : {gsvm.threshold:.6f}")

    print("\nKORAK 5a – TEST-normal FPR (iskrena generalizacija)")
    te_feat, te_unk = extract_frame_features(te.reset_index(drop=True), baseline)
    te_pred = gsvm.predict(te_feat, te_unk)
    te_flag = int((te_pred["anomaly"] > 0).sum())
    print(f"  TEST frames  : {len(te_feat):,}")
    print(f"  TEST FPR     : {te_flag}/{len(te_feat):,} "
          f"({te_flag/max(len(te_feat),1)*100:.4f}%)")

    print("\nKORAK 5b – čitavi napad-fajlovi (frame-level coverage, kontinuitet)")
    if ATTACK_COVERAGE_CAP:
        print(f"  (skor na prvih {ATTACK_COVERAGE_CAP:,} okvira/fajl — OCSVM scoring)")
    print(f"{'label':<12}{'frames':>10}{'flagged':>10}{'events':>8}{'coverage':>10}")
    for lbl in ATTACK_LABELS:
        r = _attack_file_summary(gsvm, baseline, lbl)
        print(f"{r['label']:<12}{r['frames']:>10,}{r['flagged']:>10,}"
              f"{r['events']:>8}{r['coverage']:>10.2%}")

    print("\nKORAK 6 – red-team injection (3 manifesta) — PRAVI test, 1:1 sa ostalima")
    clean = _clean_stream()
    agg = evaluate_manifests_svm(gsvm, baseline, per, clean)
    print(f"{'napad':<6}{'detected':>9}{'total':>7}{'detection':>11}")
    for a in ATTACK_LABELS:
        d = agg[a]["detected"]
        tot = agg[a]["total"]
        print(f"{a:<6}{d:>9}{tot:>7}{d/max(tot,1)*100:>10.1f}%")

    print("\nKORAK 7 – perzistiranje modela + known_ids")
    save_model(gsvm)
    print(f"  model -> {ARTIFACT_PATH}")


def evaluate_manifests_svm(model: GlobalOneClassSVM, baseline: pd.DataFrame,
                           per, clean) -> dict:
    """Red-team injection test, identical bookkeeping to the forest's
    evaluate_manifests, but scoring each injected frame via the SVM."""
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
                sc = float(model.score_row(vec)[0])
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


if __name__ == "__main__":
    main()
