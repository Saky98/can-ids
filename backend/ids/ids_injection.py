"""
IDS heuristic detector — "red-team" injection evaluation (method #1, step 7).

Instead of the (over-optimistic) whole-file coverage metric, this runs a more
honest test: inject a handful of GENUINELY bad frames (statistical outliers vs.
the clean norm) into an otherwise clean stream, at random places, and measure how
often each injection is detected.

This is closer to a real attacker: a few malicious frames slipped into normal
traffic, not a saturated all-attack recording.

Per-attack injection semantics (agreed with user):
  - DoS        : a tight BURST of bad frames (DoS is, by nature, density), repeated.
  - Fuzzy      : N scattered single bad frames (unknown IDs / out-of-range).
  - gear / RPM : N scattered single bad frames (out-of-range payload).

Run: .venv/bin/python backend/ids/ids_injection.py
"""
from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd

from ids_heuristic import (
    BCOLS, DATA, load_normal_split, train_norma, payloads_to_scalars,
    score_windows, _parse_hex_byte,
)

ATTACKS = ["DoS", "Fuzzy", "gear", "RPM"]

N_SCATTERED = 10   # single bad frames per trial for Fuzzy/gear/RPM
DoS_BURST = 8      # frames per DoS burst (density attack)
DoS_BURST_GAP_S = 0.002  # ~2ms apart -> clearly below any natural minimum
N_TRIALS = 10      # independent random trials per attack

# We keep THREE independent manifests (different seeds) so the final precision is
# an AVERAGE over 3 reproducible tests, not a single possibly-lucky draw. All
# three have the SAME number of injections; only the random placement / bad-frame
# choice differs (each seed drives its own reproducible random stream).
SEEDS = [20240910, 20240911, 20240912]

# Where the manifests live. Named *_1/2/3.json so the ML methods can iterate them.
_MANIFEST_DIR = os.path.dirname(DATA)
MANIFEST_PATHS = [os.path.join(_MANIFEST_DIR, f"injection_manifest_{i}.json")
                  for i in range(1, 4)]

# Back-compat: the very first manifest (single) we made before the multi-manifest
# refactor lived at this path; keep a pointer so nothing breaks.
MANIFEST_PATH = MANIFEST_PATHS[0]
SEED = SEEDS[0]


def learn_norma():
    t, v, te = load_normal_split()
    t2 = t.reset_index(drop=True)
    t2["scalar"] = payloads_to_scalars(t2)
    norma = train_norma(t2)
    return norma


def _norma_maps(norma):
    per = {r.CAN_ID: r for r in norma.itertuples()}
    known = set(norma["CAN_ID"].astype(str))
    return per, known


def load_attack(label: str) -> pd.DataFrame:
    path = os.path.join(DATA, f"{label}.csv")
    dtype = {"CAN_ID": str, **{c: str for c in BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + BCOLS, dtype=dtype)
    return df


def collect_bad_frames(df: pd.DataFrame, per, known) -> pd.DataFrame:
    """Return the subset of df that is a statistical outlier vs the clean norm.

    Outlier = (unknown CAN ID) OR (any STATIC byte leaves its clean [lo,hi]
    range) OR (any DRIFT byte takes a step clearly above its clean max step).
    DYNAMIC bytes are ignored (they carry full-range chatter, not a reliable
    bad/clean separator on their own).
    """
    bad_idx = set()
    for cid, g in df.groupby("CAN_ID"):
        c = str(cid)
        if c not in known:
            # unknown id -> every frame of it is foreign (Fuzzy invents ids)
            bad_idx.update(g.index.tolist())
            continue
        row = per[c]
        bts = g[BCOLS].map(_parse_hex_byte).astype("int64").to_numpy()
        for i in range(8):
            cls = getattr(row, f"byte{i}_cls", None)
            if cls == "static":
                lo = getattr(row, f"byte{i}_lo"); hi = getattr(row, f"byte{i}_hi")
                if lo is None or hi is None or np.isnan(lo) or np.isnan(hi):
                    continue
                col = bts[:, i]
                oob = np.where((col < lo) | (col > hi))[0]
                bad_idx.update(g.index[k] for k in oob)
            elif cls == "drift":
                mx = getattr(row, f"byte{i}_maxstep", 0)
                col = bts[:, i]
                if len(col) > 1:
                    dd = np.abs(np.diff(col))
                    over = np.where(dd > mx * 2.0)[0]  # 2x = same margin as test3
                    # a step involves two frames; mark the "after" frame
                    bad_idx.update(g.index[k + 1] for k in over if k + 1 < len(col))
    bad = df.loc[sorted(bad_idx)].reset_index(drop=True)
    return bad


def normalize_clean() -> pd.DataFrame:
    """Load the full clean stream (train is plenty; use whole normal.csv)."""
    path = os.path.join(DATA, "normal.csv")
    dtype = {"CAN_ID": str, **{c: str for c in BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + BCOLS, dtype=dtype)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    return df


def sample_bad(bad: pd.DataFrame, n: int, rng) -> pd.DataFrame:
    """Randomly pick n bad frames (with their actual timestamps/payload)."""
    idx = rng.choice(len(bad), size=min(n, len(bad)), replace=False)
    return bad.iloc[idx].reset_index(drop=True)


def generate_manifest(norma, per, known, seed: int) -> list[dict]:
    """Deterministically generate the full injection set (one manifest per seed).

    Each record fully describes ONE injected frame so any method can replay the
    exact same test later:
       {attack, trial, i, mode, timestamp, CAN_ID, B0..B7}
    'burst' records share one trial with a 'burst' flag; scatter records are each
    their own i-th injection. A fixed seed -> identical manifest every run.
    """
    rng = np.random.default_rng(seed)
    clean = normalize_clean()
    span_lo = clean["Timestamp"].min()
    span_hi = clean["Timestamp"].max()
    manifest = []

    for label in ATTACKS:
        df = load_attack(label)
        bad = collect_bad_frames(df, per, known)
        if label == "DoS":
            mode, n = "burst", DoS_BURST
        else:
            mode, n = "scatter", N_SCATTERED

        for trial in range(N_TRIALS):
            picks = sample_bad(bad, n, rng)
            if mode == "burst":
                t0 = rng.uniform(span_lo + 5.0, span_hi - 5.0)
                for k, (_, bad_row) in enumerate(picks.iterrows()):
                    manifest.append(_record(label, trial, k, mode,
                                            t0 + k * DoS_BURST_GAP_S, bad_row))
            else:
                t_targets = rng.uniform(span_lo + 5.0, span_hi - 5.0, size=n)
                t_targets = np.sort(t_targets)
                t_targets = np.maximum(t_targets, np.arange(n))  # >=1s apart
                for k, (t_tgt, (_, bad_row)) in enumerate(zip(t_targets, picks.iterrows())):
                    manifest.append(_record(label, trial, k, mode, t_tgt, bad_row))
    return manifest


def _record(attack, trial, i, mode, timestamp, bad_row) -> dict:
    rec = {"attack": attack, "trial": int(trial), "i": int(i),
           "mode": mode, "timestamp": float(timestamp),
           "CAN_ID": str(bad_row["CAN_ID"])}
    for c in BCOLS:
        rec[c] = str(bad_row[c]).strip()
    return rec


def load_manifest() -> list[dict]:
    with open(MANIFEST_PATH) as f:
        return json.load(f)


def save_manifest(manifest: list[dict]) -> None:
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=1)


def run_eval(clean: pd.DataFrame, norma, manifest: list[dict]) -> dict:
    """Score every injected frame and report per-attack detection rate.

    Scatter records are each one injection (counted individually). Burst records
    are grouped by (attack, trial): a burst is detected if ANY of its frames is
    flagged, and counts as ONE injection.
    """
    per = {r.CAN_ID: r for r in norma.itertuples()}
    detected = {a: 0 for a in ATTACKS}
    total = {a: 0 for a in ATTACKS}
    burst_hits: dict[tuple[str, int], int] = {}

    for rec in manifest:
        a = rec["attack"]
        hit = _probe_insert(clean, norma, per, rec)
        if rec["mode"] == "burst":
            key = (a, rec["trial"])
            burst_hits[key] = burst_hits.get(key, 0) or hit
        else:
            detected[a] += hit
            total[a] += 1

    for (a, _trial), v in burst_hits.items():
        detected[a] += v
        total[a] += 1

    return detected, total


def _probe_insert(clean, norma, per, rec) -> int:
    """Insert one injected frame (from a manifest record) into its 1s window and
    check whether that window is flagged anomaly. Returns 1/0."""
    t_tgt = rec["timestamp"]
    win = int(np.floor(t_tgt / 1.0))
    seg = clean[(clean["Timestamp"] >= win) & (clean["Timestamp"] < win + 1)].copy()
    if seg.empty:
        return 0
    inj = pd.DataFrame([{
        "Timestamp": t_tgt, "CAN_ID": rec["CAN_ID"],
        **{c: rec[c] for c in BCOLS},
    }])
    seg = pd.concat([seg, inj], ignore_index=True)
    seg["scalar"] = payloads_to_scalars(seg)
    sc = score_windows(seg, norma, win_s=1.0)
    if sc.empty:
        return 0
    return int((sc["anomaly"] > 0).any())


def main():
    norma = learn_norma()
    per, known = _norma_maps(norma)
    clean = normalize_clean()

    # Ensure all three manifests exist (generate any missing one with its seed).
    # This keeps the ML comparison reproducible across the same 3 tests.
    for path, seed in zip(MANIFEST_PATHS, SEEDS):
        if not os.path.exists(path):
            manifest = generate_manifest(norma, per, known, seed)
            with open(path, "w") as f:
                json.dump(manifest, f, indent=1)
            print(f"Generisan manifest {os.path.basename(path)} "
                  f"(seed={seed}, {len(manifest)} ubrizgavanja)")
        else:
            print(f"Manifest {os.path.basename(path)} već postoji "
                  f"({len(load_manifest())} ubrizgavanja)")

    print("\nInjection evaluation (red-team) — 3 manifesta, prosek + varijacija:\n")
    print(f"{'napad':<6}{'#1':>7}{'#2':>7}{'#3':>7}{'prosek':>9}{'min':>7}{'max':>7}")
    agg = {a: [] for a in ATTACKS}
    for path in MANIFEST_PATHS:
        manifest = load_manifest()
        detected, total = run_eval(clean, norma, manifest)
        for a in ATTACKS:
            agg[a].append(detected[a] / max(total[a], 1) * 100)

    for a in ATTACKS:
        rates = agg[a]
        avg = sum(rates) / len(rates)
        print(f"{a:<6}{rates[0]:>6.1f}%{rates[1]:>6.1f}%{rates[2]:>6.1f}%"
              f"{avg:>8.1f}%{min(rates):>6.1f}%{max(rates):>6.1f}%")


if __name__ == "__main__":
    main()
