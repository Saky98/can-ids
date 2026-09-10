"""
Shared feature extractor for the ML IDS methods (method #2 Isolation Forest,
method #3 One-Class SVM).

The thesis requires that all three detectors share the SAME featurization and
the SAME split. The heuristic (ids_heuristic.py) scores *per CAN_ID per 1s
window*, so the ML methods use the same granularity: one feature vector per
(CAN_ID, 1-second window). Training is done ONLY on clean TRAIN (never attack
data), matching the no-leak protocol in ids_heuristic.py.

Feature vector (per CAN_ID per 1s window):
  rate            : number of frames of this ID in that second
  gap_median      : median inter-arrival gap (s)  (rhythm)
  gap_min         : minimum inter-arrival gap (s) -> burst/flooding
  gap_cv          : coefficient of variation of gaps (regularity)
  delta_median    : median |byte-step| across the 8 payload bytes
  delta_max       : max |byte-step| across the 8 payload bytes
  range_width     : max - min (per byte, averaged) -> payload spread
  n_known_bad     : (for diagnostics) count of bytes that were "dynamic"

An unknown CAN_ID (e.g. Fuzzy injection) is still featurised the same way, but
an extra boolean "id_seen" is NOT part of the raw vector; instead the caller
distinguishes unknown IDs upstream (the heuristic's test1) so the ML model can
decide purely on the numeric signature. For convenience we expose `known` as a
mask column in the returned DataFrame, but it is dropped before model fit.
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd

from ids_heuristic import BCOLS, DATA, _parse_hex_byte

WIN_S = 1.0

# Feature columns fed to the model (order is fixed and stable).
FEATURES = [
    "rate",
    "gap_median",
    "gap_min",
    "gap_cv",
    "delta_median",
    "delta_max",
    "range_width",
]


def _window_features(g: pd.DataFrame) -> dict:
    """Stats for one (CAN_ID, window) group `g`, already time-sorted."""
    ts = g["Timestamp"].to_numpy()
    n = len(g)

    if n >= 2:
        dt = np.diff(ts)
        gap_median = float(np.median(dt))
        gap_min = float(np.min(dt))
        gap_std = float(np.std(dt))
        gap_cv = gap_std / gap_median if gap_median > 0 else 0.0
    else:
        gap_median = gap_min = gap_cv = 0.0

    bts = g[BCOLS].map(_parse_hex_byte).astype("int64").to_numpy()
    if n >= 2:
        dd = np.abs(np.diff(bts, axis=0))
        delta_median = float(np.median(dd))
        delta_max = float(np.max(dd))
    else:
        delta_median = delta_max = 0.0

    # payload spread: average per-byte (max - min) in this window
    range_width = float(np.mean(np.ptp(bts, axis=0))) if n else 0.0

    return {
        "can_id": str(g["CAN_ID"].iloc[0]),
        "n": n,
        "rate": float(n),
        "gap_median": gap_median,
        "gap_min": gap_min,
        "gap_cv": gap_cv,
        "delta_median": delta_median,
        "delta_max": delta_max,
        "range_width": range_width,
    }


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """One feature vector per (CAN_ID, 1s window); df needs `scalar`-free raw cols.

    Returns a DataFrame with `can_id`, `win`, `n`, the FEATURES columns, and a
    `known` boolean (whether this CAN_ID was seen in clean TRAIN — filled by the
    caller via `mark_known`).
    """
    df = df.assign(win=np.floor(df["Timestamp"] / WIN_S).astype(int))
    rows = []
    for (win, cid), g in df.groupby(["win", "CAN_ID"], sort=True):
        g = g.sort_values("Timestamp")
        rec = _window_features(g)
        rec["win"] = int(win)
        rows.append(rec)

    cols = ["can_id", "win", "n"] + FEATURES + ["known"]
    out = pd.DataFrame(rows)
    out["known"] = True  # placeholder; overwritten by mark_known()
    return out[cols]


def mark_known(feat: pd.DataFrame, known_ids: set[str]) -> pd.DataFrame:
    """Set the `known` column from the learnt CAN_ID set."""
    feat["known"] = feat["can_id"].isin(known_ids)
    return feat


def load_attack_features(label: str) -> pd.DataFrame:
    """Load an attack file and extract features (same path/columns as heuristic)."""
    path = os.path.join(DATA, f"{label}.csv")
    dtype = {"CAN_ID": str, **{c: str for c in BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + BCOLS, dtype=dtype)
    return extract_features(df)
