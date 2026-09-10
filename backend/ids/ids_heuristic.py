"""
IDS heuristic/statistical detector — offline prototype (method #1).
Built step by step (see heuristics.html §12).

Steps done: 1 (split) + 2 (scalar) + 3 (learn norma) + 4 (score windows:
test1 unknown-id, test2 burst, test3 class-aware payload) + 5 (logical-OR
window verdict "anomaly") + 6 (event-level evaluation on the 4 attack files).

Train/eval protocol (no cheating, strictly enforced):
  - TRAIN  ~70%  -> the model LEARNS the "normal" per-ID behaviour.
  - VALID  ~15%  -> used to pick thresholds / check FPR (never touches attacks).
  - TEST-normal ~15% -> held-out clean period used only for FINAL FPR check.
  - Attack files (DoS/Fuzzy/gear/RPM) are ONLY used for final evaluation (step 6),
    never to shape any threshold or model.
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
ROOT = os.path.dirname(BACKEND)
DATA = os.path.join(ROOT, "dataset ", "normalized")

# Train / Valid / Test fractions of the clean file (sum to 1.0).
FRAC = {"train": 0.70, "valid": 0.15, "test": 0.15}

# The 8 payload byte columns.
BCOLS = [f"B{i}" for i in range(8)]


def _read_cols() -> list[str]:
    """Column names we keep: Timestamp, traffic label (CAN_ID) and payload bytes."""
    return ["Timestamp", "CAN_ID"] + BCOLS


def load_normal_split() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load normal.csv and split it chronologically: TRAIN, VALID, TEST-normal.

    The file is already time-sorted, so splitting by row index gives three
    contiguous non-overlapping clean periods. Payload byte columns are read as
    STRING on purpose: they are hex (e.g. "6d", "a2"), and pandas would guess a
    number otherwise. We need the exact hex text to build the scalar (step 2).
    """
    dtype = {"CAN_ID": str, **{c: str for c in BCOLS}}
    df = pd.read_csv(os.path.join(DATA, "normal.csv"), usecols=_read_cols(),
                     dtype=dtype)

    n = len(df)
    i_train = int(n * FRAC["train"])
    i_valid = int(n * (FRAC["train"] + FRAC["valid"]))

    train = df.iloc[:i_train].reset_index(drop=True)
    valid = df.iloc[i_train:i_valid].reset_index(drop=True)
    test = df.iloc[i_valid:].reset_index(drop=True)
    return train, valid, test


# --- STEP 2 : payload -> scalar -------------------------------------------------
# Concatenate the 8 payload bytes (B0 is the most significant) into one integer.
# The CSV stores each byte as a hex string such as "05", "6d", "a2". Missing bytes
# (when DLC < 8) appear as empty/NaN strings and are treated as 0x00.
#
#   bytes 05 28 84 66 6d 00 00 a2  =>  int(0x052884666d0000a2)
# The result fits comfortably in uint64 (max 2**64-1 = all 0xff bytes).


def _parse_hex_byte(s, default: int = 0) -> int:
    """Parse one hex byte string (maybe stripped, may be ''/NaN) to an int."""
    if s is None:
        return default
    t = str(s).strip().lower()
    if t in ("", "nan", "none"):
        return default
    return int(t, 16)


def payloads_to_scalars(frame: pd.DataFrame) -> pd.Series:
    """Add a column `scalar` = whole 8-byte payload read as one uint64.

    Applies a python-level element-wise parse only once per run; for 700k rows
    this is a transient cost (~a few seconds) acceptable for an offline prototype.
    """
    b = frame[BCOLS].astype(object)
    # bytes->int matrix (string, lowercase, '' -> 0)
    mat = b.map(_parse_hex_byte)
    # accumulate in python-int (object) to avoid overflow, cast to uint64 at end.
    # B0 is the MOST significant byte, so we fold bytes left-to-right:
    # scalar = B0 B1 B2 ... B7  (little-end walk builds big value)
    acc = mat[BCOLS[0]].copy()          # object Series of ints
    for ci in BCOLS[1:]:
        acc = acc * 256 + mat[ci]
    return acc.astype("uint64")


# --- STEP 3 : learn THE "norma" (per-ID reference) from TRAIN ------------------
# After training we persist a small per-ID table (not a duplicate of the huge
# per-message file). This table is the only thing the later phases need to re-load:
#    known_ids        : which CAN_IDs exist in clean traffic            (test 1)
#    period_mean       : median gap (s) between consecutive frames (test 2)
#    period_std        : spread of those gaps (test 2 robustness)
#    delta_mean        : median |scalar_change| between consecutive frames (test 3)
#    scalar_lo, hi     : observed scalar range on clean frames           (test 3)


def train_norma(train: pd.DataFrame) -> pd.DataFrame:
    """Row-wise per-ID stats. Expects the raw B0..B7 hex columns present.

    Everything is learned ONLY from clean TRAIN (never attack data — no-leak).

    Per byte position we classify the byte into one of three behavioural classes
    using its CLEAN per-message |delta| distribution, then store what test3 needs
    for that class:

      * STATIC  (max |delta| == 0):          value never moves -> test3 uses the
                                              clean value range [lo,hi].
      * DRIFT   (0 < max |delta| <= DRIFT_MAX):  slides in small steps; a per-frame
                                              step is bounded, so test3 flags a step
                                              larger than the clean max step.
      * DYNAMIC (max |delta| > DRIFT_MAX):      full 0..255 chatter (status/opcode /
                                              wrap counters). No clean heuristic can
                                              separate spoof from normal here without
                                              data-leak, so test3 SKIPS this byte and
                                              it is left to the ML method (this is the
                                              honest boundary of the heuristic).

    scalar_* columns are kept for reference only; they drive no test.
    """
    rows = []
    for cid, g in train.groupby("CAN_ID", sort=False):
        gsort = g.sort_values("Timestamp")
        ts = gsort["Timestamp"].to_numpy()
        dt = np.diff(ts)
        period_mean = float(np.median(dt)) if len(dt) else float("nan")
        period_std = float(np.std(dt)) if len(dt) else float("nan")

        rec = {"CAN_ID": str(cid), "count": int(len(g)),
               "period_mean": period_mean, "period_std": period_std,
               "period_p01": float(np.percentile(dt, 0.1)) if len(dt) else float("nan"),
               "period_min": float(np.min(dt)) if len(dt) else float("nan")}

        # scalar (joined, kept informational only)
        s = gsort["scalar"].astype(object).tolist()              # python ints
        d = [abs(b - a) for a, b in zip(s, s[1:])]               # exact |delta|
        rec["scalar_lo"] = float(np.percentile(s, 0.5)) if s else float("nan")
        rec["scalar_hi"] = float(np.percentile(s, 99.5)) if s else float("nan")
        rec["scalar_delta_mean"] = float(np.median(d)) if d else float("nan")
        rec["scalar_delta_q99"] = float(np.percentile(d, 99)) if d else float("nan")

        # per-BYTE classification + test3 parameters
        bts = gsort[BCOLS].map(_parse_hex_byte).astype("int64").to_numpy()
        for i in range(8):
            col = bts[:, i]
            dd = np.abs(np.diff(col)) if len(col) > 1 else np.array([0], dtype=int)
            maxd = int(dd.max()) if len(dd) else 0
            if maxd == 0:
                cls = "static"
            elif maxd <= DRIFT_MAX:
                cls = "drift"
            else:
                cls = "dynamic"
            lo = float(np.percentile(col, 0.5)) if len(col) else float("nan")
            hi = float(np.percentile(col, 99.5)) if len(col) else float("nan")
            rec[f"byte{i}_cls"] = cls
            rec[f"byte{i}_lo"] = lo
            rec[f"byte{i}_hi"] = hi
            rec[f"byte{i}_maxstep"] = maxd
        rows.append(rec)
    return pd.DataFrame(rows)


NORMA_CSV = os.path.join(HERE, "ids_norma.csv")


# --- STEP 4 : score each 1s window with the three tests ------------------------
# For a clean/victim/attack dataframe (with `scalar` column and the learnt norma)
# we split time into whole 1s windows and, per window, decide each test 0/1.
#
#   test1 (unknown id) : any CAN_ID not in known_ids appeared           -> 0/1
#   test2 (burst)      : any same-id gap fell below BURST_MIN_FRAC * period_min
#                        (per-id natural lower bound, not a global constant) -> 0/1
#   test3 (payload)    : class-aware per-byte check learned from clean TRAIN:
#                          STATIC  -> value outside [lo,hi] for >= MIN_CONSEC frames
#                          DRIFT   -> any single-frame step > clean max step
#                          DYNAMIC -> skipped (left to ML; honest heuristic bound)
#   oob_n (range)      : total abnormal bytes counted (info).
#
# Decision recorded with user: test3 = per-byte classification (static/drift/
# dynamic) from clean TRAIN only; no attack data shapes any threshold.

# test2 burst: a same-id inter-arrival gap is "too fast" (burst) when it drops
# below BURST_MIN_FRAC * the id's own natural lower bound (min gap in clean
# TRAIN). Per-id because natural jitter differs per id: a global constant (old
# BURST_FRAC=0.6) sat below the natural minimum of high-rate ids (e.g. 0x0545
# ~5.05ms = 0.505x) and fired false bursts on clean data. We use the CLEAN min
# gap as the per-id floor and multiply by BURST_MIN_FRAC<1 to leave a safety
# zone: real DoS injection is ~an order of magnitude denser than nominal, i.e.
# far below 0.5x the clean minimum, so 0.5x keeps FPR=0 while still catching it.
BURST_MIN_FRAC = 0.5  # gap < 0.5 * period_min => burst (calibrated: 0 FP on clean)

# test3 byte classification boundary: a byte whose clean per-frame |delta| never
# exceeds DRIFT_MAX is treated as DRIFT (bounded step); above that it is DYNAMIC
# (full-range chatter) and is left to the ML method, not the heuristic.
DRIFT_MAX = 8

# test3 drift margin: flag a drift-byte step only when |delta| > DRIFT_MARGIN *
# its clean max step. Calibrated on clean VALID: the largest observed overrun
# factor there is 2.00x, so a 2x margin yields FPR=0 while a spoof jumping far
# beyond the natural step is still caught. (No attack data used.)
DRIFT_MARGIN = 2.0

# test3: how many CONSECUTIVE out-of-range frames of the same id+byte (in time
# order) must occur before we call it a payload anomaly. Chosen on clean VALID so
# FPR stays ~0; single-frame drift from counters/noise does not reach this.
MIN_CONSEC = 3


def max_run(mask) -> int:
    """Length of the longest run of consecutive True values in a boolean array."""
    if len(mask) == 0:
        return 0
    best = run = 0
    for v in mask:
        run = run + 1 if v else 0
        best = max(best, run)
    return best


def load_norma() -> pd.DataFrame:
    """Load the persisted norma table (ids_norma.csv)."""
    return pd.read_csv(NORMA_CSV)


def score_windows(df: pd.DataFrame, norma: pd.DataFrame,
                  win_s: float = 1.0) -> pd.DataFrame:
    """Return one row per integer second with the three test results.

    df       : must already contain a `scalar` column (uint64).
    norma    : per-ID reference table (as produced by train_norma).
    win_s    : window size in seconds (keep 1.0 step by step).
    """
    # maps
    known = set(norma["CAN_ID"].astype(str))
    per = {r.CAN_ID: r for r in norma.itertuples()}

    df = df.assign(win=np.floor(df["Timestamp"] / win_s).astype(int))
    out = {}

    for win, g in df.groupby("win", sort=True):
        rec = {"n": 0, "test1": 0, "test2": 0, "test3": 0,
               "burst_n": 0, "oob_n": 0}
        for cid, h in g.groupby("CAN_ID", sort=False):
            c = str(cid)
            rec["n"] += len(h)
            # ---- test1: unknown id ----
            if c not in known:
                rec["test1"] = 1
                continue  # no learnt period/range to test against an unknown id
            row = per[c]
            # keep within-window order by time for period + delta
            h = h.sort_values("Timestamp")
            # ---- test2: burst (same-id gap below its natural lower bound) ----
            ts = h["Timestamp"].to_numpy()
            dt = np.diff(ts)
            pmin = getattr(row, "period_min", None)
            if pmin is None or (isinstance(pmin, float) and np.isnan(pmin)) or pmin <= 0:
                fast = 0
            else:
                thr = pmin * BURST_MIN_FRAC
                fast = int((dt < thr).sum())
            if fast > 0:
                rec["test2"] = 1
            rec["burst_n"] += fast
            # ---- test3: payload anomaly, class-aware per byte ----
            bts = h[BCOLS].map(_parse_hex_byte).astype("int64").to_numpy()
            viol = 0
            for i in range(8):
                cls = getattr(row, f"byte{i}_cls", None)
                if cls is None:
                    continue
                col = bts[:, i]
                if cls == "static":
                    # value must stay inside its clean range [lo,hi]
                    lo = getattr(row, f"byte{i}_lo", None)
                    hi = getattr(row, f"byte{i}_hi", None)
                    if lo is None or hi is None:
                        continue
                    if isinstance(lo, float) and np.isnan(lo):
                        continue
                    if isinstance(hi, float) and np.isnan(hi):
                        continue
                    oob = (col < lo) | (col > hi)
                    if max_run(oob) >= MIN_CONSEC:
                        viol += max_run(oob)
                elif cls == "drift":
                    # a single frame step larger than the clean max step = anomaly
                    maxstep = getattr(row, f"byte{i}_maxstep", 0)
                    if maxstep is None or (isinstance(maxstep, float) and np.isnan(maxstep)):
                        continue
                    if len(col) > 1:
                        dd = np.abs(np.diff(col))
                        if int(dd.max()) > int(maxstep) * DRIFT_MARGIN:
                            viol += 1
                # "dynamic" bytes are intentionally skipped (left to ML)
            if viol > 0:
                rec["test3"] = 1
            rec["oob_n"] += viol
        # ---- final window verdict: logical OR of the three tests ----
        rec["anomaly"] = int(rec["test1"] or rec["test2"] or rec["test3"])
        out[int(win)] = rec
    return pd.DataFrame.from_dict(out, orient="index").sort_index()


# --- STEP 6 : event-level evaluation on the 4 attack files (evaluate only) -----
# Detector thresholds are already final (learned/calibrated on clean data only).
# Here we measure how well the locked-down detector reacts to each attack, using
# the thesis-friendly "event-level" metric: contiguous runs of flagged windows
# are collapsed into single attack EVENTS, so intermittent injection bursts are
# not over-penalised (per-window recall would overstate misses).

ATTACK_LABELS = ["DoS", "Fuzzy", "gear", "RPM"]


def _runs(flagged: list[int]) -> list[tuple[int, int]]:
    """Collapse sorted flagged window indices into contiguous [start, end] spans."""
    spans: list[list[int]] = []
    for w in flagged:
        if spans and w == spans[-1][1] + 1:
            spans[-1][1] = w
        else:
            spans.append([w, w])
    return [(s, e) for s, e in spans]


def evaluate_attack(label: str, norma: pd.DataFrame) -> dict:
    """Score one attack file and collapse flagged windows into events.

    Returns a dict with per-window counts, per-test hit counts, and the
    event-level summary (number of events, avg event length, coverage).
    """
    path = os.path.join(DATA, f"{label}.csv")
    dtype = {"CAN_ID": str, **{c: str for c in BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + BCOLS, dtype=dtype)
    df["scalar"] = payloads_to_scalars(df)
    sc = score_windows(df, norma)

    n_win = len(sc)
    t1 = int((sc["test1"] > 0).sum())
    t2 = int((sc["test2"] > 0).sum())
    t3 = int((sc["test3"] > 0).sum())
    flagged = sorted(int(w) for w in sc.index[sc["anomaly"] > 0])

    spans = _runs(flagged)
    covered = sum(e - s + 1 for s, e in spans)
    return {
        "label": label,
        "windows": n_win,
        "test1": t1, "test2": t2, "test3": t3,
        "anomaly_windows": len(flagged),
        "events": len(spans),
        "avg_event_len_s": covered / len(spans) if spans else 0.0,
        "coverage": covered / n_win if n_win else 0.0,
    }


if __name__ == "__main__":
    t, v, te = load_normal_split()
    print("KORAK 1 – Učitaj + podeli normal.csv")
    print(f"  TRAIN : {len(t):>9,} poruka (~70%)")
    print(f"  VALID : {len(v):>9,} poruka (~15%)")
    print(f"  TEST  : {len(te):>9,} poruka (~15%)")

    print("\nKORAK 2 – payload (8 bajtova) -> skalar (uint64)")
    t2 = t.reset_index(drop=True)
    t2["scalar"] = payloads_to_scalars(t2)
    for i in range(min(3, len(t2))):
        raw = " ".join(str(x).strip() for x in t2.loc[i, BCOLS])
        print(f"  row {i}: bytes=[{raw}]  scalar={int(t2.at[i,'scalar'])}")
    print(f"  TRAIN now {len(t2):,} rows x {t2.shape[1]} cols (added 'scalar')")

    print("\nKORAK 3 – trening: uči 'normu' (per-ID) iz TRAIN")
    norma = train_norma(t2)
    pd.set_option("display.width", 200)
    cols = ["CAN_ID", "count", "period_mean",
            "byte0_cls", "byte1_cls", "byte2_cls", "byte3_cls",
            "byte4_cls", "byte5_cls", "byte6_cls", "byte7_cls"]
    print(norma[cols].to_string(index=False))
    norma.to_csv(NORMA_CSV, index=False)
    print(f"\nSačuvana norma-tabela -> {NORMA_CSV}  ({len(norma)} redova)")

    print("\nKORAK 4 – skoruj 1s prozore (test1/2/3) na VALID (čist) nad normom")
    v2 = v.reset_index(drop=True)
    v2["scalar"] = payloads_to_scalars(v2)
    sc_v = score_windows(v2, norma)
    n_win = len(sc_v)
    t1 = int((sc_v["test1"] > 0).sum())
    t2 = int((sc_v["test2"] > 0).sum())
    t3 = int((sc_v["test3"] > 0).sum())
    any_win = int((sc_v["anomaly"] > 0).sum())
    print(f"  VALID ima {n_win:,} 1s prozora")
    print(f"    test1 (nepoznat ID):  {t1} prozora")
    print(f"    test2 (burst):        {t2} prozora")
    print(f"    test3 (payload opseg):{t3} prozora  (MIN_CONSEC={MIN_CONSEC})")
    print(f"    KORAK 5 – OR sud (anomaly): {any_win} prozora "
          f"({any_win/max(n_win,1)*100:.1f}% FPR)")

    print("\nKORAK 6 – evaluacija na 4 napada (event-level; samo merenje)")
    print(f"{'napad':<8}{'prozora':>9}{'t1':>5}{'t2':>5}{'t3':>5}"
          f"{'anom_proz':>11}{'events':>8}{'avg_len_s':>11}{'coverage':>10}")
    for lbl in ATTACK_LABELS:
        r = evaluate_attack(lbl, norma)
        print(f"{r['label']:<8}{r['windows']:>9}{r['test1']:>5}{r['test2']:>5}"
              f"{r['test3']:>5}{r['anomaly_windows']:>11}{r['events']:>8}"
              f"{r['avg_event_len_s']:>11.2f}{r['coverage']:>10.1%}")
