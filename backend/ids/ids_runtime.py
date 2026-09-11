"""
ids_runtime.py — real-time IDS engine for the simulator/live stream.

One unified, per-frame detector that wraps the three offline methods built for
the thesis, so the Simulator page can pick a detector and flag/inject frames
live over the WebSocket:

  * heuristic        (method #1)  — explicit per-ID thresholds from ids_norma.csv
  * isolation_forest (method #2)  — global IF  (ids_isolation_forest.joblib)
  * one_class_svm    (method #3)  — global RBF OCSVM (ids_one_class_svm.joblib)

Interface used by stream.py:

    engine = IdsEngine(method)              # loads the chosen detector once
    verdict = engine.check(can_id, ts, pay) # -> {"block": bool, "reason": str,
                                            #    "score": float}
    batch = engine.inject("DoS")            # -> list[dict] of synthetic frames
                                            #    (DoS = 8-frame burst, others = 1)

The engine is STATEFUL per connection: it keeps the last timestamp/payload per
CAN_ID to compute inter-arrival gaps and per-byte steps, which both the heuristic
test2/test3 and the ML per-frame features need. `check` updates that state.

Per-frame scoring (all three methods share the same frame = one payload + gap):

  heuristic   — test1 unknown-ID, test2 burst (gap < 0.5*period_min), test3
                payload (static byte outside [lo,hi] OR drift-byte step > 2*max).
                This is the *per-frame* runtime variant of ids_heuristic's
                window test (no MIN_CONSEC running-window requirement), which is
                the honest real-time simplification and matches how the injected
                outliers are designed (single genuinely-bad frames).
  IF / OCSVM  — the shared per-frame z-score features (gap_z, max_abs_z,
                n_over_2) from ids_isolation_forest, scored against the loaded
                model; blocked when score < threshold (per-frame anomaly).

Injection payloads are sourced from the three red-team manifests
(dataset /injection_manifest_*.json), so the frames injected live are the SAME
genuine outliers the offline evaluation used — a fair, reproducible demo.
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np

# The ids/* modules are sibling top-level modules (run standalone from backend/ids/);
# when ids_runtime is imported as `ids.ids_runtime` from backend/, add this dir to
# sys.path so `from ids_heuristic import ...` resolves in both contexts.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from ids_heuristic import (  # noqa: E402
    BCOLS,
    BURST_MIN_FRAC,
    DRIFT_MARGIN,
    _parse_hex_byte,
    load_norma,
    load_normal_split,
)
from ids_isolation_forest import (  # noqa: E402
    FEATURES,
    _baseline_maps,
    _frame_features,
    learn_baseline,
    load_model as load_if_model,
)
from ids_one_class_svm import load_model as load_svm_model  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
_MANIFEST_DIR = os.path.join(_HERE, "..", "..", "dataset ")
_MANIFEST_PATHS = [os.path.join(_MANIFEST_DIR, f"injection_manifest_{i}.json")
                   for i in range(1, 4)]

METHODS = ("heuristic", "isolation_forest", "one_class_svm")

DoS_BURST_N = 8
DoS_BURST_GAP = 0.002


def _norm_id(can_id: str) -> str:
    """Normalize a CAN_ID to the dataset's '0xXXXX' (lowercase) form.

    The dataset stores IDs as 4-hex-digit strings with leading zeros preserved
    (e.g. "0x0350", "0x0002"), so we lowercase + re-add the 0x prefix WITHOUT
    stripping zeros (else "0x0350" would become "0x350" and stop matching the
    learnt baseline)."""
    v = (can_id or "").strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    return "0x" + v


class IdsEngine:
    def __init__(self, method: str = "heuristic"):
        if method not in METHODS:
            raise ValueError(f"unknown IDS method {method!r} (one of {METHODS})")
        self.method = method
        self._last_ts: dict[str, float] = {}
        self._last_pay: dict[str, np.ndarray] = {}

        if method == "heuristic":
            self.norma = load_norma()
            self._per = {r.CAN_ID: r for r in self.norma.itertuples()}
            self._known = set(self.norma["CAN_ID"].astype(str))
        else:
            # ML methods share the per-frame z-score baseline (clean TRAIN only).
            train, _, _ = load_normal_split()
            self.baseline = learn_baseline(train.reset_index(drop=True))
            self._per, self._known = _baseline_maps(self.baseline)
            if method == "isolation_forest":
                self._model = load_if_model()
                self._thr = self._model.threshold
            else:
                self._model = load_svm_model()
                self._thr = self._model.threshold

        self._inject_pool: dict[str, list[dict]] = {}
        self._inject_i: dict[str, int] = {}
        self._load_inject_pool()

    # ---- injection (source of synthetic attack frames) ----------------------
    def _load_inject_pool(self) -> None:
        pools: dict[str, list[dict]] = {}
        for path in _MANIFEST_PATHS:
            if not os.path.exists(path):
                continue
            with open(path) as f:
                manifest = json.load(f)
            for rec in manifest:
                attack = rec["attack"]
                pools.setdefault(attack, []).append({
                    "can_id": rec["CAN_ID"],
                    "payload": "".join(
                        (str(rec[c]).strip() if str(rec[c]).strip() not in ("", "nan")
                         else "00") for c in BCOLS),
                })
        self._inject_pool = pools
        self._inject_i = {a: 0 for a in pools}

    def inject(self, attack: str, now: float) -> list[dict]:
        """Return a list of synthetic frames for one injection at virtual time `now`.

        DoS -> 8-frame burst (2ms apart); others -> a single frame. Payloads are
        real outliers drawn (round-robin) from the manifests.
        """
        pool = self._inject_pool.get(attack)
        if not pool:
            return []
        k = self._inject_i.get(attack, 0)
        self._inject_i[attack] = (k + 1) % len(pool)
        base = pool[k]

        if attack == "DoS":
            rows = []
            for i in range(DoS_BURST_N):
                rows.append({
                    "ts": now + i * DoS_BURST_GAP,
                    "hex": _norm_id(base["can_id"]),
                    "can_id": _norm_id(base["can_id"]),
                    "dlc": 8,
                    "payload": base["payload"],
                    "injected": True,
                })
            return rows
        return [{
            "ts": now,
            "hex": _norm_id(base["can_id"]),
            "can_id": _norm_id(base["can_id"]),
            "dlc": 8,
            "payload": base["payload"],
            "injected": True,
        }]

    # ---- per-frame scoring --------------------------------------------------
    def check(self, can_id: str, ts: float, pay: np.ndarray | list) -> dict:
        """Score one frame; update gap/step state. Returns a verdict dict."""
        cid = _norm_id(can_id)
        p = np.asarray(pay, dtype="int64")
        if p.shape != (8,):
            p = np.zeros(8, dtype="int64")

        gap = (ts - self._last_ts[cid]) if cid in self._last_ts else None
        prev = self._last_pay.get(cid)

        if self.method == "heuristic":
            verdict = self._check_heuristic(cid, gap, p, prev)
        else:
            verdict = self._check_ml(cid, gap, p)

        # update state (only for known ids so foreign ids don't poison gap state)
        self._last_ts[cid] = ts
        self._last_pay[cid] = p
        return verdict

    @staticmethod
    def payload_hex_to_bytes(hexstr: str) -> np.ndarray:
        """Parse a payload hex string ('aabbcc...') into 8 ints, zero-padded."""
        hexstr = (hexstr or "").strip()
        out = np.zeros(8, dtype="int64")
        for i in range(8):
            seg = hexstr[i * 2:i * 2 + 2]
            if not seg:
                break
            try:
                out[i] = int(seg, 16)
            except ValueError:
                out[i] = 0
        return out

    def check_hex(self, can_id: str, ts: float, payload_hex: str) -> dict:
        """Convenience wrapper: score a frame given its hex payload string."""
        return self.check(can_id, ts, self.payload_hex_to_bytes(payload_hex))

    # ---- batched scoring (fast path for the stream) -------------------------
    def check_batch(self, frames: list) -> list[dict]:
        """Score a list of (can_id, ts, payload_hex) frames at once.

        Returns one verdict dict per frame (same shape as check, keyed by 'block',
        'reason', 'score'). Gaps/steps are computed incrementally (frame i sees
        frame i-1's state, exactly like check); only the model *scoring* call is
        vectorized, which is where the IsolationForest's expensive one-frame-at-a
        time cost lives (~23ms/frame -> ~0.07ms/frame batched).
        """
        n = len(frames)
        pays = [self.payload_hex_to_bytes(hx) for (cid, ts, hx) in frames]
        verdicts = []
        feats = [None] * n
        known = [True] * n

        # Pass 1: per-frame incremental feature computation + state update.
        for i, ((cid, ts, hx), pay) in enumerate(zip(frames, pays)):
            nc = _norm_id(cid)
            gap = (ts - self._last_ts[nc]) if nc in self._last_ts else None
            prev = self._last_pay.get(nc)

            if self.method == "heuristic":
                verdicts.append(self._check_heuristic(nc, gap, pay, prev))
            else:
                row = self._per.get(nc)
                if row is None:
                    known[i] = False
                else:
                    feats[i] = _frame_features(pay, gap, row)
                verdicts.append(None)

            # advance state incrementally
            self._last_ts[nc] = ts
            self._last_pay[nc] = pay

        # Pass 2: one vectorized model score for the ML methods.
        if self.method != "heuristic":
            idx = [i for i in range(n) if known[i]]
            if idx:
                X = np.array([[feats[i][k] for k in FEATURES] for i in idx],
                             dtype=float)
                if self.method == "isolation_forest":
                    scores = self._model.model.decision_function(X)
                else:
                    scores = self._model.score_row(X)
                for j, i in enumerate(idx):
                    f = feats[i]
                    score = float(scores[j])
                    block = score < self._thr
                    reason = ""
                    if block:
                        reason = f"anomaly ({max(f['max_abs_z'], 0):.1f}σ payload, " \
                                 f"{int(f['n_over_2'])} bytes)"
                    verdicts[i] = {"block": block, "reason": reason,
                                   "score": score}
            for i in range(n):
                if not known[i]:
                    verdicts[i] = {"block": True, "reason": "unknown CAN-ID",
                                   "score": None}

        return verdicts

    def _check_heuristic(self, cid: str, gap, p: np.ndarray, prev) -> dict:
        # test1: unknown ID
        if cid not in self._known:
            return {"block": True, "reason": "unknown CAN-ID", "score": None}
        row = self._per[cid]

        # test2: burst (gap below natural floor)
        if gap is not None:
            pmin = getattr(row, "period_min", None)
            if pmin is not None and not (isinstance(pmin, float) and np.isnan(pmin)) \
                    and pmin > 0 and gap < pmin * BURST_MIN_FRAC:
                return {"block": True, "reason": f"burst ({gap*1e3:.2f}ms < nominal)",
                        "score": None}

        # test3: payload (static out-of-range / drift over-step) — per-frame
        for i in range(8):
            cls = getattr(row, f"byte{i}_cls", None)
            v = int(p[i])
            if cls == "static":
                lo = getattr(row, f"byte{i}_lo", None)
                hi = getattr(row, f"byte{i}_hi", None)
                if lo is None or hi is None or np.isnan(lo) or np.isnan(hi):
                    continue
                if v < lo or v > hi:
                    return {"block": True,
                            "reason": f"byte{i} out-of-range ({v} ∉ [{lo:.0f},{hi:.0f}])",
                            "score": None}
            elif cls == "drift":
                mx = getattr(row, f"byte{i}_maxstep", 0)
                if mx is None or (isinstance(mx, float) and np.isnan(mx)):
                    continue
                if prev is not None:
                    step = abs(int(p[i]) - int(prev[i]))
                    if step > mx * DRIFT_MARGIN:
                        return {"block": True,
                                "reason": f"byte{i} step {step} > {DRIFT_MARGIN:.0f}×max",
                                "score": None}
        return {"block": False, "reason": "", "score": None}

    def _check_ml(self, cid: str, gap, p: np.ndarray) -> dict:
        row = self._per.get(cid)
        # out-of-band unknown-ID rule (mirrors the offline pipeline's unknown_mask):
        # a foreign CAN_ID has no baseline and is anomalous by definition.
        if row is None:
            return {"block": True, "reason": "unknown CAN-ID", "score": None}
        f = _frame_features(p, gap, row)
        vec = np.array([[f[k] for k in FEATURES]], dtype=float)
        if self.method == "isolation_forest":
            score = float(self._model.model.decision_function(vec)[0])
        else:
            score = float(self._model.score_row(vec)[0])
        block = score < self._thr
        reason = ""
        if block:
            reason = f"anomaly ({max(f['max_abs_z'], 0):.1f}σ payload, " \
                     f"{int(f['n_over_2'])} bytes)"
        return {"block": block, "reason": reason, "score": score}


def prewarm(method: str) -> IdsEngine:
    """Build an engine (used to surface load errors early in tests)."""
    return IdsEngine(method)


if __name__ == "__main__":
    # quick self-test of each method against a known-bad injected frame
    for m in METHODS:
        eng = IdsEngine(m)
        frames = eng.inject("gear", now=100.0)
        fr = frames[0]
        pay = np.array([_parse_hex_byte(fr["payload"][i:i+2])
                        for i in range(0, 16, 2)], dtype="int64")
        v = eng.check(fr["can_id"], fr["ts"], pay)
        print(f"[{m}] injected gear frame {fr['can_id']} -> block={v['block']} "
              f"({v['reason']}) score={v['score']}")
