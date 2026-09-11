"""
ids_log.py — structured event log for the live IDS / simulator.

Goal: a detailed, machine-readable log so we can later analyse WHY the UI feels
laggy (e.g. "clicked DoS, nothing happened, then frames appeared much later").

Every command (click) and every relevant transition is recorded with a wall-clock
timestamp + a monotonic-per-event sequence id, and — crucially — how long it took
to go from "requested" to "done". The log is both printed to stderr (via the
`logging` module bridge below) and appended to a JSON-lines file.

Format: one JSON object per line (JSON Lines). Fields:

    t         : wall-clock ISO-8601 (ms precision)
    seq       : absolute event ordinal (gaps reveal skipped/slow work)
    ev        : event name (click, engine_load, inject, score, block, emit, ...)
    actor     : 'client' | 'server' | 'engine'
    ok        : bool (did the intended thing happen)
    ms        : elapsed wall-clock ms for this whole event (where meaningful)
    ...       : event-specific context

The file grows unbounded per backend process; for a demo that is fine. The path
is fixed to backend/ids/ids_events.jsonl (gitignored), but can be overridden via
IDS_LOG_PATH so multiple runs don't clobber each other.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(HERE, "ids_events.jsonl")

# In-memory ring so the UI / tests can also read recent events without the file.
_RING: deque = deque(maxlen=5000)
_LOCK = threading.Lock()
_SEQ = 0


def _path() -> str:
    return os.environ.get("IDS_LOG_PATH", DEFAULT_PATH)


def log(ev: str, actor: str = "server", ok: bool = True, ms: float | None = None,
        **ctx) -> dict:
    """Append one event. Returns the record (also appended to file + ring)."""
    global _SEQ
    with _LOCK:
        _SEQ += 1
        rec = {
            "t": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()) +
                 f".{int(time.time()*1000) % 1000:03d}",
            "ts": round(time.time(), 6),
            "seq": _SEQ,
            "ev": ev,
            "actor": actor,
            "ok": bool(ok),
        }
        if ms is not None:
            rec["ms"] = round(ms, 3)
        rec.update({k: v for k, v in ctx.items() if v is not None})
        _RING.append(rec)

        try:
            with open(_path(), "a") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            # logging must never break the demo
            pass
        # also mirror to stderr (visible in uvicorn console)
        print(f"[ids-log] {rec['seq']:>5} {rec['ev']:<12} ok={rec['ok']} "
              f"{('ms=' + str(rec['ms'])) if 'ms' in rec else ''} "
              f"{ctx}", file=sys.stderr, flush=True)
        return rec


def recent(n: int = 100) -> list[dict]:
    with _LOCK:
        return list(_RING)[-n:]


def clear() -> None:
    """Reset the ring (not the file)."""
    with _LOCK:
        _RING.clear()
