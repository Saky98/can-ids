"""
recorder.py — dual-format CAN traffic recorder.

Writes every received frame to TWO files simultaneously so recorded traffic is
immediately usable in both ecosystems of this project:

    dataset /recorded/<stem>.csv   normalized CSV (Timestamp, CAN_ID, DLC, B0..B7, Label)
    dataset /recorded/<stem>.log   raw candump-style log   ( <ts>  CAN_ID#payloadhex )
    dataset /recorded/<stem>.meta.json   session metadata

The recorder is intentionally *single-consumer*: it is driven by one playback /
capture task, so no locking is required. A session is:
    1. Recorder.create(label, note=None, source=?)  -> starts files
    2. recorder.add_rows(items)  x N            -> append decoded frames
    3. recorder.finish() / recorder.abort()      -> close files
"""
from __future__ import annotations

import csv
import json
import os
import time
import uuid

APP_DIR = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(APP_DIR, ".."))
REC_DIR = os.path.join(ROOT, "dataset ", "recorded")

# Mirrors the normalized dataset header (see convert_dataset.py) so a recorded
# CSV can be loaded by the same analysis pipeline without changes.
CSV_COLS = ["Timestamp", "CAN_ID", "DLC"] + [f"B{i}" for i in range(8)] + ["Label"]

# Columns written in raw candump order are just the payload bytes column names.
BCOLS = [f"B{i}" for i in range(8)]


def ensure_dir() -> str:
    os.makedirs(REC_DIR, exist_ok=True)
    return REC_DIR


def stem_for(token: str) -> str:
    """Session file stem (all files share it)."""
    return token if token.startswith("rec_") else f"rec_{token}"


class Recorder:
    """One recording session writing normalized CSV + raw candump log."""

    def __init__(self, label: str = "live", meta: dict | None = None):
        ensure_dir()
        # Compact sortable session token with entropy to avoid collisions.
        token = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        self.label = label
        self.token = token
        self.stem = stem_for(token)
        self.csv_path = os.path.join(REC_DIR, self.stem + ".csv")
        self.log_path = os.path.join(REC_DIR, self.stem + ".log")
        self.meta_path = os.path.join(REC_DIR, self.stem + ".meta.json")

        self.meta = {
            "token": token,
            "source": (meta or {}).get("source") or "unknown",
            "label": label,
            "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "started_wall": time.time(),
            "count": 0,
            "first_ts": None,
            "last_ts": None,
            "raw_bytes": 0,
        }
        self._f_csv = None
        self._f_log = None

    # ---- lifecycle ----
    def open(self) -> "Recorder":
        self._f_csv = open(self.csv_path, "w", newline="", encoding="utf-8")
        self._w = csv.writer(self._f_csv)
        self._w.writerow(CSV_COLS)
        self._f_log = open(self.log_path, "w", encoding="utf-8")
        self.log_header()
        return self

    def log_header(self) -> None:
        info = (
            f"# CAN capture session {self.token}\n"
            f"# label={self.label} source={self.meta['source']} "
            f"started={self.meta['recorded_at_utc']}\n"
        )
        self._f_log.write(info)

    def add_row(self, record: dict) -> None:
        """record keys: ts, hex (0x..), dlc, payload (hex bytes stripped of 0x)."""
        ts = float(record.get("ts") or 0.0)
        if self.meta["first_ts"] is None:
            self.meta["first_ts"] = ts
        self.meta["last_ts"] = ts

        # normalized CSV row
        can_raw = record.get("hex", "0x000")
        can_digits = can_raw[2:] if can_raw.lower().startswith("0x") else can_raw.zfill(3)
        payload = (record.get("payload") or "").replace(" ", "").lower()
        if len(payload) % 2 == 1:
            payload = payload[:-1]  # guard should not happen
        # split into bytes; pad to exactly DLC bytes with '' for the remainder
        dlc = int(record.get("dlc") or len(payload) // 2)
        bytes_list = [payload[i:i + 2] for i in range(0, len(payload), 2)]
        # extend to exactly 8 slots (leave remaining empty = dataset convention)
        data8 = list(bytes_list[:8])
        while len(data8) < 8:
            data8.append("")
        row = [f"{ts:.6f}", can_raw, dlc] + data8 + [self.label]
        self._w.writerow(row)

        # raw candump line: e.g.  (1479121434.850202) 0350#052884666d0000a2
        self._f_log.write(
            f"({ts:.6f}) {can_digits}#{payload}\n")
        self.meta["count"] += 1
        self.meta["raw_bytes"] += len(row)

    def add_rows(self, items: list[dict]) -> None:
        for it in items:
            self.add_row(it)

    def finish(self) -> dict:
        """Flush + close files. Returns session summary dict."""
        if self._f_csv:
            self._f_csv.flush()
            self._f_csv.close()
            self._f_csv = None
        if self._f_log:
            self._f_log.write("# end\n")
            self._f_log.flush()
            self._f_log.close()
            self._f_log = None
        first = self.meta.get("first_ts")
        last = self.meta.get("last_ts")
        if first is not None and last is not None:
            self.meta["span_s"] = round(last - first, 4)
        else:
            self.meta["span_s"] = None
        self.meta["bytes_written"] = self._file_sizes()
        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump(self.meta, f, indent=2)
        return dict(self.meta)

    def abort(self) -> None:
        """Close file handles and delete partially written files."""
        if self._f_csv is not None:
            self._f_csv.close(); self._f_csv = None
        if self._f_log is not None:
            self._f_log.close(); self._f_log = None
        for p in (self.csv_path, self.log_path):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def _file_sizes(self) -> dict:
        out = {}
        for tag, p in (("csv", self.csv_path), ("log", self.log_path),
                       ("meta", self.meta_path)):
            if os.path.exists(p):
                out[tag] = os.path.getsize(p)
        return out

    # ---- context manager sugar ----
    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        if exc[0] is None:
            self.finish()
        else:
            self.abort()
        return False


def list_sessions() -> list[dict]:
    """Return sorted session summaries (newest first)."""
    out = []
    if not os.path.isdir(REC_DIR):
        return out
    for fn in sorted(os.listdir(REC_DIR), reverse=True):
        if fn.endswith(".meta.json"):
            full = os.path.join(REC_DIR, fn)
            try:
                with open(full, encoding="utf-8") as f:
                    meta = json.load(f)
                out.append({
                    "token": meta.get("token"),
                    "stem": stem_for(str(meta.get("token", ""))),
                    "source": meta.get("source"),
                    "label": meta.get("label"),
                    "count": meta.get("count"),
                    "span_s": meta.get("span_s"),
                    "recorded_at_utc": meta.get("recorded_at_utc"),
                    "bytes": meta.get("bytes_written", {}),
                })
            except (OSError, ValueError):
                continue
    return out


def session_path(token: str, ext: str) -> str:
    """Absolute path to one session file (ext in {csv, log, meta.json})."""
    return os.path.join(REC_DIR, stem_for(token) + "." + ext)
