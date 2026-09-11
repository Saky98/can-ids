"""
stream.py — Unified CAN message stream (WebSocket) for the CarHacking frontend.

The Simulator page replays recorded CAN traffic as if it came from a live bus.
Both the Simulator and the future Live mode (ESP32 / socketcan) share the same
WebSocket protocol so the React UI stays identical and only the source switches:

    /ws/stream?source=sim      -> replay of a normalized CSV at wall-clock pace
    /ws/stream?source=live     -> (planned) ESP32 / socketcan reading

Server -> client frames (JSON, one text frame per batch of messages):

    {"type":"hello","label":..,"speed":..,"run":n}
    {"type":"messages","items":[ {ts,hex,dlc,payload}, ... ], "tps":<float>,
                                                       "done":<count>}
    {"type":"end","items_done":<int>,"run":<n>}

Client -> server frames (JSON commands):

    {"cmd":"pause"} | {"cmd":"resume"} | {"cmd":"speed","speed":<n>}
    {"cmd":"restart"}                                   # replay from the top

Concurrency model
-----------------
* One ASGI task (`_inbound`) owns all `ws.receive_text()` calls and applies
  every command synchronously onto the session state — pause/resume as an
  asyncio.Event, restart/speed as plain attributes. This is safe because it is
  the only place that reads from the socket.
* The playback loop (`run_sim`) never reads the socket; it only *sends*. It
  sleeps in small slices so state changes made by `_inbound` take effect within
  ~50 ms even at very low replay speed.

Pacing & gaps
-------------
Virtual replay time advances by `(TS_prev - TS_cur) / speed` seconds of real
time. Long silences (empty bus between bursts in the DoS/RPM recordings) are
capped at MAX_GAP_S so a recording does not stall the demo for minutes.
"""
from __future__ import annotations

import asyncio
import csv
import json
import os
import time
from typing import AsyncIterator, Iterator

from recorder import Recorder

APP_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(APP_DIR, "..", "dataset ", "normalized")

BCOLS = [f"B{i}" for i in range(8)]

MAX_GAP_S = 2.0
DEFAULT_SPEED = 25.0
MIN_SPEED = 0.1
MAX_SPEED = 10000.0
BATCH = 200            # rows per outbound message frame
SS = 0.05              # async sleep quantum -> responsive pause/restart

IDS_METHODS = ("heuristic", "isolation_forest", "one_class_svm", "off")


def _make_ids_engine(method: str):
    """Lazily build the chosen IDS engine (heavy: loads a model + clean baseline).

    Returns None for 'off'. Import is deferred so the normal (no-IDS) path stays
    lightweight and never touches the ML stack.
    """
    if not method or method == "off":
        return None
    from ids.ids_runtime import IdsEngine
    return IdsEngine(method)


def _norm_hex(v) -> str:
    v = (v or "").strip().lower()
    v = v[2:] if v.startswith("0x") else v
    return "0x" + v.zfill(3)


def _payload_hex(row) -> str:
    out: list[str] = []
    for col in BCOLS:
        v = (row.get(col) or "").strip()
        if not v:
            break
        try:
            out.append(f"{int(v, 16) & 0xff:02x}")
        except ValueError:
            try:
                out.append(f"{int(v) & 0xff:02x}")  # tolerate decimal bytes
            except ValueError:
                break
    return "".join(out)


def iter_batches(label: str, speed: float) -> Iterator[tuple[list[dict], float]]:
    """Yield (batch, wait_s_before_batch) by replaying `label` sorted CSV file."""
    path = os.path.join(DATA_DIR, f"{label}.csv")
    batch: list[dict] = []
    prev_ts: float | None = None

    def flush():
        nonlocal batch
        out = batch
        batch = []
        return out

    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row is None or not row.get("Timestamp"):
                continue
            try:
                ts = float(row["Timestamp"])
            except ValueError:
                continue
            gap = 0.0
            if prev_ts is not None:
                gap = (ts - prev_ts) / speed
                gap = min(max(gap, 0.0), MAX_GAP_S)
            prev_ts = ts
            try:
                dlc = int(row.get("DLC") or 0)
            except ValueError:
                dlc = 0
            batch.append({
                "ts": round(ts, 6),
                "hex": _norm_hex(row.get("CAN_ID")) if row.get("CAN_ID") else "0x000",
                "dlc": dlc,
                "payload": _payload_hex(row),
            })
            if len(batch) >= BATCH:
                yield flush(), gap
    if batch:
        yield flush(), 0.0


class SimSession:
    """Playback state for a single simulator WebSocket connection."""

    def __init__(self, label: str, speed: float, ids_method: str = "off"):
        self.label = label
        self.speed = SimSession.clamp(speed)
        self.run = 0
        self.restart_requested = False
        self.resume = asyncio.Event()
        self.resume.set()          # initially playing
        self.closed = False
        # recording (owned by the play loop; inbound *requests* via rec_ev)
        self.recording = None            # Recorder when active
        self.rec_ev = asyncio.Event()    # set when command change is pending
        self.rec_act = None              # ('start'{..}|'stop') pending intent
        # IDS + injection (owned by the play loop; inbound *requests* via inj_ev)
        self.ids_method = ids_method if ids_method in IDS_METHODS else "off"
        self.engine = None               # IdsEngine when ids_method != 'off'
        self.ids_ready = False
        self.inj_ev = asyncio.Event()    # set when an inject command is pending
        self.inj_attack = None           # pending attack label ('DoS'|...)
        self.inj_req_time = None         # wall-clock when inject was requested
        self.last_ts = 0.0               # last replayed timestamp (inject anchor)

    @staticmethod
    def clamp(s):
        try:
            return min(max(float(s), MIN_SPEED), MAX_SPEED)
        except (TypeError, ValueError):
            return DEFAULT_SPEED

    # --- controlled only from _inbound task ---
    def process(self, msg):
        cmd = msg.get("cmd")
        if cmd == "pause":
            self.resume.clear()
        elif cmd == "resume":
            self.resume.set()
        elif cmd == "restart":
            self.restart_requested = True
            self.resume.set()          # wake a paused sleeper immediately
        elif cmd == "speed":
            self.speed = self.clamp(msg.get("speed"))
        elif cmd == "inject":
            attack = (msg.get("attack") or "").strip()
            if attack in ("DoS", "Fuzzy", "gear", "RPM"):
                self.inj_attack = attack
                self.inj_req_time = time.time()
                self.inj_ev.set()
        elif cmd in ("record_start", "record_stop"):
            # playback loop owns recorder: just request a state change
            self.rec_act = (
                "start" if cmd == "record_start" else "stop",
                (msg.get("label") or self.label) if cmd == "record_start" else None,
            )
            self.rec_ev.set()
            self.resume.set()          # if paused, proceed so recorder can tick

    # --- IDS / inject: owned by the playback loop ---
    def inj_intent(self):
        """Return a pending attack label, else None (consumes the event)."""
        if self.inj_ev.is_set():
            attack = self.inj_attack
            self.inj_ev.clear()
            self.inj_attack = None
            return attack
        return None

    # --- owned by the playback loop (only caller) ---
    def rec_intent(self):
        """Return a pending ('start',label) / ('stop',None) intent, else None."""
        if self.rec_ev.is_set():
            act, label = self.rec_act
            self.rec_ev.clear()
            return act, label
        return None

    def rec_start(self, label: str, source: str):
        if self.recording is not None:
            self.recording.abort()      # drop any stale session
        rec = Recorder(label=label or self.label, meta={"source": source})
        rec.open()
        self.recording = rec
        return rec.stem

    def rec_tick(self, items):
        if self.recording is not None:
            self.recording.add_rows(items)

    def rec_stop(self) -> dict | None:
        """Finalize active recording. Returns session meta dict or None."""
        if self.recording is None:
            return None
        meta = self.recording.finish()
        self.recording = None
        return meta

    @property
    def recording_stem(self):
        return self.recording.stem if self.recording else None


async def _inbound(ws, session: SimSession):
    """Sole socket reader: apply each incoming command to session state."""
    try:
        while not session.closed:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                continue
            session.process(msg)
    except Exception:
        session.closed = True     # client gone / socket closed


async def _recorder_drain(ws, session, source: str):
    """Process any queued record start/stop intents; ack to client.

    Returns 'stop' / 'start' / None for the last applied action (may be None).
    The recorder is only ever touched by the play loop, so no locking here.
    """
    action = None
    while True:
        intent = session.rec_intent()   # consumes event if set
        if intent is None:
            break
        act, label = intent
        if act == "start":
            stem = session.rec_start(label or session.label, source=source)
            await ws.send_text(json.dumps(
                {"type": "recording_started", "stem": stem, "label": label or session.label}))
            action = "start"
        elif act == "stop":
            meta = session.rec_stop()
            action = "stop"
            await ws.send_text(json.dumps(
                {"type": "record_stopped", "meta": meta}))
    return action


async def _sleep_wall(session, seconds: float):
    """Sleep `seconds` of wall clock in small slices, honoring pause/restart."""
    if seconds <= 0:
        return
    remaining = seconds
    while remaining > 0 and not session.restart_requested:
        if not session.resume.is_set():
            await session.resume.wait()
            continue                      # (paused — wait for resume)
        step = min(SS, remaining)
        await asyncio.sleep(step)
        remaining -= step


async def run_sim(ws, label: str, speed: float, source: str = "sim",
                  ids_method: str = "off"):
    """Serve a simulator/live replay until the client disconnects or errors.

    `source` is recorded in capture metadata so a recording made from the live
    tab is tagged 'live', one from the simulator tab 'sim'.
    `ids_method` selects the inline detector: 'heuristic' | 'isolation_forest'
    | 'one_class_svm' | 'off'. Each replayed frame is scored per-frame; blocked
    frames are marked and injected attacks are flagged as they land on the bus.
    """
    session = SimSession(label or "normal", speed, ids_method)
    capture_source = source
    reader = asyncio.create_task(_inbound(ws, session))

    # Lazily build the IDS engine (heavy: model load + clean baseline). Doing it
    # inline (not lazily per frame) keeps scoring fast and atomic.
    if session.ids_method != "off":
        try:
            session.engine = _make_ids_engine(session.ids_method)
            session.ids_ready = session.engine is not None
        except Exception as exc:
            session.ids_ready = False
            await ws.send_text(json.dumps({
                "type": "error",
                "error": f"cannot load IDS '{session.ids_method}': {exc}",
            }))

    try:
        while not session.closed:
            if session.restart_requested:                 # restart same run
                session.restart_requested = False
            session.run += 1
            sent = 0
            t_start = time.time()

            await ws.send_text(json.dumps({
                "type": "hello",
                "label": session.label,
                "speed": session.speed,
                "run": session.run,
                "ids": session.ids_method,
                "ids_ready": session.ids_ready,
            }))

            gen = iter_batches(session.label, session.speed)
            try:
                for batch, gap in gen:
                    if session.restart_requested or session.closed:
                        break
                    await _sleep_wall(session, gap)
                    # honour pause also *after* the gap, before emitting
                    if not session.resume.is_set() or session.closed:
                        continue
                    if not batch:
                        continue
                    # forward to the wire AND (optionally) the recorder
                    if session.recording is not None:
                        session.rec_tick(batch)

                    # inline IDS: score every replayed frame per-frame
                    _score_batch(session, batch)

                    sent += len(batch)
                    tps = sent / max(time.time() - t_start, 1e-6)
                    await ws.send_text(json.dumps({
                        "type": "messages",
                        "items": batch,
                        "tps": round(tps, 1),
                        "done": sent,
                    }))

                    # honour control intents (record start/stop) queued meanwhile
                    await _recorder_drain(ws, session, source=capture_source)

                    # inject any pending attack at the current bus position
                    await _drain_inject(ws, session)

            except FileNotFoundError:
                await ws.send_text(json.dumps(
                    {"type": "error", "error": f"unknown label: {session.label}"}))
                break

            # End of one run: if a recording is still active on a *replay* that
            # finished, finalize it so captured frames are not lost.
            if session.recording is not None:
                meta = session.rec_stop()
                if meta:
                    await ws.send_text(json.dumps(
                        {"type": "record_stopped", "meta": meta}))

            await ws.send_text(json.dumps(
                {"type": "end", "items_done": sent, "run": session.run}))

            # Recording finished. We never read the socket from this task
            # (_inbound owns reads), so simply wait until the user asks for a
            # restart or the connection closes.
            if session.closed:
                break
            try:
                while not session.restart_requested and not session.closed:
                    await asyncio.sleep(SS)
            except Exception:
                break
    finally:
        session.closed = True
        # Disconnect / error while capturing? Do NOT leave a dangling recorder:
        # finalize (close files + write meta) so the session is usable and stops
        # "recording forever". The socket is likely gone, so no ack is sent.
        if session.recording is not None:
            try:
                session.rec_stop()
            except Exception:
                pass
        reader.cancel()
        try:
            await reader
        except (asyncio.CancelledError, Exception):
            pass


def _score_batch(session: SimSession, batch: list[dict]) -> None:
    """Inline per-frame IDS scoring of a replay batch (mutates items in place).

    Uses the engine's batched path: the ML detectors score the whole batch in one
    vectorized call (IsolationForest is ~100x faster batched than one-frame-at-a
    time), so the replay keeps up at realtime throughput.
    """
    eng = session.engine
    if eng is None:
        for it in batch:
            session.last_ts = it.get("ts")
            return
    frames = [(it.get("hex"), it.get("ts"), it.get("payload")) for it in batch]
    verdicts = eng.check_batch(frames)
    for it, v in zip(batch, verdicts):
        session.last_ts = it.get("ts")
        it["blocked"] = bool(v["block"])
        it["reason"] = v["reason"]
        it["score"] = v["score"]
        it["injected"] = False


async def _drain_inject(ws, session: SimSession) -> None:
    """Inject any pending attack (if IDS is active), score it, and emit it.

    Injected frames are emitted as their own 'messages' batch with injected=True
    so the UI can render them red and record blocked ones into quarantine. Each
    frame carries `detect_ms` = wall-clock ms from the inject command to the
    detection decision (the realtime latency the demo wants to surface).
    """
    attack = session.inj_intent()
    if not attack:
        return
    eng = session.engine
    if eng is None:
        return
    req_time = session.inj_req_time or time.time()
    # bus position = last replayed ts of this run (fall back to 0)
    now = session.last_ts if getattr(session, "last_ts", None) else 0.0
    frames = eng.inject(attack, now)
    if not frames:
        return

    # batch-score the injected frames (same fast path as the replay batch)
    verdicts = eng.check_batch([(fr["hex"], fr["ts"], fr["payload"])
                                for fr in frames])
    for fr, v in zip(frames, verdicts):
        fr["blocked"] = bool(v["block"])
        fr["reason"] = v["reason"]
        fr["score"] = v["score"]
        fr["detect_ms"] = round((time.time() - req_time) * 1000, 1)

    await ws.send_text(json.dumps({
        "type": "messages",
        "items": frames,
        "tps": None,
        "done": None,
        "injected": True,
        "attack": attack,
    }))
