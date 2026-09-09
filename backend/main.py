"""
CarHacking API — Backend for web interface.

Reads normalized CSV files from dataset /normalized/ and exposes a REST API
that the React frontend uses for display:
  - overview statistics by Label
  - top CAN ID + frequencies
  - delta-t distribution (periodicity)
  - sample of messages (for table)

Efficiency: files are loaded once into memory (pandas, correct dtypes), and the
API returns aggregated data (e.g. top-N), never the whole dataset.

Run:
  cd backend && ../.venv/bin/python -m uvicorn main:app --reload --port 8000
"""
import os
import glob
import numpy as np
import pandas as pd
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Unified live/sim message stream (Simulator replay + future Live/ESP32).
from stream import run_sim
from recorder import list_sessions, session_path, REC_DIR

APP_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(APP_DIR, "..", "dataset ", "normalized")

COLS = ["Timestamp", "CAN_ID", "DLC"] + [f"B{i}" for i in range(8)] + ["Label"]
# Types for fast reading
DTYPES = {"Timestamp": np.float64, "CAN_ID": "category", "DLC": np.int8} | \
         {f"B{i}": "category" for i in range(8)} | {"Label": "category"}

# Store datasets in global (loaded once)
DATAFRAMES = {}
META = {}

app = FastAPI(title="CarHacking Web", version="1.0")

# CORS for React dev server (localhost:5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_all():
    """Load all normalized csv files into DATAFRAMES dict."""
    for path in glob.glob(os.path.join(DATA_DIR, "*.csv")):
        label = os.path.splitext(os.path.basename(path))[0]
        print(f"[load] {label}")
        # All normalized files have headers (Timestamp,CAN_ID,...)
        df = pd.read_csv(path, dtype=DTYPES, low_memory=False)
        # Normalize CAN_ID: '0x0350' -> int. parse hex into int.
        # Dataset uses hex, so we keep the raw hex string and an int form.
        hex_str = df["CAN_ID"].astype(str).str.strip().str.lower()
        # If it does not start with 0x, just use as-is before conversion
        has_0x = hex_str.str.startswith("0x")
        clean = hex_str.str.replace("0x", "", regex=False)
        df["CAN_ID_INT"] = clean.apply(lambda s: int(s, 16) if s else 0)
        df["CAN_ID"] = df["CAN_ID_INT"]  # keep int for filtering
        DATAFRAMES[label] = df
        META[label] = {"rows": len(df), "file": os.path.basename(path)}


def _has_header(path):
    """Detect whether the file has a header (Timestamp, ...)."""
    with open(path) as f:
        first = f.readline()
        return first.strip().startswith("Timestamp")


def detect_header_cols(path):
    """Return the actual column names from the header if the file has one."""
    with open(path) as f:
        first = f.readline().strip()
    if first.startswith("Timestamp"):
        return first.split(",")
    return COLS


@app.on_event("startup")
def startup():
    load_all()


@app.get("/api/health")
def health():
    return {"status": "ok", "datasets": list(META.keys())}


@app.get("/api/meta")
def meta():
    """Overview of all datasets and message counts."""
    return META


@app.get("/api/overview")
def overview():
    """Statistics by Label (traffic type)."""
    rows = []
    for label, df in DATAFRAMES.items():
        rows.append({
            "label": label,
            "rows": len(df),
            "unique_ids": df["CAN_ID"].nunique(),
            "dlc_modes": _dlc_modes(df),
        })
    return rows


def _dlc_modes(df):
    """Most common DLC (message length) per dataset."""
    try:
        vc = df["DLC"].value_counts()
        return [{"dlc": int(k), "count": int(v)} for k, v in vc.head(4).items()]
    except Exception:
        return []


@app.get("/api/top-ids")
def top_ids(label: str = Query("normal"), top: int = Query(15)):
    """Top CAN IDs by frequency for the given label."""
    if label not in DATAFRAMES:
        return {"error": f"unknown label '{label}'", "available": list(META.keys())}
    vc = DATAFRAMES[label]["CAN_ID"].value_counts().head(top)
    total = len(DATAFRAMES[label])
    return [{"can_id": int(k), "hex": f"0x{int(k):03X}", "count": int(v),
             "pct": round(100 * v / total, 3), "label": label}
            for k, v in vc.items()]


@app.get("/api/deltat")
def deltat(label: str = Query("normal"), top_ids_str: str = Query("")):
    """Delta-t statistics (periodicity) by top CAN IDs."""
    if label not in DATAFRAMES:
        return {"error": f"unknown label '{label}'"}
    df = DATAFRAMES[label].sort_values("Timestamp")
    # distinguish delta-t by CAN ID
    result = {}
    top = df["CAN_ID"].value_counts().head(10).index.tolist()
    for cid in top:
        sub = df[df["CAN_ID"] == cid].sort_values("Timestamp")
        dt = sub["Timestamp"].diff().dropna()
        if len(dt) > 1:
            result[f"{int(cid)}"] = {
                "hex": f"0x{int(cid):03X}", "count": int(len(sub)),
                "dt_mean_ms": round(float(dt.mean()) * 1000, 3),
                "dt_median_ms": round(float(dt.median()) * 1000, 3),
                "dt_min_ms": round(float(dt.min()) * 1000, 3),
                "dt_max_ms": round(float(dt.max()) * 1000, 3),
            }
    return list(result.values())


@app.get("/api/rows")
def rows(label: str = Query("normal"), limit: int = Query(100, le=2000),
         can_id: str = ""):
    """Sample of messages for table (limited). Optional filter by can_id (hex or dec)."""
    if label not in DATAFRAMES:
        return {"error": f"unknown label '{label}'"}
    df = DATAFRAMES[label]
    if can_id:
        cid = int(can_id, 16) if can_id.startswith(("0x", "0X")) else int(can_id)
        df = df[df["CAN_ID"] == cid]
    sample = df.head(limit)
    recs = []
    for _, r in sample.iterrows():
        payload = [int(b, 16) if str(b) not in ("", "nan") else -1
                   for b in r[[f"B{i}" for i in range(8)]] if str(b) not in ("", "nan")]
        recs.append({
            "timestamp": float(r["Timestamp"]),
            "can_id": int(r["CAN_ID"]),
            "hex": f"0x{int(r['CAN_ID']):03X}",
            "dlc": int(r["DLC"]),
            "payload": payload,
            "label": str(r["Label"]),
        })
    return {"rows": recs, "total_match": len(df)}


@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket, source: str = Query("sim"),
                    label: str = Query("normal"), speed: float = Query(25.0)):
    """Unified live bus stream.

    source=sim : replay a normalized CSV recording at wall-clock pace.
    source=live: (future) read from ESP32/socketcan.

    All sources speak the SAME frame protocol so the React UI doesn't care.
    """
    await websocket.accept()
    try:
        if source == "sim":
            await run_sim(websocket, label, speed)
        elif source == "live":
            # PROVISIONAL: until the ESP32/socketcan reader lands, the "live"
            # tab plays a recorded label at wall-clock pace so the recorder and
            # UI can be built/tested against a moving stream. Replacing the
            # body with a real socketcan reader later changes nothing upstream.
            await run_sim(websocket, label or "normal", speed, source="live")
        else:
            await websocket.send_json({
                "type": "error",
                "error": f"unsupported source '{source}' (only 'sim'/'live' for now)",
            })
    except WebSocketDisconnect:
        pass
    except Exception:
        # sink exceptions; the socket either closed or is being torn down
        pass


@app.get("/api/recordings")
def recordings():
    """List recorded capture sessions (newest first)."""
    return {"sessions": list_sessions()}


@app.get("/api/recordings/download")
def recordings_download(token: str = Query(""), kind: str = Query("csv")):
    """Download one file of a recorded session.

    kind = csv | log | meta (one file per HTTP response; the UI offers both
    'csv' and 'log' buttons which call this endpoint separately).
    """
    media = {"csv": ("text/csv", ".csv"),
             "log": ("text/plain", ".log"),
             "meta": ("application/json", ".meta.json")}.get(kind.lower())
    if not media:
        return {"error": "unsupported kind"}
    p = session_path(token, "meta.json" if kind.lower() == "meta" else kind.lower())
    if not os.path.exists(p):
        return {"error": f"session file not found: {os.path.basename(p)}"}
    mime, ext = media
    return FileResponse(p, media_type=mime, filename=os.path.basename(p))


@app.get("/api/recordings/delete")
def recordings_delete(token: str = Query("")):
    """Delete a recorded session (all its files)."""
    removed = []
    for ext in ("csv", "log", "meta.json"):
        p = session_path(token, ext)
        if os.path.exists(p):
            os.remove(p)
            removed.append(ext)
    return {"removed": removed}
