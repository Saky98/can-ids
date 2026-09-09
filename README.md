# CAN-IDS — Automotive Intrusion Detection System

**Analysis and implementation of an intrusion detection system (IDS) for protecting CAN communication in automotive information systems**

> Original title (Serbian): *"Analiza i implementacija intrusion detection sistema (IDS) za zaštitu CAN komunikacije u automobilskim informacionim sistemima"*

---

## Overview

This project is a graduation thesis focused on **automotive cybersecurity**. It built around the
**Controller Area Network (CAN)** protocol, which lacks built-in authentication and encryption —
making vehicles vulnerable to injected or anomalous traffic.

The goal is an **Intrusion Detection System (IDS)** that monitors CAN traffic, recognizes
anomalies/attacks, and alerts or reacts when suspicious behavior is detected.

The project includes an **interactive web application** for analyzing CAN traffic, a CAN frame
placer visualizer, and planned simulator / live modes.

## System architecture

```
[ Auto CAN Bus ] <---> [ SN65HVD230 ] <---> [ ESP32 TWAI ]
     <--- Serial/USB (SLCAN) ---> [ Linux/Mac SocketCAN (can0) ]
     <---> [ Python Backend (FastAPI) + Machine Learning ]
     <---> [ React Frontend (browser) ]
```

## Repository layout

```
├── frontend/           React (Vite) web application
│   └── src/
│       ├── pages/      Home (CAN Frame), Analysis, Simulator, Live
│       └── components/ Interactive CAN Frame Placer / Diagram
├── backend/            Python FastAPI backend (reads normalized CSV)
│   ├── main.py         REST + WebSocket endpoints
│   ├── stream.py       unified /ws/stream (sim + live) replay engine
│   └── recorder.py     dual-format capture recorder (CSV + raw candump log)
├── dataset/            (LOCAL ONLY, NOT in Git — large CSV files)
│   ├── archive/        original Car-Hacking dataset
│   ├── normalized/     normalized CSVs (normal + DoS/Fuzzy/gear/RPM)
│   └── recorded/       your live captures (created at runtime; NOT in Git)
├── convert_dataset.py  Script to normalize the raw Car-Hacking Dataset
├── reference/          Sources and literature (Markdown)
└── handoff.md          Project handoff / knowledge documentation
```

## Dataset

The project uses the public **Car-Hacking Dataset** (HCRL / Seo et al.) containing normal and
attack traffic (DoS, fuzzy, gear spoofing, RPM spoofing).

**Note:** The normalized dataset (~15M messages, ~GB) is intentionally **not committed to Git**.
It stays local in `dataset /normalized/`. To reproduce, run `convert_dataset.py` on the original
files in `dataset /archive/`.

## How to run

### Backend (FastAPI)
```bash
cd backend
../.venv/bin/python -m uvicorn main:app --port 8000
```

### Frontend (React / Vite)
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173/ (Vite proxies `/api` **and** `/ws` to the backend on port 8000).

### Simulator (replay stream)

The **Simulator** page replays a recorded dataset as if it came from a live bus,
streaming frames to the browser over a unified WebSocket:

```
UI ── ws://<host>/ws/stream?source=sim&label=<label>&speed=<n> ──> FastAPI
```

- Runs in dev with no extra setup: Vite proxies `/ws` to the backend.
- Controls: Start/Stop, Pause, Resume, Restart, traffic type (normal / DoS /
  Fuzzy / gear / RPM), playback speed (0.1–2000×).
- The stream protocol is shared with the planned **Live** source
  (`source=live`, ESP32 / socketcan), so the page keeps working unchanged when
  the future live source is plugged in behind the same endpoint.

Backend files: `backend/stream.py` (WebSocket replay engine) + the `/ws/stream`
route in `backend/main.py`.

### Live mode & recording (capture)

The **Live** page shows the bus in real time and can save every received frame.

- Live mode data source: until the vehicle is attached, the backend streams a
  recorded dataset over the `source=live` channel (a **dev bridge**) so the page
  and recorder can be tested end-to-end. Wired later to ESP32 / socketcan, the
  UI and save/export stay the same.
- **Recording** writes each frame to two files at once into `dataset /recorded/`:
  - `rec_<id>.csv`  analysis-ready (same header as the normalized dataset) and
  - `rec_<id>.log`  raw candump log `(<ts>) CAN#payload`
  - plus `rec_<id>.meta.json` with session metadata.
- Recorder state is controlled over the same WebSocket (`record_start`,
  `record_stop`) and saved sessions are listed / downloaded / deleted via REST:
  - `GET /api/recordings`        — list sessions
  - `GET /api/recordings/download?token=…&kind=csv|log|meta`
  - `GET /api/recordings/delete?token=…`
- Frontend → `frontend/src/pages/LivePage.jsx`; recorder logic → `backend/recorder.py`.

## Status

- ✅ Dataset normalization
- ✅ Interactive CAN Frame Placer
- ✅ Analysis page (ID tables, frequencies, periodicity, sample messages)
- ✅ Simulator — replays recorded data as a live WebSocket stream
- ✅ Live-mode dashboard + dual-format recording/export (CSV + raw log)
- 🚧 IDS engine / metrics (in progress)
- 🚧 Live capture hardware (ESP32 / socketcan) — planned; `source=live` is a
  dev replay bridge until then

## Tech stack

- **Frontend:** React 19, Vite, Recharts
- **Backend:** Python, FastAPI, pandas
- **ICS/hardware (planned):** ESP32, SN65HVD230 transceiver, SocketCAN
