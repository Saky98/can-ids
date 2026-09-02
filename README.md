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
├── dataset/            (LOCAL ONLY, NOT in Git — large CSV files)
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

Open http://localhost:5173/ (Vite proxies `/api` to the backend on port 8000).

## Status

- ✅ Dataset normalization
- ✅ Interactive CAN Frame Placer
- ✅ Analysis page (ID tables, frequencies, periodicity, sample messages)
- 🚧 IDS engine / metrics (in progress)
- 🚧 Simulator (replay as live) — planned
- 🚧 Live mode (ESP32 / socketcan) — planned

## Tech stack

- **Frontend:** React 19, Vite, Recharts
- **Backend:** Python, FastAPI, pandas
- **ICS/hardware (planned):** ESP32, SN65HVD230 transceiver, SocketCAN
