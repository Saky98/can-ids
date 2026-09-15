"""
run_manifest_interleaved.py — detekcija ubrizganih napada nad PUNIM normalnim tokom.

Pokreće SAMO red-team manifest test (sekcija 4), ali interleaved: sve manifest
okvire (3 manifesta, 380 rekorda svaki) se ubaci u ceo normal.csv (~900k okvira)
po timestamp-u, pa se CELI spojeni tok skoruje redom (live režim) za svaku od tri
metode. Beleži detekciju po napadu + vremensku efikasnost.

    .venv/bin/python backend/ids/run_manifest_interleaved.py

Ne radi FPR ni coverage (te rezultate već imamo); samo detekciju ubrizganih.
"""
from __future__ import annotations

import html
import json
import os
import time

import numpy as np
import pandas as pd

import ids_heuristic as HE
import ids_injection as INJ
from ids_runtime import IdsEngine

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_PATH = os.path.join(HERE, "manifest_interleaved_report.html")
ATTACKS = ["DoS", "Fuzzy", "gear", "RPM"]


def _payload_hex(rec) -> str:
    out = []
    for c in HE.BCOLS:
        v = rec[c]
        s = str(v).strip()
        if s in ("", "nan", "None"):
            s = "00"
        out.append(s)
    return "".join(out)


def _clean_stream() -> pd.DataFrame:
    path = os.path.join(HE.DATA, "normal.csv")
    dtype = {"CAN_ID": str, **{c: str for c in HE.BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + HE.BCOLS, dtype=dtype)
    return df.sort_values("Timestamp").reset_index(drop=True)


def _manifest_interleaved(engine: IdsEngine, clean: pd.DataFrame,
                          paths: list[str]) -> dict:
    """Inject every manifest frame into the FULL clean stream by timestamp, score
    the entire merged stream in order. Burst = 1 event, scatter = each frame.

    Uses engine.check_batch (batched but still per-frame verdicts) so the full
    ~900k stream completes in minutes; the per-frame decision is IDENTICAL to
    scoring one frame at a time (gap/step state is advanced incrementally inside
    check_batch).
    """
    # collect injected records
    inj_rows = []
    for path in paths:
        with open(path) as f:
            manifest = json.load(f)
        for rec in manifest:
            inj_rows.append(rec)

    # build merged frame list: (ts, cid, payload_hex, rec_or_None)
    clean_ts = clean["Timestamp"].to_numpy()
    clean_cid = clean["CAN_ID"].astype(str).to_numpy()
    # precompute payload hex strings for clean stream (robust to NaN bytes)
    clean_pay = np.array([_payload_hex(r) for r in clean[HE.BCOLS].to_dict("records")])

    frames = []
    for i in range(len(clean)):
        frames.append((clean_ts[i], clean_cid[i], clean_pay[i], None))
    for rec in inj_rows:
        frames.append((rec["timestamp"], rec["CAN_ID"], _payload_hex(rec), rec))
    frames.sort(key=lambda x: x[0])

    detected = {a: 0 for a in ATTACKS}
    total = {a: 0 for a in ATTACKS}
    burst_hits: dict[tuple[str, int], int] = {}
    scatter_seen: set[tuple] = set()

    BATCH = 256
    n = len(frames)
    for start in range(0, n, BATCH):
        chunk = frames[start:start + BATCH]
        ids = [f[1] for f in chunk]
        tss = [f[0] for f in chunk]
        pays = [f[2] for f in chunk]
        verdicts = engine.check_batch(list(zip(ids, tss, pays)))
        for (ts, cid, pay, rec), v in zip(chunk, verdicts):
            if rec is None:
                continue
            a = rec["attack"]
            block = int(v["block"])
            if rec["mode"] == "burst":
                key = (a, rec["trial"])
                burst_hits[key] = burst_hits.get(key, 0) or block
            else:
                rkey = (a, rec["trial"], rec["i"])
                if rkey not in scatter_seen:
                    scatter_seen.add(rkey)
                    detected[a] += block
                    total[a] += 1

    for path in paths:
        with open(path) as f:
            manifest = json.load(f)
        for rec in manifest:
            if rec["mode"] == "burst":
                key = (rec["attack"], rec["trial"])
                if key in burst_hits:
                    detected[rec["attack"]] += burst_hits[key]
                    total[rec["attack"]] += 1
                    del burst_hits[key]

    return {a: {"detected": detected[a], "total": total[a]} for a in ATTACKS}


def build_report(clean_len: int, results: dict, per_method_seconds: dict) -> str:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    L = []
    L.append("<!DOCTYPE html><html lang='sr'><head><meta charset='utf-8'>")
    L.append("<title>Detekcija ubrizganih napada — interleaved (900k)</title>")
    L.append("<style>")
    L.append("body{font-family:system-ui,Arial,sans-serif;max-width:900px;margin:30px auto;padding:0 20px;color:#e6edf3;background:#0d1117}")
    L.append("h1{font-size:22px}h2{font-size:17px;margin-top:28px;border-bottom:1px solid #30363d;padding-bottom:5px}")
    L.append("table{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}")
    L.append("th,td{border:1px solid #30363d;padding:7px 10px;text-align:center}")
    L.append("th{background:#1f2630;color:#9ba7b4}td{color:#e6edf3}")
    L.append("td.best{background:rgba(63,185,80,.15);color:#3fb950;font-weight:700}")
    L.append(".mut{color:#6e7681;font-size:13px}")
    L.append("</style></head><body>")
    L.append("<h1>Detekcija ubrizganih napada — interleaved na punom toku</h1>")
    L.append(f"<div class='mut'>Generisano: {now} · normalni tok: {clean_len:,} okvira · "
             f"3 manifesta ubrizgana po timestamp-u, ceo tok skorovan redom.</div>")

    L.append("<h2>Detekcija (prosek kroz 3 manifesta)</h2>")
    L.append("<table><tr><th>Napad</th><th>Heuristika</th><th>Isolation Forest</th><th>One-Class SVM</th></tr>")
    for a in ATTACKS:
        cells = []
        best = -1
        for m in ["heuristic", "isolation_forest", "one_class_svm"]:
            d = results[m][a]["detected"]
            tot = results[m][a]["total"]
            p = d / max(tot, 1) * 100
            best = max(best, p)
            cells.append((p, d, tot))
        row = f"<td>{a}</td>"
        for (p, d, tot) in cells:
            cls = " class='best'" if p == best else ""
            row += f"<td{cls}>{p:.1f}% <span class='mut'>({d}/{tot})</span></td>"
        L.append(f"<tr>{row}</tr>")
    L.append("</table>")
    L.append("<div class='mut'>DoS = 10 burst-ova × 3 manifesta; Fuzzy/gear/RPM = 100 pojedinačnih × 3 manifesta. "
             "Interleaved: okviri su stvarno ubačeni u pun tok, pa je gap/step računat od stvarnog prethodnog okvira.</div>")

    L.append("<h2>Vremenska efikasnost (skorovanje celog toka + ubrizganih)</h2>")
    L.append("<table><tr><th>Metoda</th><th>vreme (s)</th><th>okvira</th><th>µs / okvir</th></tr>")
    for m, name in [("heuristic", "Heuristika"), ("isolation_forest", "Isolation Forest"),
                    ("one_class_svm", "One-Class SVM")]:
        sec = per_method_seconds[m]
        n = clean_len + 380 * 3  # clean + injected frames
        L.append(f"<tr><td>{name}</td><td>{sec:.1f}</td><td>{n:,}</td><td>{sec/n*1e6:.1f}</td></tr>")
    L.append("</table>")
    L.append("<div class='mut'>Vreme za skorovanje celog normalnog toka sa ubrizganim okvirima (per-frame, live režim).</div>")

    L.append("</body></html>")
    return "\n".join(L)


def main():
    print("=== Detekcija ubrizganih napada — interleaved na 900k toku ===\n")
    clean = _clean_stream()
    print(f"normal tok: {len(clean):,} okvira")

    results = {}
    seconds = {}
    for method, name in [("heuristic", "Heuristika"),
                         ("isolation_forest", "Isolation Forest"),
                         ("one_class_svm", "One-Class SVM")]:
        print(f"\n[{name}] ...")
        engine = IdsEngine(method)
        t0 = time.perf_counter()
        agg = _manifest_interleaved(engine, clean, INJ.MANIFEST_PATHS)
        sec = time.perf_counter() - t0
        results[method] = agg
        seconds[method] = sec
        print(f"  vreme: {sec:.1f}s")
        for a in ATTACKS:
            d = agg[a]["detected"]; tot = agg[a]["total"]
            print(f"  {a:<6} {d}/{tot}  ({d/max(tot,1)*100:.1f}%)")

    print("\n[Generisanje HTML izveštaja]")
    html_out = build_report(len(clean), results, seconds)
    with open(REPORT_PATH, "w") as f:
        f.write(html_out)
    print(f"\n✅ Izveštaj -> {REPORT_PATH}")


if __name__ == "__main__":
    main()
