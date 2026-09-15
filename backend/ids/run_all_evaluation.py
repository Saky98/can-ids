"""
run_all_evaluation.py — one-shot evaluation runner + HTML report.

Runs the complete evaluation for all three IDS methods in a single call and
writes every result to one self-contained HTML report:

    .venv/bin/python backend/ids/run_all_evaluation.py

What it measures and reports
----------------------------
1. Data split  — chrono TRAIN/VALID/TEST sizes (no-leak protocol).
2. FPR         — false-positive rate on VALID and TEST-normal (clean frames).
3. Coverage    — whole attack-file coverage (continuity / "is the bus flagged?")
                for DoS / Fuzzy / gear / RPM.
4. Red-team    — the 3-manifest injection test, averaged (the honest per-frame
                detection rate), for all three methods.
5. Timing      — wall-clock time of the red-team (manifest) scoring per method,
                and a per-frame µs figure (this is the "vremenska efikasnost").

Output file: <ids>/evaluation_report.html  (regenerated each run; the path is
printed at the end so a demo can be regenerated in one go).

Note: models are NOT re-trained here vs. a different recipe; this re-runs the
SAME training/eval as the individual module mains, collecting results object-
wise (no subprocess/print parsing), so the numbers are identical to the module
mains.
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
import ids_isolation_forest as IF
import ids_one_class_svm as SVM
import ids_viz
from ids_runtime import IdsEngine

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_PATH = os.path.join(HERE, "evaluation_report.html")

ATTACKS = ["DoS", "Fuzzy", "gear", "RPM"]

# Total injected frames across all 3 manifests (380 records each).
INJECTED_COUNT = 380 * 3

# Deterministic prefix cap for per-frame coverage over whole attack files (~4M
# frames each), so the per-frame Python loop stays practical. Matches the idea
# of the OCSVM ATTACK_COVERAGE_CAP (1_500_000).
ATTACK_COVERAGE_CAP = 1_500_000


def _pct(part: float, whole: float) -> str:
    return f"{part / whole * 100:.2f}%" if whole else "0.00%"


def _fpr(pred_df: pd.DataFrame) -> tuple[int, int]:
    n = len(pred_df)
    flagged = int((pred_df["anomaly"] > 0).sum())
    return flagged, n


# --- heuristic -----------------------------------------------------------------

def eval_heuristic():
    t, v, te = HE.load_normal_split()
    te = te.reset_index(drop=True)

    # Per-frame heuristic = the SAME code path the live Simulator uses
    # (ids_runtime._check_heuristic). This is what the thesis reports as the
    # heuristic's real-time behaviour (one frame -> one verdict, no 1s window).
    engine = IdsEngine("heuristic")

    # FPR on TEST-normal, per-frame (frame-level, not window-level)
    val_fpr = _per_frame_fpr(engine, v.reset_index(drop=True))
    test_fpr = _per_frame_fpr(engine, te)

    # per-frame coverage over whole attack files (same granularity as IF/SVM)
    coverage = {}
    for lbl in ATTACKS:
        coverage[lbl] = _per_frame_coverage_heuristic(engine, lbl)

    # red-team manifests — TRUE interleaved test over the full ~900k normal stream
    clean = INJ.normalize_clean()
    manifest_avg = _manifest_summary(_manifest_interleaved(engine, clean, INJ.MANIFEST_PATHS))
    n_inj = sum(manifest_avg[a]["total"] for a in ATTACKS)

    # time the interleaved manifest scoring (re-run once, timed)
    manifest_seconds = _time_interleaved(engine, clean, INJ.MANIFEST_PATHS)

    return {
        "split": (len(t), len(v), len(te)),
        "val_fpr": val_fpr,
        "test_fpr": test_fpr,
        "coverage": coverage,
        "manifest_avg": manifest_avg,
        "manifest_rates": {a: [round(manifest_avg[a]["pct"], 1)] for a in ATTACKS},
        "manifest_seconds": manifest_seconds,
        "manifest_frames": n_inj,
        "stream_frames": len(clean) + INJECTED_COUNT,
    }


def _manifest_summary(agg: dict) -> dict:
    """agg[a] = {'detected': int, 'total': int} -> per-attack {detected,total,pct}."""
    out = {}
    for a in ATTACKS:
        d = agg[a]["detected"]
        tot = agg[a]["total"]
        out[a] = {"detected": d, "total": tot,
                  "pct": d / max(tot, 1) * 100}
    return out


def _payload_hex(rec: dict) -> str:
    out = []
    for c in HE.BCOLS:
        s = str(rec[c]).strip()
        if s in ("", "nan", "None"):
            s = "00"
        out.append(s)
    return "".join(out)


def _time_interleaved(engine: IdsEngine, clean: pd.DataFrame,
                      paths: list[str]) -> float:
    """Wall-clock time of the interleaved manifest scoring over the full stream."""
    t0 = time.perf_counter()
    _manifest_interleaved(engine, clean, paths)
    return time.perf_counter() - t0


# --- forest --------------------------------------------------------------

def eval_forest():
    t, v, te = _load_split()
    baseline = IF.learn_baseline(t.reset_index(drop=True))
    per, known = IF._baseline_maps(baseline)

    t_feat, _ = IF.extract_frame_features(t.reset_index(drop=True), baseline)
    model = IF.fit(t_feat)
    gif = IF.GlobalIsolationForest(model, float("inf"), known)

    v_feat, v_unk = IF.extract_frame_features(v.reset_index(drop=True), baseline)
    IF.calibrate(gif, v_feat)
    v_pred = gif.predict(v_feat, v_unk)
    val_fpr = _fpr(v_pred)

    te_feat, te_unk = IF.extract_frame_features(te.reset_index(drop=True), baseline)
    te_pred = gif.predict(te_feat, te_unk)
    test_fpr = _fpr(te_pred)

    coverage = {}
    for lbl in ATTACKS:
        coverage[lbl] = IF._attack_file_summary(gif, baseline, lbl)

    clean = IF._clean_stream()
    # TRUE interleaved red-team test over the full ~900k normal stream
    eng = IdsEngine("isolation_forest")
    manifest_avg = _manifest_summary(_manifest_interleaved(eng, clean, INJ.MANIFEST_PATHS))

    n_inj = sum(manifest_avg[a]["total"] for a in ATTACKS)
    return {
        "split": (len(t), len(v), len(te)),
        "val_fpr": val_fpr,
        "test_fpr": test_fpr,
        "coverage": coverage,
        "manifest_avg": manifest_avg,
        "manifest_rates": {a: [round(manifest_avg[a]["pct"], 1)] for a in ATTACKS},
        "manifest_seconds": _time_interleaved(eng, clean, INJ.MANIFEST_PATHS),
        "manifest_frames": n_inj,
        "stream_frames": len(clean) + INJECTED_COUNT,
        "baseline": baseline,
    }


def eval_svm():
    t, v, te = _load_split()
    baseline = SVM.learn_baseline(t.reset_index(drop=True))
    per, known = SVM._baseline_maps(baseline)

    t_feat, _ = SVM.extract_frame_features(t.reset_index(drop=True), baseline)
    model, scaler = SVM.fit(t_feat)
    gsvm = SVM.GlobalOneClassSVM(model, scaler, float("-inf"), known)

    v_feat, v_unk = SVM.extract_frame_features(v.reset_index(drop=True), baseline)
    SVM.calibrate(gsvm, v_feat)
    v_pred = gsvm.predict(v_feat, v_unk)
    val_fpr = _fpr(v_pred)

    te_feat, te_unk = SVM.extract_frame_features(te.reset_index(drop=True), baseline)
    te_pred = gsvm.predict(te_feat, te_unk)
    test_fpr = _fpr(te_pred)

    coverage = {}
    for lbl in ATTACKS:
        coverage[lbl] = SVM._attack_file_summary(gsvm, baseline, lbl)

    clean = SVM._clean_stream()
    # TRUE interleaved red-team test over the full ~900k normal stream
    eng = IdsEngine("one_class_svm")
    manifest_avg = _manifest_summary(_manifest_interleaved(eng, clean, INJ.MANIFEST_PATHS))

    n_inj = sum(manifest_avg[a]["total"] for a in ATTACKS)
    return {
        "split": (len(t), len(v), len(te)),
        "val_fpr": val_fpr,
        "test_fpr": test_fpr,
        "coverage": coverage,
        "manifest_avg": manifest_avg,
        "manifest_rates": {a: [round(manifest_avg[a]["pct"], 1)] for a in ATTACKS},
        "manifest_seconds": _time_interleaved(eng, clean, INJ.MANIFEST_PATHS),
        "manifest_frames": n_inj,
        "stream_frames": len(clean) + INJECTED_COUNT,
        "baseline": baseline,
    }


def _load_split():
    return HE.load_normal_split()


def _load_baseline():
    """Shared per-ID clean baseline (identical for IF and SVM — same TRAIN)."""
    t, _, _ = HE.load_normal_split()
    return IF.learn_baseline(t.reset_index(drop=True))


def _per_frame_fpr(engine: IdsEngine, df: pd.DataFrame) -> tuple[int, int]:
    """Run the live per-frame detector over clean frames, count false positives."""
    fp = 0
    n = len(df)
    for _, r in df.iterrows():
        v = engine.check_hex(r["CAN_ID"], r["Timestamp"], _payload_hex(r))
        fp += int(v["block"])
    return fp, n


def _per_frame_coverage_heuristic(engine: IdsEngine, label: str) -> dict:
    """Per-frame coverage over one whole attack file: share of frames flagged.

    Mirrors IF/SVM _attack_file_summary, but scores each frame with the live
    per-frame heuristic (engine.check_hex), keeping gap/step state in order.
    Scores the FULL file (no cap).
    """
    path = HE.os.path.join(HE.DATA, f"{label}.csv")
    dtype = {"CAN_ID": str, **{c: str for c in HE.BCOLS}}
    df = pd.read_csv(path, usecols=["Timestamp", "CAN_ID"] + HE.BCOLS, dtype=dtype)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    flagged = 0
    n = len(df)
    for _, r in df.iterrows():
        v = engine.check_hex(r["CAN_ID"], r["Timestamp"], _payload_hex(r))
        flagged += int(v["block"])
    return {"label": label, "frames": n, "flagged": flagged,
            "coverage": flagged / n if n else 0.0}


def _manifest_interleaved(engine: IdsEngine, clean: pd.DataFrame,
                          paths: list[str]) -> dict:
    """TRUE interleaved red-team test: inject every manifest frame into the FULL
    normal stream (~900k frames) by timestamp, and score the ENTIRE merged stream
    in order (the live Simulator path). Gap/step are computed from the actual
    preceding frame in the stream, not a hand-picked same-ID predecessor.

    Uses engine.check_batch (per-frame verdicts, but vectorized) so the full
    ~900k stream completes in minutes; decisions are IDENTICAL to 1-at-a-time
    (gap/step state advances incrementally inside check_batch).

    Returns per-attack {detected, total} with burst = 1 event, scatter = each
    frame = 1 event. Each manifest is tracked by its own index so the three
    seeds do NOT collide (DoS -> 30 events, Fuzzy/gear/RPM -> 300 events).
    """
    # Collect injected records, tagging each with its manifest index.
    inj_rows = []  # (manifest_index, rec)
    for mi, path in enumerate(paths):
        with open(path) as f:
            manifest = json.load(f)
        for rec in manifest:
            inj_rows.append((mi, rec))

    # Build merged frame list: (ts, cid, payload_hex, (mi, rec) or None)
    clean_ts = clean["Timestamp"].to_numpy()
    clean_cid = clean["CAN_ID"].astype(str).to_numpy()
    clean_pay = np.array([_payload_hex(r) for r in clean[HE.BCOLS].to_dict("records")])

    frames = []
    for i in range(len(clean)):
        frames.append((clean_ts[i], clean_cid[i], clean_pay[i], None))
    for mi, rec in inj_rows:
        frames.append((rec["timestamp"], rec["CAN_ID"], _payload_hex(rec), (mi, rec)))
    frames.sort(key=lambda x: x[0])

    detected = {a: 0 for a in ATTACKS}
    total = {a: 0 for a in ATTACKS}
    burst_hits: dict[tuple, int] = {}       # (mi, attack, trial) -> 0/1
    scatter_seen: set[tuple] = set()

    BATCH = 256
    n = len(frames)
    for start in range(0, n, BATCH):
        chunk = frames[start:start + BATCH]
        ids = [f[1] for f in chunk]
        tss = [f[0] for f in chunk]
        pays = [f[2] for f in chunk]
        verdicts = engine.check_batch(list(zip(ids, tss, pays)))
        for (ts, cid, pay, tag), v in zip(chunk, verdicts):
            if tag is None:
                continue
            mi, rec = tag
            a = rec["attack"]
            block = int(v["block"])
            if rec["mode"] == "burst":
                key = (mi, a, rec["trial"])
                burst_hits[key] = burst_hits.get(key, 0) or block
            else:
                rkey = (mi, a, rec["trial"], rec["i"])
                if rkey not in scatter_seen:
                    scatter_seen.add(rkey)
                    detected[a] += block
                    total[a] += 1

    # finalize burst events (one per (manifest, attack, trial))
    for mi, path in enumerate(paths):
        with open(path) as f:
            manifest = json.load(f)
        for rec in manifest:
            if rec["mode"] == "burst":
                key = (mi, rec["attack"], rec["trial"])
                if key in burst_hits:
                    detected[rec["attack"]] += burst_hits[key]
                    total[rec["attack"]] += 1
                    del burst_hits[key]

    return {a: {"detected": detected[a], "total": total[a]} for a in ATTACKS}


def _pct_cell(part, whole) -> str:
    return _pct(part, whole)


def _esc(x) -> str:
    return html.escape(str(x))


def build_report(res_heuristic, res_forest, res_svm) -> str:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    split = res_forest["split"]  # same for all three
    L = []

    L.append("<!DOCTYPE html><html lang='sr'><head><meta charset='utf-8'>")
    L.append("<title>IDS evaluacija — Car-Hacking</title>")
    L.append("<style>")
    L.append("body{font-family:system-ui,-apple-system,Arial,sans-serif;max-width:1000px;margin:30px auto;padding:0 20px;color:#e6edf3;background:#0d1117}")
    L.append("h1{font-size:24px}h2{font-size:19px;margin-top:34px;border-bottom:1px solid #30363d;padding-bottom:6px}")
    L.append("table{border-collapse:collapse;width:100%;margin:14px 0;font-size:14px}")
    L.append("th,td{border:1px solid #30363d;padding:7px 10px;text-align:center}")
    L.append("th{background:#1f2630;color:#9ba7b4}td{color:#e6edf3}")
    L.append("td.best{background:rgba(63,185,80,.15);color:#3fb950;font-weight:700}")
    L.append(".mut{color:#6e7681;font-size:13px}")
    L.append(".mono{font-family:ui-monospace,Menlo,Consolas,monospace}")
    L.append("</style></head><body>")

    L.append(f"<h1>IDS evaluacija — rezultati</h1>")
    L.append(f"<div class='mut'>Generisano: {now} · izvor: <span class='mono'>backend/ids/run_all_evaluation.py</span></div>")

    # data split
    L.append("<h2>1 · Podela podataka</h2>")
    L.append("<table><tr><th>TRAIN</th><th>VALID</th><th>TEST</th></tr>")
    L.append(f"<tr><td>{split[0]:,}</td><td>{split[1]:,}</td><td>{split[2]:,}</td></tr></table>")
    L.append("<div class='mut'>hronološka podela normal.csv (no-leak); napadi se koriste samo za evaluaciju.</div>")

    # FPR
    L.append("<h2>2 · Stopa lažnih pozitiva (FPR)</h2>")
    L.append("<table><tr><th>Metoda</th><th>VALID (flagged/frames)</th><th>TEST-normal</th></tr>")
    for name, r in [("Heuristika", res_heuristic), ("Isolation Forest", res_forest), ("One-Class SVM", res_svm)]:
        vf, vn = r["val_fpr"]
        tf, tn = r["test_fpr"]
        L.append(f"<tr><td>{_esc(name)}</td><td>{vf}/{vn:,} ({_pct(vf,vn)})</td>"
                 f"<td>{tf}/{tn:,} ({_pct(tf,tn)})</td></tr>")
    L.append("</table>")
    L.append("<div class='mut'>Cilj je FPR ≈ 0 na čistom saobraćaju; sve tri metode mere per-frame (svaki okvir se pojedinačno skoruje, kao u live Simulatoru).</div>")

    # coverage
    L.append("<h2>3 · Pokrivenost celih napadnih fajlova (coverage, per-frame)</h2>")
    L.append("<table><tr><th>Napad</th><th>Heuristika</th><th>Isolation Forest</th><th>One-Class SVM</th></tr>")
    for a in ATTACKS:
        h = res_heuristic["coverage"][a]
        f = res_forest["coverage"][a]
        s = res_svm["coverage"][a]
        L.append(f"<tr><td>{a}</td>"
                 f"<td>{_esc(_pct_cell(h['flagged'], h['frames']))}</td>"
                 f"<td>{_esc(_pct_cell(f['flagged'], f['frames']))}</td>"
                 f"<td>{_esc(_pct_cell(s['flagged'], s['frames']))}</td></tr>")
    L.append("</table>")
    L.append("<div class='mut'>Sve tri metode mere per-frame (svaki okvir se pojedinačno skoruje). 'Velikodušna' kontinuitet mera — ne meri osetljivost na pojedinačne okvire; pravi test je sekcija 4.</div>")

    # manifest detection
    L.append("<h2>4 · Detekcija ubrizganih napada (interleaved na punom toku)</h2>")
    L.append("<table><tr><th>Napad</th><th>Heuristika</th><th>Isolation Forest</th><th>One-Class SVM</th></tr>")
    for a in ATTACKS:
        h = res_heuristic["manifest_avg"][a]
        f = res_forest["manifest_avg"][a]
        s = res_svm["manifest_avg"][a]
        best = max(h["pct"], f["pct"], s["pct"])
        def cell(r):
            txt = f"{r['pct']:.1f}% <span class='mut'>({r['detected']}/{r['total']})</span>"
            cls = " class='best'" if r["pct"] == best else ""
            return f"<td{cls}>{txt}</td>"
        L.append(f"<tr><td>{a}</td>{cell(h)}{cell(f)}{cell(s)}</tr>")
    L.append("</table>")
    L.append("<div class='mut'>Manifest okviri se interleaved ubacuju u PUN normalni tok (~900k poruka) po timestamp-u i ceo tok se skoruje redom (live režim). DoS = 10 burst-ova × 3 manifesta = 30 događaja; Fuzzy/gear/RPM = 100 pojedinačnih × 3 manifesta = 300 događaja.</div>")

    # timing
    L.append("<h2>5 · Vremenska efikasnost (skorovanje celog toka + ubrizganih)</h2>")
    L.append("<table><tr><th>Metoda</th><th>vreme (s)</th><th>skorovanih okvira</th><th>µs / okvir</th></tr>")
    for name, r in [("Heuristika", res_heuristic), ("Isolation Forest", res_forest), ("One-Class SVM", res_svm)]:
        sec = r.get("manifest_seconds")
        if sec is None:
            L.append(f"<tr><td>{_esc(name)}</td><td class='mut'>—</td><td class='mut'>—</td><td class='mut'>—</td></tr>")
            continue
        frames = r.get("stream_frames", 0)
        us = sec / frames * 1e6 if frames else 0.0
        L.append(f"<tr><td>{_esc(name)}</td><td>{sec:.1f}</td><td>{frames:,}</td><td>{us:.1f}</td></tr>")
    L.append("</table>")
    L.append("<div class='mut'>Vreme za skorovanje CELOG normalnog toka (~900k okvira) sa interleaved ubrizganim okvirima (per-frame, batch), za sve tri metode.</div>")

    # --- vizuelizacija feature-prostora ---
    try:
        baseline = res_forest.get("baseline")
        if baseline is None:
            baseline = _load_baseline()
        plot_files = ids_viz.generate_plots(baseline)
        L.append(ids_viz.plots_as_html(plot_files))
    except Exception as e:  # viz ne sme da sruši izveštaj
        L.append("<h2>7 · Vizuelizacija feature-prostora</h2>")
        L.append(f"<div class='mut'>Vizuelizacija nije uspela: {_esc(e)}</div>")

    L.append("<h2>8 · Reprodukcija</h2>")
    L.append("<div class='mut'>Pokrenuti ponovo:<br><span class='mono'>.venv/bin/python backend/ids/run_all_evaluation.py</span></div>")

    L.append("</body></html>")
    return "\n".join(L)


def main():
    print("=== IDS evaluacija (jedan poziv) ===\n")
    print("[1/4] Heuristika ...")
    res_heuristic = eval_heuristic()
    print("[2/4] Isolation Forest ...")
    res_forest = eval_forest()
    print("[3/4] One-Class SVM ...")
    res_svm = eval_svm()
    print("[4/4] Generisanje HTML izveštaja ...")
    html_out = build_report(res_heuristic, res_forest, res_svm)
    with open(REPORT_PATH, "w") as f:
        f.write(html_out)
    print(f"\n✅ Izveštaj -> {REPORT_PATH}")


if __name__ == "__main__":
    main()
