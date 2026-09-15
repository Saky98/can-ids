"""
ids_viz.py — vizuelizacija feature-prostora IDS detektora za izveštaj.

Crta 3D i 2D slike u kojima se vidi kako normalne poruke formiraju gustu
gomilu oko koordinatnog početka, dok ubrizgane (napadne) poruke i lažni
pozitivi „beže" od te gomile. Radi nad STVARNIM frame-level feature vektorom
koji koriste Isolation Forest i One-Class SVM: (gap_z, max_abs_z, n_over_2).

Izlaz: PNG slike u <ids>/report_plots/ (kreira se po potrebi), koje
run_all_evaluation.py ugrađuje u evaluation_report.html (base64 inline).

Nema nove zavisnosti — koristi se isključivo matplotlib (već prisutan).
"""
from __future__ import annotations

import base64
import json
import os

import matplotlib
matplotlib.use("Agg")  # headless, nema GUI
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import ids_heuristic as HE
import ids_injection as INJ
import ids_isolation_forest as IF

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "report_plots")

# Koliko nasumičnih normalnih okvira se ucrtava (da slika ostane čitljiva).
N_NORMAL_SAMPLE = 8000

# Boje po kategoriji (konzistentne kroz sve slike).
COL_NORMAL = "#5a6b7a"      # siva — normalan saobraćaj
COL_INJ = "#e5534b"         # crvena — ubrizgani napadi
COL_FP = "#f2cc60"          # žuta — lažni pozitivi (0x0545)


def _ensure_outdir() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)


def _frame_features_for(cid: str, bytes8: list[int], baseline, per) -> dict:
    """Izračunaj (gap_z, max_abs_z, n_over_2) za JEDAN okvir (bez gap-a).

    bytes8 je lista 8 celobrojnih vrednosti bajtova. gap_z = 0.0 jer za
    pojedinačni okvir nemamo prethodnika; ovo konzistentno tretira i napadne
    i FP okvire (a kod normalnih koristimo pravi gap iz toka).
    """
    row = per.get(cid)
    pay = np.array(bytes8, dtype="float64")
    if row is None:
        return {"gap_z": 0.0, "max_abs_z": 0.0, "n_over_2": 0.0}
    zs = []
    for b in range(8):
        m = getattr(row, f"byte{b}_mean", None)
        s = getattr(row, f"byte{b}_std", None)
        if m is None or s is None or np.isnan(m) or np.isnan(s):
            zs.append(0.0)
        else:
            zs.append((pay[b] - m) / max(s, IF.EPS))
    zs = np.array(zs)
    return {
        "gap_z": 0.0,
        "max_abs_z": float(np.max(np.abs(zs))),
        "n_over_2": float(np.sum(np.abs(zs) > IF.OVER_THRESH)),
    }


def collect_plot_data(baseline):
    """Sakupi sve tačke za crtanje i vrati dict pod ključevima normal/injected/faults.

    normal   : (N,3) pravi frame feature-ovi normalnog uzorka (sa pravim gap_z)
    injected : (M,3) frame feature-ovi ubrizganih napada (gap_z=0 kao aproksimacija)
    faults   : (K,3) frame feature-ovi poznatih lažnih pozitiva 0x0545
    """
    per = IF._baseline_maps(baseline)[0]

    clean = INJ.normalize_clean()
    clean = clean.sort_values("Timestamp").reset_index(drop=True)

    # Uzorak normalnih — BCOLS kolone već drže 2-znakovne hex stringove po bajtu
    rng = np.random.default_rng(0)
    n = min(N_NORMAL_SAMPLE, len(clean))
    idx = np.sort(rng.choice(len(clean), size=n, replace=False))
    df_norm = clean.iloc[idx].reset_index(drop=True)
    feat_norm, _ = IF.extract_frame_features(df_norm, baseline)
    normal_pts = feat_norm[IF.FEATURES].astype(float).to_numpy()

    # Ubrizgani (iz sva 3 manifesta)
    inj_pts = []
    for path in INJ.MANIFEST_PATHS:
        with open(path) as f:
            manifest = json.load(f)
        for rec in manifest:
            bytes8 = [HE._parse_hex_byte(rec[c]) for c in HE.BCOLS]
            fv = _frame_features_for(str(rec["CAN_ID"]), bytes8, baseline, per)
            inj_pts.append([fv["gap_z"], fv["max_abs_z"], fv["n_over_2"]])
    inj_pts = np.array(inj_pts)

    # Lažni pozitivi — konkretne poruke 0x0545 identifikovane u evaluaciji
    fp_specs = [
        ["d8", "72", "00", "83", "00", "00", "00", "00"],
        ["d8", "00", "00", "84", "00", "00", "00", "00"],
        ["d8", "86", "00", "8e", "00", "00", "00", "00"],
    ]
    fp_pts = []
    for spec in fp_specs:
        bytes8 = [HE._parse_hex_byte(b) for b in spec]
        fv = _frame_features_for("0x0545", bytes8, baseline, per)
        fp_pts.append([fv["gap_z"], fv["max_abs_z"], fv["n_over_2"]])
    fp_pts = np.array(fp_pts)

    return {"normal": normal_pts, "injected": inj_pts, "faults": fp_pts}


def _plot_3d(ax, data):
    ax.scatter(data["normal"][:, 0], data["normal"][:, 1], data["normal"][:, 2],
               s=1.2, c=COL_NORMAL, alpha=0.28, depthshade=False,
               label=f"normal ({len(data['normal']):,} uzorak)")
    ax.scatter(data["injected"][:, 0], data["injected"][:, 1], data["injected"][:, 2],
               s=24, c=COL_INJ, alpha=0.95, depthshade=False,
               label=f"ubrizgani napadi ({len(data['injected'])})")
    ax.scatter(data["faults"][:, 0], data["faults"][:, 1], data["faults"][:, 2],
               s=100, c=COL_FP, alpha=1.0, marker="^", depthshade=False,
               label="lažni pozitivi (0x0545)")
    ax.set_xlabel("gap_z")
    ax.set_ylabel("max_abs_z")
    ax.set_zlabel("n_over_2")
    ax.legend(loc="upper left", fontsize=8)


def _plot_2d(ax, data, xi, yi, xlabel, ylabel):
    ax.scatter(data["normal"][:, xi], data["normal"][:, yi],
               s=3, c=COL_NORMAL, alpha=0.4, label=f"normal ({len(data['normal']):,})")
    ax.scatter(data["injected"][:, xi], data["injected"][:, yi],
               s=32, c=COL_INJ, alpha=0.95, label="ubrizgani napadi")
    ax.scatter(data["faults"][:, xi], data["faults"][:, yi],
               s=130, c=COL_FP, marker="^", label="lažni pozitivi (0x0545)")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.legend(loc="upper right", fontsize=8)


def generate_plots(baseline) -> dict[str, str]:
    """Generiši 3D + 3 projekcije 2D i vrati {ključ: putanja do PNG}."""
    _ensure_outdir()
    data = collect_plot_data(baseline)
    files = {}

    fig = plt.figure(figsize=(10, 7))
    ax = fig.add_subplot(111, projection="3d")
    _plot_3d(ax, data)
    fig.tight_layout()
    p3 = os.path.join(OUT_DIR, "feature_space_3d.png")
    fig.savefig(p3, dpi=130, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    files["3d"] = p3

    proj = [
        ("max_abs_z__n_over_2", 1, 2, "max_abs_z", "n_over_2"),
        ("gap_z__max_abs_z", 0, 1, "gap_z", "max_abs_z"),
        ("gap_z__n_over_2", 0, 2, "gap_z", "n_over_2"),
    ]
    for name, xi, yi, xl, yl in proj:
        fig, ax = plt.subplots(figsize=(8, 6))
        _plot_2d(ax, data, xi, yi, xl, yl)
        fig.tight_layout()
        p = os.path.join(OUT_DIR, f"feature_{name}.png")
        fig.savefig(p, dpi=130, bbox_inches="tight", facecolor="white")
        plt.close(fig)
        files[name] = p

    return files


def plots_as_html(files: dict[str, str]) -> str:
    """Napravi HTML blok koji ugrađuje generisane PNG slike (base64 inline)."""
    parts = []
    parts.append("<h2>7 · Vizuelizacija feature-prostora (IF/SVM)</h2>")
    parts.append("<div class='mut'>Normalne poruke (sive) formiraju gomilu oko "
                 "koordinatnog pocetka; ubrizgani napadi (crveno) i lažni pozitivi "
                 "0x0545 (zuto) se udaljavaju od nje. Feature vektor je isti koji koriste "
                 "Isolation Forest i One-Class SVM: (gap_z, max_abs_z, n_over_2). "
                 "Kod pojedinacnih napadnih/FP okvira gap_z je prikazan kao 0 "
                 "(nemaju prethodnika u ovom prikazu).</div>")

    order = ["3d", "max_abs_z__n_over_2", "gap_z__max_abs_z", "gap_z__n_over_2"]
    titles = {
        "3d": "3D prikaz (gap_z, max_abs_z, n_over_2)",
        "max_abs_z__n_over_2": "Projekcija: max_abs_z vs n_over_2",
        "gap_z__max_abs_z": "Projekcija: gap_z vs max_abs_z",
        "gap_z__n_over_2": "Projekcija: gap_z vs n_over_2",
    }
    for key in order:
        if key not in files:
            continue
        with open(files[key], "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        parts.append(
            f"<figure style='margin:20px 0'>"
            f"<img src='data:image/png;base64,{b64}' "
            f"style='width:100%;max-width:900px;background:#fff;border:1px solid #30363d;border-radius:4px'/>"
            f"<figcaption class='mut' style='margin-top:6px'>{titles[key]}</figcaption>"
            f"</figure>"
        )
    return "\n".join(parts)
