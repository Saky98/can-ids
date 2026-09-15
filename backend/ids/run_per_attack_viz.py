"""
run_per_attack_viz.py — JASAN prikaz grupacije normalnih + odskok po napadu.

Umesto apstraktnog 3D "oblaka", ovde:
  - normalan saobraćaj je prikazan kao GUSTA 2D masa (kontura/kernel-density),
    pa se jasno vidi njegovo "telo";
  - SVAKI tip napada je poseban panel (DoS / Fuzzy / gear / RPM), sa svojim
    tačkama koje odskaču od normalne mase;
  - ose su 2 najrazumljivije veličine: max_abs_z (koliko sadržaj odstupa) i
    n_over_2 (koliko bajtova je van opsega); max_abs_z je na symlog skali.

Izlaz: report_plots/per_attack_2x2.png (+ interaktivna verzija po izboru).
"""
from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

import ids_heuristic as HE
import ids_injection as INJ
import ids_isolation_forest as IF

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "report_plots")

ATTACKS = ["DoS", "Fuzzy", "gear", "RPM"]
ATTACK_COLORS = {"DoS": "#d64541", "Fuzzy": "#e67e22",
                 "gear": "#2e86de", "RPM": "#8e44ad"}


def symlog(v, linthresh=10.0):
    return np.sign(v) * np.log10(1.0 + np.abs(v) / linthresh)


def build_stream():
    clean = INJ.normalize_clean().sort_values("Timestamp").reset_index(drop=True)
    inj_rows = []
    for p in INJ.MANIFEST_PATHS:
        with open(p) as f:
            for r in json.load(f):
                inj_rows.append(r)
    dc = clean[["Timestamp", "CAN_ID"] + HE.BCOLS].copy()
    dc["tag"] = 0
    dc["attack"] = ""
    inj = pd.DataFrame(inj_rows)[["timestamp", "CAN_ID"] + HE.BCOLS]
    inj = inj.rename(columns={"timestamp": "Timestamp"})
    inj["tag"] = 1
    inj["attack"] = [r["attack"] for r in inj_rows]
    specs = [["d8", "72", "00", "83", "00", "00", "00", "00"],
             ["d8", "00", "00", "84", "00", "00", "00", "00"],
             ["d8", "86", "00", "8e", "00", "00", "00", "00"]]
    mid = float(clean["Timestamp"].median())
    fp = pd.DataFrame([{"CAN_ID": "0x0545", "Timestamp": mid + i * 0.001,
                        **dict(zip(HE.BCOLS, s))} for i, s in enumerate(specs)])
    fp["tag"] = 2
    fp["attack"] = "fault"
    m = pd.concat([dc, inj, fp], ignore_index=True)
    return m.sort_values("Timestamp", kind="stable").reset_index(drop=True)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print("[1] featurizacija ...")
    t, _, _ = HE.load_normal_split()
    baseline = IF.learn_baseline(t.reset_index(drop=True))
    stream = build_stream()
    feat, _ = IF.extract_frame_features(stream, baseline)
    X = feat[IF.FEATURES].astype(float).to_numpy()
    tag = np.asarray(stream["tag"].to_numpy())
    attack = np.asarray(stream["attack"].to_numpy())

    Xl = X.copy()
    Xl[:, 1] = symlog(X[:, 1])   # log skala za max_abs_z

    mask_n = tag == 0
    x_n = Xl[mask_n, 1]
    y_n = Xl[mask_n, 2]

    # 99.9% granica normalne mase (po max_abs_z) za iscrtavanje "ivice"
    x99 = np.percentile(x_n, 99.9)

    xmax = 2.0  # symlog gornja granica (pokriva do raw≈990)

    # ===== Slika 1: 1D preklop gustina (NAJJASNIJA priča grupacija vs odskok) =====
    fig1, axes1 = plt.subplots(2, 2, figsize=(13, 8.5))
    axes1 = axes1.ravel()
    bins = np.linspace(0, xmax, 90)
    for ax, a in zip(axes1, ATTACKS):
        m = (tag == 1) & (attack == a)
        ax.hist(x_n, bins=bins, color="#9aa4b1", alpha=0.75,
                label=f"normal ({int(mask_n.sum()):,})", log=True)
        ax.hist(Xl[m, 1], bins=bins, color=ATTACK_COLORS[a], alpha=0.9,
                label=f"{a} ({int(m.sum())})", log=True)
        ax.axvline(x99, color="#c0392b", linestyle="--", linewidth=1.4,
                   label=f"99.9% normalne mase")
        ax.set_title(f"{a}", fontsize=13, fontweight="bold",
                     color=ATTACK_COLORS[a])
        ax.set_xlabel("max_abs_z (symlog) → odstupanje sadržaja")
        ax.set_ylabel("broj okvira (log)")
        ax.legend(loc="upper right", fontsize=8)
        ax.grid(alpha=0.15)
    fig1.suptitle("Normalna masa je uski vrh; napadi se razvlače udesno (odskok)",
                  fontsize=14, fontweight="bold")
    fig1.tight_layout(rect=[0, 0, 1, 0.96])
    out1 = os.path.join(OUT_DIR, "per_attack_hist_1d.png")
    fig1.savefig(out1, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig1)
    print(f"    -> {out1}")

    # ===== Slika 2: 2D gustina (masa + tačke) =====
    fig, axes = plt.subplots(2, 2, figsize=(13, 9.5))
    axes = axes.ravel()
    for ax, a in zip(axes, ATTACKS):
        ax.hist2d(x_n, y_n, bins=[120, 7], range=[[0, xmax], [-0.4, 5.4]],
                  cmap="Greys", alpha=0.9, cmin=1)
        ax.axvline(x99, color="#c0392b", linestyle="--", linewidth=1.2,
                   alpha=0.8, label="99.9% normalne mase")
        m = (tag == 1) & (attack == a)
        ax.scatter(Xl[m, 1], Xl[m, 2], s=40, c=ATTACK_COLORS[a], edgecolors="black",
                   linewidths=0.5, alpha=0.9, zorder=5, label=f"{a} ({int(m.sum())})")
        mf = tag == 2
        ax.scatter(Xl[mf, 1], Xl[mf, 2], s=200, c="#f1c40f", marker="^",
                   edgecolors="black", linewidths=1, zorder=6, label="FP 0x0545")
        ax.set_title(f"{a}", fontsize=13, fontweight="bold", color=ATTACK_COLORS[a])
        ax.set_xlabel("max_abs_z (symlog) — odstupanje sadržaja")
        ax.set_ylabel("n_over_2 — br. bajtova van opsega")
        ax.set_xlim(0, xmax)
        ax.set_ylim(-0.4, 5.4)
        ax.legend(loc="upper right", fontsize=7.5, framealpha=0.95)
        ax.grid(alpha=0.1)
    fig.suptitle("Normalna masa (sivo) vs. napad po panelu — 2D prikaz",
                 fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out2 = os.path.join(OUT_DIR, "per_attack_2d.png")
    fig.savefig(out2, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"    -> {out2}")


if __name__ == "__main__":
    main()
