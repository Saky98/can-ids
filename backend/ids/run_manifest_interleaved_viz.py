"""
run_manifest_interleaved_viz.py — vizuelizacija CELOG interleaved toka (poboljšana).

Prikazuje ceo tok (normal ~989k + 1.140 ubrizganih + 3 FP) u feature prostoru
(gap_z, max_abs_z, n_over_2) koji koriste Isolation Forest i One-Class SVM.

Poboljšanja u odnosu na sirovu verziju:
  - max_abs_z je na symlog skali (jer ubrizgani idu do ~494 a normalni do ~22,
    pa linearno sve zgusne u ugao).
  - normalni deo je prikazan kao 2D gustina (heatmap), ne kao 990k tačaka.
  - ubrizgani su obojeni po tipu napada, sa crnim okvirom i većim markerima.
  - lažni pozitivi 0x0545 su istaknuti trouglovima sa anotacijom.
"""
from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import ids_heuristic as HE
import ids_injection as INJ
import ids_isolation_forest as IF

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "report_plots")

# Paleta (semantički jasna)
COL_NORMAL = "#6c7a89"      # siva (normal)
COL_DOS = "#d64541"         # crvena
COL_FUZZY = "#e67e22"       # narandžasta
COL_GEAR = "#2e86de"        # plava
COL_RPM = "#8e44ad"         # ljubičasta
COL_FP = "#f1c40f"          # žuta (lažni pozitiv)

ATTACK_COLORS = [("DoS", COL_DOS), ("Fuzzy", COL_FUZZY),
                 ("gear", COL_GEAR), ("RPM", COL_RPM)]


def _payload_hex(rec) -> str:
    return "".join(
        "00" if str(rec[c]).strip().lower() in ("", "nan", "none")
        else str(rec[c]).strip() for c in HE.BCOLS
    )


def build_interleaved_stream():
    clean = INJ.normalize_clean()
    clean = clean.sort_values("Timestamp").reset_index(drop=True)

    inj_rows = []
    for path in INJ.MANIFEST_PATHS:
        with open(path) as f:
            manifest = json.load(f)
        for rec in manifest:
            inj_rows.append(rec)

    fp_specs = [
        ["d8", "72", "00", "83", "00", "00", "00", "00"],
        ["d8", "00", "00", "84", "00", "00", "00", "00"],
        ["d8", "86", "00", "8e", "00", "00", "00", "00"],
    ]

    df_clean = clean[["Timestamp", "CAN_ID"] + HE.BCOLS].copy()
    df_clean["tag"] = 0
    df_clean["attack"] = ""

    inj_df = pd.DataFrame(inj_rows)[["timestamp", "CAN_ID"] + HE.BCOLS]
    inj_df = inj_df.rename(columns={"timestamp": "Timestamp"})
    inj_df["tag"] = 1
    inj_df["attack"] = [r["attack"] for r in inj_rows]

    mid_ts = float(clean["Timestamp"].median())
    fp_df = pd.DataFrame([
        {"CAN_ID": "0x0545", "Timestamp": mid_ts + i * 0.001,
         **dict(zip(HE.BCOLS, spec))} for i, spec in enumerate(fp_specs)
    ])
    fp_df["tag"] = 2
    fp_df["attack"] = "fault"

    merged = pd.concat([df_clean, inj_df, fp_df], ignore_index=True)
    merged = merged.sort_values("Timestamp", kind="stable").reset_index(drop=True)
    return merged


def _compute(baseline):
    stream = build_interleaved_stream()
    feat, _ = IF.extract_frame_features(stream, baseline)
    X = feat[IF.FEATURES].astype(float).to_numpy()
    tag = stream["tag"].to_numpy()
    attack = stream["attack"].to_numpy()
    return X, tag, attack


def _density2d(ax, x, y, xbins, ybins):
    """Nacrtaj 2D gustinu normalnih tačaka kao heatmap."""
    h, xe, ye = np.histogram2d(x, y, bins=[xbins, ybins])
    # log skala za vidljivost; transponuj za imshow
    h = h.T
    with np.errstate(divide="ignore"):
        h = np.log1p(h)
    ax.imshow(h, extent=[xe[0], xe[-1], ye[0], ye[-1]], origin="lower",
              aspect="auto", cmap="Greys", alpha=0.85, vmin=0,
              vmax=h.max() * 0.9, interpolation="bilinear")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print("[1] Učenje baseline + featurizacija celog toka ...")
    t, _, _ = HE.load_normal_split()
    baseline = IF.learn_baseline(t.reset_index(drop=True))
    X, tag, attack = _compute(baseline)

    mask_n = tag == 0
    mask_i = tag == 1
    mask_f = tag == 2

    # --- symlog transform za max_abs_z (indeks 1) ---
    linthresh = 10.0  # linearno do 10, pa log
    def symlog(v):
        return np.sign(v) * np.log10(1.0 + np.abs(v) / linthresh)

    X_log = X.copy()
    X_log[:, 1] = symlog(X[:, 1])

    n = mask_n.sum()
    print(f"    normal={n:,}  injected={mask_i.sum():,}  fault={mask_f.sum():,}")

    # Uzorak za tačkasti prikaz ubrizganih (sve, samo 1140, OK)
    # --- 3D ---
    fig = plt.figure(figsize=(12, 8))
    ax = fig.add_subplot(111, projection="3d")
    # normal kao providna gomila (uzorak da ne guši)
    rng = np.random.default_rng(0)
    s_idx = rng.choice(n, size=min(30000, n), replace=False)
    ax.scatter(X_log[mask_n][s_idx, 0], X_log[mask_n][s_idx, 1],
               X_log[mask_n][s_idx, 2], s=1, c=COL_NORMAL, alpha=0.08,
               depthshade=False, label=f"normal ({n:,})")
    for lbl, col in ATTACK_COLORS:
        m = mask_i & (attack == lbl)
        ax.scatter(X_log[m, 0], X_log[m, 1], X_log[m, 2], s=20, c=col,
                   alpha=0.95, depthshade=False, edgecolors="black",
                   linewidths=0.4, label=lbl)
    ax.scatter(X_log[mask_f, 0], X_log[mask_f, 1], X_log[mask_f, 2],
               s=200, c=COL_FP, marker="^", depthshade=False,
               edgecolors="black", linewidths=0.8, label="lažni pozitivi 0x0545")
    ax.set_xlabel("gap_z", labelpad=8)
    ax.set_ylabel("max_abs_z (symlog)", labelpad=8)
    ax.set_zlabel("n_over_2", labelpad=6)
    ax.set_title("IDS feature prostor — ceo interleaved tok", fontsize=13)
    ax.legend(loc="upper left", fontsize=8, ncol=2)
    fig.tight_layout()
    p3 = os.path.join(OUT_DIR, "interleaved_3d.png")
    fig.savefig(p3, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"    -> {p3}")

    # --- 2D projekcije (sa gustinom) ---
    proj2d = [
        ("max_abs_z__n_over_2", 1, 2, "max_abs_z (symlog)", "n_over_2"),
        ("gap_z__max_abs_z", 0, 1, "gap_z", "max_abs_z (symlog)"),
        ("gap_z__n_over_2", 0, 2, "gap_z", "n_over_2"),
    ]
    for name, xi, yi, xl, yl in proj2d:
        fig, ax = plt.subplots(figsize=(9.5, 6.8))
        # gustina normalnih
        _density2d(ax, X_log[mask_n, xi], X_log[mask_n, yi],
                   120, 120)
        for lbl, col in ATTACK_COLORS:
            m = mask_i & (attack == lbl)
            ax.scatter(X_log[m, xi], X_log[m, yi], s=34, c=col, alpha=0.95,
                       edgecolors="black", linewidths=0.6, label=lbl, zorder=5)
        ax.scatter(X_log[mask_f, xi], X_log[mask_f, yi], s=220, c=COL_FP,
                   marker="^", edgecolors="black", linewidths=1.2,
                   label="lažni pozitivi 0x0545", zorder=6)
        ax.set_xlabel(xl, fontsize=11)
        ax.set_ylabel(yl, fontsize=11)
        ax.set_title(f"Projekcija: {xl} vs {yl}", fontsize=12)
        ax.legend(loc="upper right", fontsize=8)
        ax.grid(alpha=0.15)
        fig.tight_layout()
        p = os.path.join(OUT_DIR, f"interleaved_{name}.png")
        fig.savefig(p, dpi=140, bbox_inches="tight", facecolor="white")
        plt.close(fig)
        print(f"    -> {p}")

    print("\nGotovo.")


if __name__ == "__main__":
    main()
