"""
run_svm_boundary_viz.py — SVM-specifična vizuelizacija (granica odluke).

IF i SVM dele ISTI feature prostor (gap_z, max_abs_z, n_over_2), ali SVM ima
NAUČENU granicu odluke (RBF One-Class SVM + RobustScaler). Ova skripta prikazuje:
  1) 2D konturu SVM granice odluke u ravni (max_abs_z, n_over_2) — glavnoj
     diskriminativnoj ravni — preko tačaka, koristeći STVARNI persistirani model.
  2) Interaktivni 3D prikaz gde su tačke obojene prema SVM odluci
     (inlier = normalno/plavo, outlier = anomalno/crveno).

Izlaz: report_plots/svm_* .png i .html (self-contained).
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
import ids_one_class_svm as SVM

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "report_plots")


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
    print("[1] Učitavanje persistiranog SVM modela ...")
    gsvm = SVM.load_model()
    print(f"    threshold = {gsvm.threshold:.6f}")

    print("[2] baseline + featurizacija celog toka ...")
    t, _, _ = HE.load_normal_split()
    baseline = IF.learn_baseline(t.reset_index(drop=True))
    stream = build_stream()
    feat, _ = IF.extract_frame_features(stream, baseline)
    # napomena: SVM koristi sopstveni extract_frame_features (isti rezultat)
    feat_svm, _ = SVM.extract_frame_features(stream, baseline)
    X_raw = feat_svm[SVM.FEATURES].astype(float).to_numpy()
    tag = stream["tag"].to_numpy()
    attack = stream["attack"].to_numpy()

    # SVM skor (skaliran + score_samples)
    scores = gsvm.score(feat_svm)          # signed distance
    is_outlier = scores < gsvm.threshold

    print(f"    normal={int((tag==0).sum()):,} inj={int((tag==1).sum()):,} fault={int((tag==2).sum()):,}")
    print(f"    SVM proglasio anomalnim (od celog toka): {int(is_outlier.sum()):,}")

    # X u SYMLOG prostoru za crtanje
    X_log = X_raw.copy()
    X_log[:, 1] = symlog(X_raw[:, 1])

    # ===== 1) 2D kontura granice u (max_abs_z, n_over_2) =====
    # Radimo u RAW feature prostoru da bismo koristili pravi scaler/boundary,
    # ali konturu crtamo na symlog(osu) preko grid mappiranja.
    # Ose: x = symlog(max_abs_z), y = n_over_2. gap_z fiksiramo na median (0).
    gap_med = float(np.median(X_raw[:, 0]))

    # grid u symlog(max_abs_z) prostoru
    x_min, x_max = X_log[:, 1].min(), X_log[:, 1].max()
    x_grid = np.linspace(x_min, x_max, 220)
    y_grid = np.linspace(0, 5, 120)   # n_over_2 je u [0,5]
    # invertuj symlog da dobijemo raw max_abs_z
    linthresh = 10.0
    raw_x = np.sign(x_grid) * linthresh * (10**np.abs(x_grid) - 1.0)

    XX, YY = np.meshgrid(x_grid, y_grid)
    ZZ = np.zeros_like(XX)
    for i in range(XX.shape[0]):
        for j in range(XX.shape[1]):
            p = np.array([[gap_med, raw_x[j], YY[i, j]]])
            ZZ[i, j] = gsvm.score_row(p)[0]

    # granica: score == threshold
    fig, ax = plt.subplots(figsize=(9.5, 6.8))
    # normalna gustina
    mask_n = tag == 0
    ax.hist2d(X_log[mask_n, 1], X_log[mask_n, 2], bins=[200, 60],
              cmap="Greys", alpha=0.55)
    cs = ax.contour(XX, YY, ZZ, levels=[gsvm.threshold], colors=["#c0392b"],
                    linewidths=2.5, linestyles="--")
    ax.clabel(cs, fmt="SVM granica", fontsize=9)
    # tačke napada obojene po SVM odluci
    mask_i = tag == 1
    det = ~is_outlier[mask_i]   # otkriven (outlier) = True znači anomalan
    ax.scatter(X_log[mask_i & is_outlier, 1], X_log[mask_i & is_outlier, 2],
               s=26, c="#e5534b", alpha=0.85, edgecolors="black", linewidths=0.4,
               label="ubrizgan napad (SVM: anomalan)")
    ax.scatter(X_log[mask_i & ~is_outlier, 1], X_log[mask_i & ~is_outlier, 2],
               s=26, c="#4db6ac", alpha=0.85, edgecolors="black", linewidths=0.4,
               label="ubrizgan napad (SVM: propušten)")
    # FP
    mask_f = tag == 2
    ax.scatter(X_log[mask_f, 1], X_log[mask_f, 2], s=180, c="#f1c40f", marker="^",
               edgecolors="black", linewidths=1, label="lažni pozitiv 0x0545")
    ax.set_xlabel("max_abs_z (symlog)")
    ax.set_ylabel("n_over_2")
    ax.set_title("SVM granica odluke (max_abs_z, n_over_2) — zelena=propušteno")
    ax.legend(loc="upper right", fontsize=7.5)
    ax.grid(alpha=0.15)
    fig.tight_layout()
    p2 = os.path.join(OUT_DIR, "svm_boundary_2d.png")
    fig.savefig(p2, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"    -> {p2}")

    # ===== 2) interaktivni 3D obojen po SVM odluci =====
    import plotly.graph_objects as go
    rng = np.random.default_rng(0)
    n = int(mask_n.sum())
    n_idx = np.where(mask_n)[0][rng.choice(n, size=min(20000, n), replace=False)]

    fig3 = go.Figure()
    # normal inlier (plavo, providno)
    n_in = n_idx[~is_outlier[n_idx]]
    n_out = n_idx[is_outlier[n_idx]]
    fig3.add_trace(go.Scatter3d(x=X_log[n_in,0], y=X_log[n_in,1], z=X_log[n_in,2],
        mode="markers", name="normal — SVM inlier (uzorak)",
        marker=dict(size=1.2, color="#5dade2", opacity=0.2),
        hovertemplate="gap_z=%{x:.2f}<br>max_abs_z=%{y:.2f}<br>n_over_2=%{z:.0f}<extra></extra>"))
    fig3.add_trace(go.Scatter3d(x=X_log[n_out,0], y=X_log[n_out,1], z=X_log[n_out,2],
        mode="markers", name="normal — SVM outlier (FP)",
        marker=dict(size=3, color="#c0392b", opacity=0.8),
        hovertemplate="gap_z=%{x:.2f}<br>max_abs_z=%{y:.2f}<br>n_over_2=%{z:.0f}<extra></extra>"))
    # napadi: detektovani vs propušteni
    i_det = mask_i & is_outlier
    i_miss = mask_i & ~is_outlier
    fig3.add_trace(go.Scatter3d(x=X_log[i_det,0], y=X_log[i_det,1], z=X_log[i_det,2],
        mode="markers", name=f"napad — SVM detektovan ({int(i_det.sum())})",
        marker=dict(size=3.5, color="#e5534b", opacity=0.95, line=dict(color="black", width=0.4)),
        hovertemplate="<b>detektovan</b><br>%{x:.2f},%{y:.2f},%{z:.0f}<extra></extra>"))
    fig3.add_trace(go.Scatter3d(x=X_log[i_miss,0], y=X_log[i_miss,1], z=X_log[i_miss,2],
        mode="markers", name=f"napad — SVM propušten ({int(i_miss.sum())})",
        marker=dict(size=3.5, color="#4db6ac", opacity=0.95, line=dict(color="black", width=0.4)),
        hovertemplate="<b>propušten</b><br>%{x:.2f},%{y:.2f},%{z:.0f}<extra></extra>"))
    fig3.add_trace(go.Scatter3d(x=X_log[mask_f,0], y=X_log[mask_f,1], z=X_log[mask_f,2],
        mode="markers", name="lažni pozitiv 0x0545",
        marker=dict(size=7, color="#f1c40f", symbol="diamond", line=dict(color="black", width=1)),
        hovertemplate="<b>0x0545 FP</b><br>%{x:.2f},%{y:.2f},%{z:.0f}<extra></extra>"))
    fig3.update_layout(
        title="One-Class SVM — odluke na celom interleaved toku (rotiraj mišem)",
        scene=dict(xaxis_title="gap_z", yaxis_title="max_abs_z (symlog)",
                   zaxis_title="n_over_2", bgcolor="white"),
        legend=dict(x=0.02, y=0.98, bgcolor="rgba(255,255,255,0.7)"),
        margin=dict(l=0, r=0, t=40, b=0), paper_bgcolor="white")
    out3 = os.path.join(OUT_DIR, "svm_decision_3d_selfcontained.html")
    fig3.write_html(out3, include_plotlyjs=True, full_html=True)
    print(f"    -> {out3} ({os.path.getsize(out3)} bytes)")


if __name__ == "__main__":
    main()
