"""
run_manifest_interleaved_plotly3d.py — interaktivna 3D vizuelizacija (Plotly).

Generiše samostalan HTML sa rotirajućim 3D grafikom feature-prostora
(gap_z, max_abs_z, n_over_2) za ceo interleaved tok. Može se pomerati mišem,
zumirati i hover-ovati po tačkama.

Koristi plotly.graph_objects.Scatter3d sa WebGL rendererom. Normalne poruke su
downsample-ovane (da graf ostane tečan), ubrizgani i FP su svi prikazani.

Izlaz: report_plots/interleaved_3d_interactive.html (i embed u izveštaj po potrebi).
"""
from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd

import plotly.graph_objects as go

import ids_heuristic as HE
import ids_injection as INJ
import ids_isolation_forest as IF

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "report_plots")

N_NORMAL = 20000  # downsample normalnih (tečnost)

ATTACK_COLORS = {
    "DoS": "#d64541",
    "Fuzzy": "#e67e22",
    "gear": "#2e86de",
    "RPM": "#8e44ad",
}
COL_NORMAL = "#8892a0"
COL_FP = "#f1c40f"


def _payload_hex(rec) -> str:
    return "".join(
        "00" if str(rec[c]).strip().lower() in ("", "nan", "none")
        else str(rec[c]).strip() for c in HE.BCOLS
    )


def build_interleaved_stream():
    clean = INJ.normalize_clean().sort_values("Timestamp").reset_index(drop=True)
    inj_rows = []
    for path in INJ.MANIFEST_PATHS:
        with open(path) as f:
            for rec in json.load(f):
                inj_rows.append(rec)

    df_clean = clean[["Timestamp", "CAN_ID"] + HE.BCOLS].copy()
    df_clean["tag"] = 0
    df_clean["attack"] = ""

    inj_df = pd.DataFrame(inj_rows)[["timestamp", "CAN_ID"] + HE.BCOLS]
    inj_df = inj_df.rename(columns={"timestamp": "Timestamp"})
    inj_df["tag"] = 1
    inj_df["attack"] = [r["attack"] for r in inj_rows]

    fp_specs = [
        ["d8", "72", "00", "83", "00", "00", "00", "00"],
        ["d8", "00", "00", "84", "00", "00", "00", "00"],
        ["d8", "86", "00", "8e", "00", "00", "00", "00"],
    ]
    mid_ts = float(clean["Timestamp"].median())
    fp_df = pd.DataFrame([
        {"CAN_ID": "0x0545", "Timestamp": mid_ts + i * 0.001,
         **dict(zip(HE.BCOLS, s))} for i, s in enumerate(fp_specs)
    ])
    fp_df["tag"] = 2
    fp_df["attack"] = "fault"

    merged = pd.concat([df_clean, inj_df, fp_df], ignore_index=True)
    return merged.sort_values("Timestamp", kind="stable").reset_index(drop=True)


def symlog(v, linthresh=10.0):
    return np.sign(v) * np.log10(1.0 + np.abs(v) / linthresh)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print("[1] baseline + featurizacija ...")
    t, _, _ = HE.load_normal_split()
    baseline = IF.learn_baseline(t.reset_index(drop=True))
    stream = build_interleaved_stream()
    feat, _ = IF.extract_frame_features(stream, baseline)
    X = feat[IF.FEATURES].astype(float).to_numpy()
    tag = stream["tag"].to_numpy()
    attack = stream["attack"].to_numpy()

    Xl = X.copy()
    Xl[:, 1] = symlog(X[:, 1])

    mask_n = tag == 0
    mask_i = tag == 1
    mask_f = tag == 2

    # downsample normal
    rng = np.random.default_rng(0)
    n = int(mask_n.sum())
    s_idx = rng.choice(n, size=min(N_NORMAL, n), replace=False)
    n_idx = np.where(mask_n)[0][s_idx]

    fig = go.Figure()

    # normal (sivo, providno)
    fig.add_trace(go.Scatter3d(
        x=Xl[n_idx, 0], y=Xl[n_idx, 1], z=Xl[n_idx, 2],
        mode="markers", name=f"normal ({n:,} — uzorak {len(n_idx):,})",
        marker=dict(size=1.2, color=COL_NORMAL, opacity=0.25),
        hovertemplate="gap_z=%{x:.2f}<br>max_abs_z=%{y:.2f}<br>n_over_2=%{z:.0f}<extra></extra>",
    ))

    # ubrizgani, po tipu
    for lbl, col in ATTACK_COLORS.items():
        m = mask_i & (attack == lbl)
        fig.add_trace(go.Scatter3d(
            x=Xl[m, 0], y=Xl[m, 1], z=Xl[m, 2],
            mode="markers", name=f"{lbl} ({int(m.sum())})",
            marker=dict(size=3.5, color=col, opacity=0.95,
                        line=dict(color="black", width=0.4)),
            hovertemplate=f"<b>{lbl}</b><br>gap_z=%{{x:.2f}}<br>max_abs_z=%{{y:.2f}}<br>n_over_2=%{{z:.0f}}<extra></extra>",
        ))

    # FP (žuto)
    fig.add_trace(go.Scatter3d(
        x=Xl[mask_f, 0], y=Xl[mask_f, 1], z=Xl[mask_f, 2],
        mode="markers", name="lažni pozitiv 0x0545",
        marker=dict(size=7, color=COL_FP, symbol="diamond",
                    line=dict(color="black", width=1)),
        hovertemplate="<b>0x0545 (FP)</b><br>gap_z=%{x:.2f}<br>max_abs_z=%{y:.2f}<br>n_over_2=%{z:.0f}<extra></extra>",
    ))

    fig.update_layout(
        title="IDS feature prostor — ceo interleaved tok (interaktivno, rotiraj mišem)",
        scene=dict(
            xaxis_title="gap_z",
            yaxis_title="max_abs_z (symlog)",
            zaxis_title="n_over_2",
            bgcolor="white",
        ),
        legend=dict(x=0.02, y=0.98, bgcolor="rgba(255,255,255,0.7)"),
        margin=dict(l=0, r=0, t=40, b=0),
        width=1000, height=720,
        paper_bgcolor="white",
    )

    out_html = os.path.join(OUT_DIR, "interleaved_3d_interactive.html")
    fig.write_html(out_html, include_plotlyjs="cdn", full_html=True)
    print(f"    -> {out_html}")

    # inlajnovana (sva plotly.js ubačena) verzija za embed u izveštaj
    inline = fig.to_html(full_html=False, include_plotlyjs="cdn",
                         default_width="100%", default_height="680px")
    out_frag = os.path.join(OUT_DIR, "interleaved_3d_fragment.html")
    with open(out_frag, "w") as f:
        f.write(inline)
    print(f"    -> {out_frag}")


if __name__ == "__main__":
    main()
