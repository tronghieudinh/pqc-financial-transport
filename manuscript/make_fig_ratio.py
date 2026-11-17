#!/usr/bin/env python3
"""figures/fig_ratio.pdf: ratio of size-dependent transport overhead O (serialisation + slow-start waiting + middlebox delay) to the modelled
cryptographic time, SWIFT MX at chain depth 3, RTT 30 ms, MTU 1500, cold connection, pi = 0, thirteen suites against bit rate. Same model and
palette as make_assets.py (which cannot be run from this directory without the sweep CSVs); computed directly with pqc_sim at CPU scale 1.
Drawn at the width at which it is included (0.9 textwidth of 6.5 in), so the text is not rescaled."""
import math, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "Simulation"))
import pqc_sim as S
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import TwoSlopeNorm, LinearSegmentedColormap

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#dcdbd6"
plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 9.5, "axes.edgecolor": INK2, "text.color": INK,
                     "xtick.color": INK2, "ytick.color": INK2, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
                     "savefig.facecolor": SURFACE, "pdf.fonttype": 42})
ALL = list(S.SUITES)
BWS = [10.0, 100.0, 200.0, 400.0, 800.0, 1600.0]


def sig_only(s):
    return {"ECDSA-P256|X25519": "ECDSA-P256", "ECDSA-P256|X25519MLKEM768": "ECDSA-P256 + hybrid KEM",
            "RSA-2048|ECDHE-P256": "RSA-2048", "RSA-3072|ECDHE-P256": "RSA-3072"}.get(s, s.split("|")[0])


def ratio(su, bw):
    r = S.run_flow(S.build_flow(su, "SWIFT_MX", 3, "cold", False), S.Net(bw, 30.0, 1500, 0.0, 4))
    return (r["ser"] + r["ssw"] + r["pen"]) / r["cpu"]


data = [[math.log10(max(1e-3, ratio(su, b))) for b in BWS] for su in ALL]
cmap = LinearSegmentedColormap.from_list("dv", ["#2a78d6", "#f0efec", "#eb6834"])
fig, ax = plt.subplots(figsize=(5.9, 4.4))
im = ax.imshow(data, cmap=cmap, norm=TwoSlopeNorm(vcenter=0.0, vmin=-1.0, vmax=2.2), aspect="auto")
ax.set_xticks(range(len(BWS)), [f"{b:g}" for b in BWS])
ax.set_yticks(range(len(ALL)), [sig_only(s) for s in ALL])
ax.tick_params(labelsize=9.5)
for i, row in enumerate(data):
    for j, v in enumerate(row):
        ax.text(j, i, f"{10 ** v:.1f}", ha="center", va="center", fontsize=8.5, color=INK)
ax.set_xlabel("bit rate (Mbit/s)", fontsize=10.5)
ax.grid(False)
cb = fig.colorbar(im, ax=ax, pad=0.02)
cb.set_label("transport overhead / cryptographic time", fontsize=9.5)
cb.set_ticks([-1, 0, 1, 2], labels=["0.1", "1", "10", "100"])
cb.ax.tick_params(labelsize=9)
fig.savefig(os.path.join(HERE, "figures", "fig_ratio.pdf"), bbox_inches="tight"); plt.close(fig)
print([ (sig_only(s), round(10 ** data[i][1], 1)) for i, s in enumerate(ALL) if s in (S.BASELINE, "ML-DSA-65|ML-KEM-768", "SLH-DSA-128s|ML-KEM-768")])
