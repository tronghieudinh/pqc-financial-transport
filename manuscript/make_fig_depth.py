#!/usr/bin/env python3
"""figures/fig_depth.pdf: SWIFT MX latency against chain depth for six suites at three MTUs (100 Mbit/s, RTT 30 ms, cold connection, pi = 0).
Drawn at the text width (6.5 in) and included at 1.0 textwidth, so the text is not rescaled. Same model and palette as make_assets.py
(which cannot be run from this directory without the sweep CSVs); the values are the model's totals, computed directly with pqc_sim."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "Simulation"))
import pqc_sim as S
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#dcdbd6"
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MARK = ["o", "s", "^", "D", "v", "P"]
LSTY = ["-", "--", "-.", ":", (0, (5, 1)), (0, (3, 1, 1, 1))]
plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 9.5, "axes.edgecolor": INK2,
                     "axes.labelcolor": INK, "text.color": INK, "xtick.color": INK2, "ytick.color": INK2, "figure.facecolor": SURFACE,
                     "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE, "axes.grid": True, "grid.color": GRID,
                     "grid.linewidth": 0.5, "axes.spines.top": False, "axes.spines.right": False, "lines.linewidth": 1.6,
                     "lines.markersize": 5.5, "pdf.fonttype": 42})
SHOW = [S.BASELINE, "RSA-2048|ECDHE-P256", "ECDSA-P256|X25519MLKEM768", "ML-DSA-65|ML-KEM-768", "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]


def sig_only(s):
    return {"ECDSA-P256|X25519": "ECDSA-P256 (baseline)", "ECDSA-P256|X25519MLKEM768": "ECDSA-P256 + hybrid KEM",
            "RSA-2048|ECDHE-P256": "RSA-2048"}.get(s, s.split("|")[0])


def total(su, d, mtu):
    return S.run_flow(S.build_flow(su, "SWIFT_MX", d, "cold", False), S.Net(100.0, 30.0, mtu, 0.0, 4))["total"]


fig, axs = plt.subplots(1, 3, figsize=(6.5, 3.4), sharey=True)
for ax, mtu in zip(axs, (1280, 1500, 9000)):
    for i, su in enumerate(SHOW):
        ax.plot((1, 2, 3, 4), [total(su, d, mtu) for d in (1, 2, 3, 4)], marker=MARK[i], ls=LSTY[i], color=CAT[i], label=sig_only(su))
    ax.set_title(f"MTU {mtu} B", fontsize=11)
    ax.set_xlabel("chain depth $d$", fontsize=10)
    ax.set_xticks((1, 2, 3, 4))
    ax.tick_params(labelsize=9.5)
axs[0].set_ylabel("SWIFT MX latency (ms)", fontsize=10)
axs[0].set_yscale("log")
axs[0].set_yticks([100, 200, 300], ["100", "200", "300"])
axs[0].yaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
fig.legend(*axs[0].get_legend_handles_labels(), loc="lower center", ncol=3, frameon=False, fontsize=9.5, bbox_to_anchor=(0.5, -0.24))
fig.savefig(os.path.join(HERE, "figures", "fig_depth.pdf"), bbox_inches="tight"); plt.close(fig)
for su in (S.BASELINE, "ML-DSA-65|ML-KEM-768"):
    print(su, [round(total(su, d, 1500), 1) for d in (1, 2, 3, 4)], "d4-d1 =", round(total(su, 4, 1500) - total(su, 1, 1500), 1))
