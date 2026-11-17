#!/usr/bin/env python3
"""Rebuilds only figures/fig_testbed.pdf (measured excess latency against the two models) from data/testbed_configurations.csv.
The same figure is drawn by Measurements/testbed/paper_assets.py together with the tables and numbers; this script needs nothing else.
Panel titles: (a) idealized model, (b) stack model (the names used in the text)."""
import csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
HERE = os.path.dirname(os.path.abspath(__file__))
rows = list(csv.DictReader(open(os.path.join(HERE, "data", "testbed_configurations.csv"), newline="")))
short = {"RSA-2048|ECDHE-P256": "RSA-2048 / ECDHE", "ECDSA-P256|X25519": "ECDSA-P256 / X25519",
         "ECDSA-P256|X25519MLKEM768": "ECDSA-P256 / X25519MLKEM768", "ML-DSA-44|ML-KEM-768": "ML-DSA-44 / ML-KEM-768",
         "ML-DSA-65|ML-KEM-768": "ML-DSA-65 / ML-KEM-768", "ML-DSA-87|ML-KEM-1024": "ML-DSA-87 / ML-KEM-1024"}
cols = {"RSA-2048|ECDHE-P256": "#999999", "ECDSA-P256|X25519": "#000000", "ECDSA-P256|X25519MLKEM768": "#56B4E9",
        "ML-DSA-44|ML-KEM-768": "#009E73", "ML-DSA-65|ML-KEM-768": "#D55E00", "ML-DSA-87|ML-KEM-1024": "#CC79A7"}
f = lambda r, k: float(r[k])
hi = max(max(f(r, "excess_ms"), f(r, "model_ms"), f(r, "model_stack_ms")) for r in rows) * 1.3
fig, axs = plt.subplots(1, 2, figsize=(6.2, 3.7), sharex=True, sharey=True)
for ax, key, title in ((axs[0], "model_ms", "(a) idealized model"), (axs[1], "model_stack_ms", "(b) stack model")):
    for su, c in cols.items():
        ts = [r for r in rows if r["suite"] == su]
        ax.scatter([f(r, "excess_ms") for r in ts], [f(r, key) for r in ts], s=12, c=c, alpha=0.8, label=short[su], linewidths=0)
    ax.plot([2, hi], [2, hi], "k--", lw=0.7)
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlim(2, hi); ax.set_ylim(2, hi)
    ax.set_xlabel("measured excess latency (ms)"); ax.set_title(title, fontsize=9); ax.grid(alpha=0.2)
axs[0].set_ylabel("model transport time (ms)")
for ax in axs:
    ax.tick_params(labelsize=8); ax.xaxis.label.set_size(8.5)
axs[0].yaxis.label.set_size(8.5)
h, l = axs[1].get_legend_handles_labels()
fig.legend(h, l, loc="lower center", ncol=3, fontsize=7.5, frameon=False, markerscale=1.4)
fig.tight_layout(rect=(0, 0.14, 1, 1))
fig.savefig(os.path.join(HERE, "figures", "fig_testbed.pdf"))
