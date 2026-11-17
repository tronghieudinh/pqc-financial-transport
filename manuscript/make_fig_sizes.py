#!/usr/bin/env python3
"""Rebuilds only figures/fig_sizes.pdf from ../Simulation/results/sizes.csv (the full make_assets.py
also needs the raw results.csv, which is not in the repository). Same drawing code as make_assets.py."""
import csv, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
SIM = os.path.join(HERE, "..", "Simulation"); sys.path.insert(0, SIM)
import pqc_sim as S
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
# ------------------------------------------------------------------ style (validated palette, fixed order)
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#dcdbd6"
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MARK = ["o", "s", "^", "D", "v", "P"]
LSTY = ["-", "--", "-.", ":", (0, (5, 1)), (0, (3, 1, 1, 1))]
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 8, "axes.titlesize": 8.5,
    "axes.labelsize": 8, "legend.fontsize": 7, "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "text.color": INK, "xtick.color": INK2,
    "ytick.color": INK2, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.spines.top": False,
    "axes.spines.right": False, "lines.linewidth": 1.4, "lines.markersize": 4, "pdf.fonttype": 42,
})

ALL = list(S.SUITES)
PNAME = {"SWIFT_MX": "SWIFT MX", "FAPI2": "FAPI 2.0"}
def sig_only(s):
    return {"ECDSA-P256|X25519": "ECDSA-P256 (baseline)", "ECDSA-P256|X25519MLKEM768": "ECDSA-P256 + hybrid KEM",
            "RSA-2048|ECDHE-P256": "RSA-2048", "RSA-3072|ECDHE-P256": "RSA-3072"}.get(s, s.split("|")[0])
SZ = list(csv.DictReader(open(os.path.join(SIM, "results", "sizes.csv"), newline="")))
szi = {(r["suite"], r["protocol"], int(r["depth"]), int(r["cc"])): r for r in SZ}
def save(fig, name):
    fig.savefig(os.path.join(HERE, "figures", name), bbox_inches="tight"); plt.close(fig)
# Fig: size breakdown
cats = [("payload_fixed", "Protocol payload"), ("obj_alg", "Signatures / keys / certs in messages"),
        ("tls_cert", "TLS certificate chains"), ("tls_cv", "TLS CertificateVerify"), ("tls_kex", "TLS key shares"),
        ("tls_other", "TLS other + record framing")]
fig, axs = plt.subplots(1, 2, figsize=(6.5, 4.2), sharey=True)   # drawn at the column width so that text is not rescaled
for ax, (pr, d) in zip(axs, (("SWIFT_MX", 3), ("FAPI2", 2))):
    left = [0.0] * len(ALL)
    for ci, (k, lab) in enumerate(cats):
        vals = [int(szi[(su, pr, d, 0)][k]) / 1024 for su in ALL]
        ax.barh(range(len(ALL)), vals, left=left, color=CAT[ci], edgecolor=SURFACE, linewidth=1.2, height=0.72,
                label=lab if pr == "SWIFT_MX" else None)
        left = [a + b for a, b in zip(left, vals)]
    for i, t in enumerate(left):
        ax.text(t + max(left) * 0.01, i, f"{t:.0f}", va="center", fontsize=8, color=INK2)
    ax.set_title(f"{PNAME[pr]}, chain depth {d}", fontsize=10)
    ax.set_xlabel("serialized size, one cold transaction (KiB)", fontsize=9)
    ax.tick_params(labelsize=8.5)
    ax.set_yticks(range(len(ALL)), [sig_only(s).replace(" (baseline)", "") for s in ALL])
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
fig.legend(loc="lower center", ncol=2, frameon=False, fontsize=8.5, bbox_to_anchor=(0.5, -0.14))
save(fig, "fig_sizes.pdf")

