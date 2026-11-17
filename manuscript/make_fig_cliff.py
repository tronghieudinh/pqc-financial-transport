#!/usr/bin/env python3
"""figures/fig_cliff.pdf: the depth series of the card-authorization example (ISO 8583-sized request and response, mutual TLS, 100 Mbit/s,
RTT 30 ms, MTU 1500, initial window 10, Reno): measured median time of the transaction (30 transactions per point, core grid,
Measurements/testbed/results/core_a.csv) and model (pqc_sim, stack model), ECDSA-P256 against ML-DSA-65, chain depth 1-4; below the plot
the model's segments of the server flight and of the client flight, with the flights that exceed the window of 10 in red."""
import csv, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "Simulation"))
import pqc_sim as S
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#dcdbd6"
C1, C2, WARN = "#2a78d6", "#eb6834", "#b02a1a"
plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 9, "axes.edgecolor": INK2, "text.color": INK,
                     "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE, "xtick.color": INK2,
                     "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False, "pdf.fonttype": 42})
CORE = next(p for p in (os.path.join(HERE, up, "Measurements", "testbed", "results", "core_a.csv") for up in ("..", os.path.join("..", ".."))) if os.path.exists(p))
rows = list(csv.DictReader(open(CORE, newline="")))
RTT, BW, MTU, W = 30.0, 100.0, 1500, 10


def measured(suite, d):
    return st.median(float(x["t_total_ms"]) for x in rows if x["suite"] == suite and x["depth"] == str(d) and x["net_id"] == "shaped"
                    and x["rtt_ms"] == "30" and not x["err"])


def model(suite, d):
    flow = S.build_flow(suite, "ISO_8583", d, "cold", False)
    net = S.Net(BW, RTT, MTU, 0.0, 99)
    total = S.run_flow(flow, net)["total"]
    mss, hdr = net.mtu - net.hdr, net.hdr
    cw, xi, segs = [net.init_cwnd] * 2, -1, []
    for stp in flow.steps:
        if stp[0] == "x":
            xi += 1
            side, nb = stp[1], stp[2]
            sizes = tuple(S.segment_sizes(flow.writes[xi], mss, cw[side]))
            _, _, n, _ = S._tcp_xfer(nb, mss, hdr, BW, RTT, cw[side], 1 << 30, False, sizes)
            segs.append((side, n)); cw[side] = S.grow_cwnd(cw[side], n)
    srv = max(n for s, n in segs if s == 1 and n > 1) if any(s == 1 and n > 1 for s, n in segs) else 1     # server certificate flight
    cli = max(n for s, n in segs if s == 0)                                                                # client second flight
    return total, srv, cli


SU = (("ECDSA-P256|X25519", "ECDSA-P256", C1), ("ML-DSA-65|ML-KEM-768", "ML-DSA-65", C2))
fig, ax = plt.subplots(figsize=(6.3, 3.6))
data = {}
for suite, lab, col in SU:
    ds = [1, 2, 3, 4]
    ms = [measured(suite, d) for d in ds]
    mo = [model(suite, d) for d in ds]
    data[lab] = (ms, mo)
    ax.plot(ds, [m[0] for m in mo], color=col, lw=1.2, ls="--", zorder=2)
    ax.plot(ds, ms, color=col, lw=0, marker="o", ms=6, zorder=3, label=f"{lab}, measured median")
    for d, v in zip(ds, ms):
        ax.text(d, v + (4.5 if lab == "ML-DSA-65" else -4.5), f"{v:.0f}", ha="center", va="bottom" if lab == "ML-DSA-65" else "top", fontsize=8.5, color=col, fontweight="bold")
ax.plot([], [], color=INK2, lw=1.2, ls="--", label="model")
ax.text(1.58, 112, "+56 ms", color=WARN, fontsize=10, fontweight="bold", ha="left")
ax.text(3.0, 128, "+3 ms, then +2 ms:\nthe waiting is already paid", color=INK2, fontsize=8.5, ha="center", va="center")
ms, mo = data["ML-DSA-65"]
ax.set_xticks([1, 2, 3, 4]); ax.set_xlim(0.6, 4.4); ax.set_ylim(70, 178)
ax.set_xticklabels([f"{d}\n{srv} + {cli}" for d, (_, srv, cli) in zip([1, 2, 3, 4], mo)])
for lab_, (d, (_, srv, cli)) in zip(ax.get_xticklabels(), zip([1, 2, 3, 4], mo)):
    if srv > W or cli > W: lab_.set_color(WARN); lab_.set_fontweight("bold")
ax.set_xlabel("chain depth (certificates sent by each side)\nbelow each depth: segments of the ML-DSA-65 server + client flight\n(red: above the window of 10 segments)", fontsize=8.5)
ax.set_ylabel("time of one call, first SYN to last byte (ms)", fontsize=9)
ax.grid(axis="y", color=GRID, linewidth=0.5)
ax.legend(loc="upper left", frameon=False, fontsize=8.5)
fig.savefig(os.path.join(HERE, "figures", "fig_cliff.pdf"), bbox_inches="tight"); plt.close(fig)
for lab in data:
    print(lab, [round(v, 1) for v in data[lab][0]], [(round(m[0], 1), m[1], m[2]) for m in data[lab][1]])
