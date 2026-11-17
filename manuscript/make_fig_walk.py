#!/usr/bin/env python3
"""figures/fig_walk.pdf: one VALIDATED configuration (ISO 8583-sized request and response of 302 and 222 bytes, mutual TLS, chain depth 3,
100 Mbit/s, RTT 30 ms, MTU 1500, Reno), flight by flight, ECDSA-P256 against ML-DSA-65. The flights are the model's (pqc_sim);
the measured totals are the medians of the 30 transactions of the core grid (Measurements/testbed/results/core_a.csv)."""
import csv, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "Simulation"))
import pqc_sim as S
sys.path.insert(0, HERE)
from icons import draw_icon
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#dcdbd6"
CLI, SRV = "#2a78d6", "#eb6834"
plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 9, "axes.edgecolor": INK2,
                     "text.color": INK, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False, "pdf.fonttype": 42})
RTT, BW, MTU = 30.0, 100.0, 1500
CORE = next(p for p in (os.path.join(HERE, up, "Measurements", "testbed", "results", "core_a.csv") for up in ("..", os.path.join("..", ".."))) if os.path.exists(p))   # repository layout of v6 or of the public copy
_rows = list(csv.DictReader(open(CORE, newline="")))


def measured(suite):
    v = [float(x["t_total_ms"]) for x in _rows if x["suite"] == suite and x["depth"] == "3" and x["net_id"] == "shaped"
         and x["rtt_ms"] == "30" and not x["err"]]
    return st.median(v), len(v)


def trace(suite):
    flow = S.build_flow(suite, "ISO_8583", 3, "cold", False)
    net = S.Net(BW, RTT, MTU, 0.0, 99)
    mss, hdr = net.mtu - net.hdr, net.hdr
    cw = [net.init_cwnd] * 2
    t, xi, rows = 0.0, -1, []
    for st in flow.steps:
        if st[0] == "cpu":
            t += st[1]
        elif st[0] == "hs":
            rows.append(("hs", t, t + RTT, 0, 0, 0)); t += RTT
        else:
            xi += 1
            side, nbytes = st[1], st[2]
            wr = flow.writes[xi] if flow.writes else ()
            sizes = tuple(S.segment_sizes(wr, mss, cw[side])) if wr else ()
            el, ser, n, _ = S._tcp_xfer(nbytes, mss, hdr, BW, RTT, cw[side], 1 << 30, False, sizes)
            rows.append(("x", t, t + el, side, n, cw[side], ser))
            cw[side] = S.grow_cwnd(cw[side], n)
            t += el
    return rows, t


fig, axs = plt.subplots(2, 1, figsize=(6.5, 3.5), sharex=True)
tmax = 0
totals = {}
for ax, (suite, lab) in zip(axs, (("ECDSA-P256|X25519", "ECDSA-P256"), ("ML-DSA-65|ML-KEM-768", "ML-DSA-65"))):
    rows, total = trace(suite)
    tmax = max(tmax, total)
    for r in rows:
        if r[0] == "hs":
            ax.barh(0, r[2] - r[1], left=r[1], height=0.5, color=GRID, edgecolor=SURFACE)
            ax.text((r[1] + r[2]) / 2, 0, "TCP", ha="center", va="center", fontsize=7.5, color=INK2)
            continue
        _, a, b, side, n, cwin, ser = r
        y = 0.55 if side == 0 else -0.55
        ax.barh(y, b - a, left=a, height=0.5, color=CLI if side == 0 else SRV, edgecolor=SURFACE)
        extra = n > cwin
        ax.text((a + b) / 2, y + (0.42 if side == 0 else -0.42), f"{n} seg" + (" > cwnd" if extra else ""),
                ha="center", va="bottom" if side == 0 else "top", fontsize=7.5, color="#b02a1a" if extra else INK2,
                fontweight="bold" if extra else "normal")
    xmax = tmax * 1.30
    for kind, col, yy in (("client", CLI, 0.78), ("server", SRV, -0.78)):      # icon at the start of the row of each endpoint
        cy = (yy + 1.35) / 2.7
        draw_icon(ax.inset_axes([0.022, cy - 0.095, 0.065, 0.19]), kind, col)
    totals[lab] = total
    mt, mn = measured(suite)
    ax.text(total + 2, 0, f"model {total:.0f} ms\nmeasured {mt:.0f} ms", va="center", fontsize=8.5, fontweight="bold")
    ax.set_yticks([0]); ax.set_yticklabels([lab], fontsize=9.5)
    ax.set_ylim(-1.35, 1.35)
    ax.grid(axis="x", color=GRID, linewidth=0.5)
axs[1].set_xlabel("time since the first SYN (ms)", fontsize=9)
axs[1].set_xlim(0, tmax * 1.30)
fig.legend(handles=[Patch(color=CLI, label="client flight"), Patch(color=SRV, label="server flight"),
                    Patch(color=GRID, label="TCP handshake")], loc="lower center", ncol=3, frameon=False, fontsize=8.5,
           bbox_to_anchor=(0.5, -0.11))
fig.savefig(os.path.join(HERE, "figures", "fig_walk.pdf"), bbox_inches="tight"); plt.close(fig)
for s in ("ECDSA-P256|X25519", "ML-DSA-65|ML-KEM-768"):
    r, t = trace(s); print(s, round(t, 1), [(x[3], x[4], x[5]) for x in r if x[0] == "x"])
