#!/usr/bin/env python3
"""figures/fig_ladder.pdf: why a flight above the congestion window costs one more round trip. The server's certificate flight of the
card-authorization example (chain depth 3, 100 Mbit/s, RTT 30 ms, MTU 1500, initial window 10), ECDSA-P256 (3 segments) against
ML-DSA-65 (16 segments). Segment times come from the ACK-clock recurrence of the paper (Eq. flight): r_k = 0 for k < c, a_floor((k-c)/2)
otherwise; the ten segments of the first burst leave 0.12 ms apart and are drawn as one band."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from icons import draw_icon
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Polygon, FancyBboxPatch, Rectangle, Circle

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#dcdbd6"
CLI, SRV, WARN = "#2a78d6", "#eb6834", "#b02a1a"
plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 9, "text.color": INK,
                     "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE, "pdf.fonttype": 42})
RTT, MSS_B, BW, C = 30.0, 1500, 100.0, 10
TAU = MSS_B * 8 / (BW * 1e3)          # ms per full segment


def flight(n, c=C):
    l, a = [], []
    prev = 0.0
    for k in range(n):
        r = 0.0 if k < c else a[(k - c) // 2]
        s = max(prev, r)
        prev = s + TAU
        l.append(prev); a.append(prev + RTT)
    return l, a


def icon(ax, xdata, kind, color):
    """small vector icon above a lifeline"""
    x0, x1 = ax.get_xlim()
    cx = (xdata - x0) / (x1 - x0)
    draw_icon(ax.inset_axes([cx - 0.085, 1.0, 0.17, 0.17]), kind, color)


def band(ax, t0, t1, color, lw=2.0, alpha=0.9):
    """a burst of segments, drawn as one arrow from the server (time t0..t1) to the client (half an RTT later)"""
    tc = (t0 + t1) / 2
    ax.annotate("", xy=(1, tc + RTT / 2), xytext=(0, tc),
                arrowprops=dict(arrowstyle="-|>,head_length=0.7,head_width=0.35", color=color, lw=lw, alpha=alpha, shrinkA=0, shrinkB=0,
                                mutation_scale=12), zorder=2)


def panel(ax, n, title):
    l, a = flight(n)
    ax.set_xlim(-0.45, 2.35); ax.set_ylim(RTT * 1.62, -4)
    for x, who, col in ((0, "server", SRV), (1, "client", CLI)):
        ax.plot([x, x], [0, RTT * 1.55], color=col, lw=1.4, zorder=1)
        ax.text(x, -2.2, who, ha="center", va="bottom", fontweight="bold", color=col)
        icon(ax, x, who, col)
    first = min(n, C)
    band(ax, 0, l[first - 1], SRV, lw=(5.5 if n > C else 1.6))
    R = 1.12                                   # all notes sit to the right of the client line, none crosses a drawn line
    ax.text(R, l[first - 1] / 2 + (3 if n > C else -1), f"{first} segment" + ("s" if first > 1 else ""), ha="left", va="center", fontsize=8.5, color=INK2)
    if n > C:
        ax.annotate("", xy=(0, a[0]), xytext=(1, a[0] - RTT / 2), arrowprops=dict(arrowstyle="-|>", color=INK2, lw=0.9, ls="--"))
        ax.text(R, RTT * 0.74, "ACKs return", ha="left", va="center", fontsize=8.5, color=INK2)
        rest = l[first:]
        band(ax, l[first] - TAU, rest[-1], SRV, lw=2.6)
        ax.text(R, (l[first] + rest[-1]) / 2 + 4, f"{n - first} more segments", ha="left", va="center", fontsize=8.5, color=INK2)
        ax.annotate("", xy=(-0.14, a[0] - 0.2), xytext=(-0.14, l[0]), arrowprops=dict(arrowstyle="<->", color=WARN, lw=1.2))
        ax.text(-0.26, (l[0] + a[0]) / 2, "waiting one RTT", rotation=90, ha="center", va="center", color=WARN, fontweight="bold", fontsize=8.5)
    else:
        ax.text(R, 31, "fits in the window:\nno waiting", ha="left", va="center", fontsize=8.5, color=INK2, style="italic")
    end = l[-1] + RTT / 2
    ax.plot([1.0, 1.08], [end, end], color=INK, lw=0.8)
    ax.text(R, end + (0 if n > C else 3), f"last segment arrives\nat {end:.0f} ms" if n > C else f"last segment arrives\nat {end:.0f} ms", ha="left", va="center", fontsize=8.5, fontweight="bold")
    ax.set_title(title, fontsize=10, pad=40, loc="left")
    ax.set_xticks([]); ax.set_yticks([0, 15, 30, 45]); ax.set_yticklabels(["0", "15", "30", "45"], color=INK2)
    for sp in ("top", "right", "bottom"): ax.spines[sp].set_visible(False)
    ax.spines["left"].set_color(INK2)
    ax.set_ylabel("time since the flight starts (ms)", fontsize=8.5, color=INK2)
    return end


fig, axs = plt.subplots(1, 2, figsize=(7.0, 3.9), sharey=True)
e1 = panel(axs[0], 3, "(a) ECDSA-P256: 3 segments")
e2 = panel(axs[1], 16, "(b) ML-DSA-65: 16 segments")
axs[1].set_ylabel("")
fig.subplots_adjust(wspace=0.12, bottom=0.04, top=0.88)
fig.savefig(os.path.join(HERE, "figures", "fig_ladder.pdf"), bbox_inches="tight"); plt.close(fig)
print("last segment arrives:", round(e1, 1), round(e2, 1))
