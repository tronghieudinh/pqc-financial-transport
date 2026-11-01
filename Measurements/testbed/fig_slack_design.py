#!/usr/bin/env python3
"""fig_slack_design.py - the three stages of WP5 as three separate figures (README, Paper 2 / supplement). Output: fig_slack_{A,B,C}.{pdf,png}"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

INK, GREY, LIGHT, ACC = "#1b1b1b", "#6b6b6b", "#ececec", "#b33a00"
BARE = os.environ.get("BARE") == "1"      # BARE=1: no title and no sub-line (the caption of the paper carries them); fig_slack_{A,B,C}_bare
MIN = os.environ.get("MIN") == "1"        # MIN=1: only the message sequence, no side panel (implies BARE); fig_slack_{A,B,C}_min
BARE = BARE or MIN
TOP = 24.4 if BARE else 30
XMAX = 54 if MIN else 100
FIGS = {k: plt.subplots(1, 1, figsize=(11 * XMAX / 100, 3.5 * TOP / 30)) for k in "ABC"}
for f, _ in FIGS.values():
    f.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
axs = [FIGS[k][1] for k in "ABC"]

def lane(ax, title, subtitle):
    ax.set_xlim(0, XMAX); ax.set_ylim(0, TOP); ax.axis("off")
    ax.add_patch(FancyBboxPatch((0.3, 0.3), XMAX - 0.6, TOP - 0.8, boxstyle="round,pad=0,rounding_size=1.2", fc="white", ec=GREY, lw=1))
    if not BARE:
        ax.text(1.5, 28.0, title, fontsize=12.5, fontweight="bold", color=INK, va="center")
        ax.text(1.5, 25.6, subtitle, fontsize=9, color=GREY, va="center")

def lifelines(ax, x_c=9, x_s=46, top=21.0, bot=2.5):
    for x, n in ((x_c, "client"), (x_s, "server")):
        ax.text(x, 22.0, n, ha="center", fontsize=9.5, color=INK)
        ax.plot([x, x], [bot, top], color=GREY, lw=1.2)
    return x_c, x_s

def arrow(ax, x0, y0, x1, y1, label, above=True, bold=False, dx=0):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0), arrowprops=dict(arrowstyle="-|>", color=INK, lw=1.8 if bold else 1.2))
    ax.text((x0 + x1) / 2 + dx, (y0 + y1) / 2 + (1.9 if above else -2.2), label, ha="center", va="center", fontsize=8.6, color=INK,
            bbox=dict(fc="white", ec="none", pad=1.2))

def mark(ax, x, y, text):
    ax.plot([x], [y], marker="o", ms=7, color=ACC)
    ax.text(x + 1.3, y, text, fontsize=8.6, color=ACC, va="center", fontweight="bold")

def side(ax, x, lines_measure, lines_compare, w=43.5):
    if MIN:
        return
    ax.add_patch(FancyBboxPatch((x, 2.0), w, 20.5, boxstyle="round,pad=0,rounding_size=0.8", fc=LIGHT, ec="none"))
    ax.text(x + 1.2, 20.3, "What is measured", fontsize=9, fontweight="bold", color=INK)
    for i, l in enumerate(lines_measure):
        ax.text(x + 1.2, 18.0 - 2.1 * i, l, fontsize=8.6, color=INK)
    y0 = 18.0 - 2.1 * len(lines_measure) - 1.0
    ax.text(x + 1.2, y0, "Compared with", fontsize=9, fontweight="bold", color=INK)
    for i, l in enumerate(lines_compare):
        ax.text(x + 1.2, y0 - 2.1 * (i + 1), l, fontsize=8.6, color=INK)

def flat(ax, xa, xb, y, label, bold=False, color=INK):
    """near-horizontal arrow from xa to xb (slight slope = time), label above it"""
    ax.annotate("", xy=(xb, y - 0.5), xytext=(xa, y + 0.5), arrowprops=dict(arrowstyle="-|>", color=color, lw=2.0 if bold else 1.2))
    ax.text((xa + xb) / 2, y + 1.6, label, ha="center", va="center", fontsize=8.6, color=INK, fontweight="bold" if bold else "normal")

# ---------------- A
ax = axs[0]; lane(ax, "A   Window rule (plain TCP, 13 configurations)", "tcp_flight; one factor changed at a time; 20 repetitions; ~25 min")
xc, xs = lifelines(ax)
flat(ax, xc, xs, 17.0, "burst 1:  n1 segments  (n1 = 1 … 16, 20, 24, 31, 40)", bold=True)
flat(ax, xs, xc, 11.5, "100-byte reply (acknowledges all of burst 1)")
mark(ax, xc, 7.0, "read TCP_INFO snd_cwnd")
side(ax, 56, ["the congestion window the kernel really has after n1 segments",
              "RTT 5/30/100 ms · 10/100/1000 Mbit/s · MTU 1280/1500/9000",
              "initcwnd 4/10/20 · delayed ACK · Cubic · timestamps · offload"],
     ["grow_cwnd(icw, n1, slack), slack = 0 … 4: share of exact matches",
      "optional: cwnd at every ACK (tcp_probe tracepoint, --trace)"])

# ---------------- B
ax = axs[1]; lane(ax, "B   Cost of a second flight (plain TCP, 6 configurations)", "tcp_flight --split; base, delayed ACK, offload, Cubic, initcwnd 4 and 20; 15 repetitions; ~1 h")
xc, xs = lifelines(ax)
flat(ax, xc, xs, 18.5, "burst 1:  n1 = 1 … 12 segments")
flat(ax, xs, xc, 14.0, "reply")
flat(ax, xc, xs, 9.8, "80 B (Finished), then  n2 − 1 segments;  n2 = 9 … 16", bold=True)
flat(ax, xs, xc, 4.6, "1 byte")
ax.annotate("", xy=(xc - 3, 10.4), xytext=(xc - 3, 3.9), arrowprops=dict(arrowstyle="<->", color=ACC, lw=1.4))
ax.text(xc - 4.4, 7.2, "t_b2", rotation=90, color=ACC, fontsize=9, va="center", fontweight="bold")
side(ax, 56, ["time t_b2: first write of the second flight to its reply",
              "(each extra round trip is a step of one RTT)"],
     ["model time with the window the kernel really had (stage A)",
      "model time with the window each slack = 0 … 4 predicts:",
      "which slack explains the extra round trips"])

# ---------------- C
ax = axs[2]; lane(ax, "C   Resumed TLS 1.3 (four suites), predictions fixed in advance", "run_testbed --resume; 222-byte response, so only the client's request flight can cost a round trip; n = 30; ~25 min")
xc, xs = lifelines(ax, top=21.0, bot=1.5)
flat(ax, xc, xs, 18.5, "ClientHello + ticket:  2 / 5 / 6 / 8 segments")
flat(ax, xs, xc, 14.0, "ServerHello … Finished (1 segment)")
flat(ax, xc, xs, 9.6, "Finished + request:  9 … 15 segments", bold=True)
flat(ax, xs, xc, 4.6, "response 222 B")
side(ax, 56, ["resumed latency: ECDSA-P256, ML-DSA-44/-65/-87,",
              "depth 2, RTT 100 ms, MTU 1500",
              "ClientHello length = the client's window at the request"],
     ["slack_predict.py, slack = 0 … 3: written and committed before the run",
      "28 cells; wrong = a whole round trip off (> 50 ms)"])

for k, (f, _) in FIGS.items():
    n = f"fig_slack_{k}" + ("_min" if MIN else "_bare" if BARE else "")
    f.savefig(n + ".pdf"); f.savefig(n + ".png", dpi=150)
