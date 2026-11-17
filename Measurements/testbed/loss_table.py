#!/usr/bin/env python3
"""loss_table.py - the packet-loss table of Supplementary Appendix SH, from results/wp6_loss_full_summary.csv
(written by analyze_loss.py from results/wp6_loss_full.csv).

    python3 loss_table.py [--latex ../../paper1/Latex]

Writes <latex>/tables/tab_loss.tex (its content is pasted into supplementary.tex, Appendix SH, so that the Overleaf project needs no new file) and prints the numbers quoted in the appendix."""
import argparse, csv, os, statistics as st

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("--latex", default=os.path.join(HERE, "..", "..", "paper1", "Latex")); a = ap.parse_args()
rows = list(csv.DictReader(open(os.path.join(HERE, "results", "wp6_loss_full_summary.csv"))))
for r in rows:
    for k in r:
        if k not in ("suite",): r[k] = float(r[k])
SH = {"ECDSA-P256|X25519": "ECDSA-P256", "ML-DSA-65|ML-KEM-768": "ML-DSA-65"}
rows.sort(key=lambda r: (r["suite"] != "ECDSA-P256|X25519", r["rtt_ms"], r["loss_pct"]))
def f(x, d=0): return f"{x:.{d}f}"
out = [r"\begin{tabular}{@{}lrrrrrrrr@{}}", r"\toprule",
       r"Suite & RTT & Loss & Mean, measured (95\% interval) & Mean, model & p50 & p95 & p99 & Client retransmissions \\",
       r" & (ms) & (\%) & (ms) & (ms) & \multicolumn{3}{c}{measured / model (ms)} & measured / model \\", r"\midrule"]
prev = None
for r in rows:
    if prev is not None and (r["suite"], r["rtt_ms"]) != prev: out.append(r"\midrule")
    prev = (r["suite"], r["rtt_ms"])
    out.append(f'{SH[r["suite"]]} & {f(r["rtt_ms"])} & {r["loss_pct"]:g} & {f(r["meas_mean"],1)} ({f(r["mean_lo"],1)}--{f(r["mean_hi"],1)}) & {f(r["model_mean"],1)} & '
               f'{f(r["meas_p50"])} / {f(r["model_p50"])} & {f(r["meas_p95"])} / {f(r["model_p95"])} & {f(r["meas_p99"])} / {f(r["model_p99"])} & {r["meas_retx"]:.2f} / {r["model_retx"]:.2f} \\\\')
out += [r"\bottomrule", r"\end{tabular}"]
os.makedirs(os.path.join(a.latex, "tables"), exist_ok=True)
open(os.path.join(a.latex, "tables", "tab_loss.tex"), "w").write("\n".join(out) + "\n")
nz = [r for r in rows if r["loss_pct"] > 0]; z = [r for r in rows if r["loss_pct"] == 0]
mae = lambda s, k="mean": st.mean(abs(r["meas_" + k] - r["model_" + k]) for r in s)
print("n transactions", int(sum(r["n"] for r in rows)))
print("MAE mean: loss 0 %.2f; loss>0 %.2f; by loss" % (mae(z), mae(nz)), {l: round(mae([r for r in nz if r["loss_pct"] == l]), 1) for l in (0.5, 1.0, 2.0)})
print("model mean inside interval: %d of %d (loss>0); loss 0: %d of %d" % (sum(r["mean_in_ci"] for r in nz), len(nz), sum(r["mean_in_ci"] for r in z), len(z)))
print("max |p50 diff| %.1f ms" % max(abs(r["meas_p50"] - r["model_p50"]) for r in rows))
print("p95 MAE (loss>0) %.1f ms; p99 MAE %.1f ms" % (mae(nz, "p95"), mae(nz, "p99")))
ratios = [r["meas_p99"] / r["model_p99"] for r in nz]; print("p99 measured/model min %.2f max %.2f; within 20%%: %d of %d" % (min(ratios), max(ratios), sum(abs(x - 1) <= .2 for x in ratios), len(ratios)))
print("interval half-width mean (loss>0) %.1f ms" % st.mean((r["mean_hi"] - r["mean_lo"]) / 2 for r in nz))
print("client retransmissions measured %.3f model %.3f (mean over loss>0)" % (st.mean(r["meas_retx"] for r in nz), st.mean(r["model_retx"] for r in nz)))
