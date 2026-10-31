#!/usr/bin/env python3
"""
analyze_variants.py - does the stack model survive other TCP settings? CUBIC, delayed ACKs, TCP timestamps, BBR.

    python3 analyze_variants.py [--latex ../../paper]

Reads results/{cubic,cubic2,delack,ts,delack_ts,bbr}.csv (those that exist; written by run_variants.sh) and, for each variant,
compares the measured excess latency with the stack model (and with the idealised closed form), and with the Reno / quick-ACK /
no-timestamps measurements of the same configurations (core_a, segs, segs2, knee, grid_b), pairing identical configurations.
With timestamps on, every segment carries 12 option bytes, so the model is run with MTU - 12 (MSS = MTU - 72).

Writes results/variants_summary.csv, <latex>/numbers_variants.tex and <latex>/tables/tab_variants.tex.
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze_testbed as A  # noqa: E402
import paper_assets as P  # noqa: E402

BASELINE = ["core_a", "segs", "segs2", "knee", "grid_b"]
VARIANTS = [("Cubic", "CUBIC, quick ACK", ["cubic", "cubic2"], 0), ("Delack", "Reno, delayed ACK", ["delack"], 0),
            ("Ts", "Reno, quick ACK, timestamps", ["ts"], 12), ("DelackTs", "Reno, delayed ACK, timestamps", ["delack_ts"], 12),
            ("Bbr", "BBR, quick ACK (exploratory)", ["bbr"], 0)]


def table_for(names, ts_shift):
    rows = [r for r in P.load(names) if r["topology"] == "direct"]
    for r in rows:
        r["mtu_orig"] = r["mtu"]
        if str(r.get("tcp_ts", "")) == "1" and ts_shift:
            r["mtu"] = str(int(r["mtu"]) - 12)
    t = [x for x in A.build_table(A.aggregate(rows), 200) if A.f(x["loss_pct"]) == 0]
    return t


def key(t, shift=0):
    """Identity of a configuration; shift = 12 for runs with timestamps, whose table carries MTU - 12."""
    return (t["suite"], int(t["depth"]), t["mtls"], int(t["req"]), A.f(t["rtt_ms"]), A.f(t["rate_mbps"]), int(t["mtu"]) + shift, int(t["icw"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--latex", default=os.path.join(HERE, "..", "..", "paper"))
    a = ap.parse_args()
    base = {key(t): t for t in table_for(BASELINE, False) if t["cc"] == "reno"}
    nums, summary, tex = {}, [], []
    for tag, label, names, shift in VARIANTS:
        if not any(os.path.exists(os.path.join(HERE, "results", n + ".csv")) for n in names):
            continue
        t = table_for(names, True)
        if not t:
            continue
        es = [x["model_stack_ms"] - x["excess_ms"] for x in t]
        ei = [x["model_ms"] - x["excess_ms"] for x in t]
        pairs = [(x, base[key(x, shift)]) for x in t if key(x, shift) in base]
        d = [x["excess_ms"] - b["excess_ms"] for x, b in pairs]
        row = dict(tag=tag, variant=label, n=len(t), mae_stack=st.mean(map(abs, es)), mae_ideal=st.mean(map(abs, ei)), bias_stack=st.mean(es),
                   max_stack=max(map(abs, es)), within1=sum(abs(e) <= 1 for e in es),
                   off_stack=sum(abs(e) > 0.4 * A.f(x["rtt_ms"]) for e, x in zip(es, t)),
                   off_ideal=sum(abs(e) > 0.4 * A.f(x["rtt_ms"]) for e, x in zip(ei, t)),
                   pairs=len(pairs), d_median=st.median(d) if d else float("nan"), d_mae=st.mean(map(abs, d)) if d else float("nan"),
                   d_max=max(map(abs, d)) if d else float("nan"))
        summary.append(row)
        for k, v in (("N", row["n"]), ("Mae", f"{row['mae_stack']:.2f}"), ("MaeIdeal", f"{row['mae_ideal']:.2f}"), ("Bias", f"{row['bias_stack']:+.2f}"),
                     ("Max", f"{row['max_stack']:.1f}"), ("OffStack", row["off_stack"]), ("OffIdeal", row["off_ideal"]), ("Pairs", row["pairs"]),
                     ("PairMed", f"{row['d_median']:+.2f}" if d else "n/a"), ("PairMae", f"{row['d_mae']:.2f}" if d else "n/a"),
                     ("PairMax", f"{row['d_max']:.1f}" if d else "n/a")):
            nums[f"var{tag}{k}"] = str(v)
        tex.append(f"{label} & {row['n']} & {row['mae_stack']:.2f} & {row['mae_ideal']:.2f} & {row['bias_stack']:+.2f} & {row['max_stack']:.1f} & "
                   f"{row['off_stack']} / {row['off_ideal']} & {row['pairs']} & " + (f"{row['d_median']:+.2f} & {row['d_max']:.1f}" if d else "-- & --") + " \\\\")
    if not summary:
        sys.exit("no variant measurements in results/ (run run_variants.sh first)")
    with open(os.path.join(HERE, "results", "variants_summary.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0].keys()))
        w.writeheader()
        for r in summary:
            w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in r.items()})
    reno = [r for r in summary if r["tag"] != "Bbr" and r["pairs"]]
    if reno:
        nums["varPairMedMax"] = f"{max(abs(r['d_median']) for r in reno):.1f}"
        nums["varPairMaxAll"] = f"{max(r['d_max'] for r in reno):.1f}"
        nums["varMaeMax"] = f"{max(r['mae_stack'] for r in reno):.2f}"
        nums["varMaxLo"] = f"{min(r['max_stack'] for r in reno):.1f}"
        nums["varMaxHi"] = f"{max(r['max_stack'] for r in reno):.1f}"
    P.write_numbers(os.path.join(a.latex, "numbers_variants.tex"), nums, "analyze_variants.py")
    head = ["\\begin{tabular}{@{}lrrrrrrrrr@{}}", "\\toprule",
            "Variant & $n$ & MAE (ms) & ideal MAE (ms) & bias (ms) & max (ms) & off $>0.4$ RTT (stack / ideal) & pairs & median $\\Delta$ (ms) & max $|\\Delta|$ (ms) \\\\",
            "\\midrule"]
    os.makedirs(os.path.join(a.latex, "tables"), exist_ok=True)
    open(os.path.join(a.latex, "tables", "tab_variants.tex"), "w").write("\n".join(head + tex + ["\\bottomrule", "\\end{tabular}"]) + "\n")
    for r in summary:
        print({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()})


if __name__ == "__main__":
    main()
