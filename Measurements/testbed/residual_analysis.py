#!/usr/bin/env python3
"""
residual_analysis.py - how good is the stack model, and where? Error of the validated model by group of configurations.

    python3 residual_analysis.py [--latex ../../paper]

Reads the same raw runs as paper_assets.py (direct path, Reno, no loss) and writes
    <latex>/numbers_residuals.tex       \\newcommand values
    <latex>/tables/tab_residuals.tex    MAE, RMSE, normalised MAE (MAE / mean excess latency) and a bootstrap 95 % interval of the MAE per group
    <latex>/figures/fig_residuals.pdf   model minus measurement against the round-trip time, per suite
    results/residual_groups.csv         the same groups as data

Calibration and validation. The model has no parameter fitted to these measurements: the two stack behaviours (window validation,
write pattern) were identified on the "core" grid (rate 100 Mbit/s, initial window 10) and are structural; the middlebox penalty
is zero. The configurations that vary the rate, the MTU above 1500 or the initial window come from a later measurement campaign (see the supplementary table)
and are reported separately as "away from the calibration point".
"""
from __future__ import annotations

import argparse
import csv
import math
import os
import random
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze_testbed as A  # noqa: E402
import paper_assets as P  # noqa: E402

SHORT = {"ECDSA-P256|X25519": "ECDSA-P256", "RSA-2048|ECDHE-P256": "RSA-2048", "ML-DSA-44|ML-KEM-768": "ML-DSA-44", "ML-DSA-65|ML-KEM-768": "ML-DSA-65",
         "ML-DSA-87|ML-KEM-768": "ML-DSA-87", "ECDSA-P256|X25519MLKEM768": "ECDSA + hybrid KEM", "ML-DSA-87|ML-KEM-1024": "ML-DSA-87"}


def stats(err, exc, boot=2000):
    n = len(err)
    mae = st.mean(abs(e) for e in err)
    rng = random.Random(7)
    bs = sorted(st.mean(abs(e) for e in rng.choices(err, k=n)) for _ in range(boot))
    return dict(n=n, mae=mae, rmse=math.sqrt(st.mean(e * e for e in err)), nmae=mae / st.mean(exc), bias=st.mean(err),
                lo=bs[int(0.025 * boot)], hi=bs[int(0.975 * boot) - 1], mx=max(abs(e) for e in err))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--latex", default=os.path.join(HERE, "..", "..", "paper"))
    a = ap.parse_args()
    rows = [r for r in P.load(P.RAW["direct"]) if r["topology"] == "direct" and r["cc"] == "reno"]
    table = [t for t in A.build_table(A.aggregate(rows), 200) if A.f(t["loss_pct"]) == 0]
    for t in table:
        t["err"] = t["model_stack_ms"] - t["excess_ms"]
        t["away"] = A.f(t["rate_mbps"]) != 100 or int(t["mtu"]) == 9000 or int(t["icw"]) != 10
    groups = []

    def add(kind, label, sel):
        sub = [t for t in table if sel(t)]
        if len(sub) >= 3:
            groups.append(dict(kind=kind, label=label, **stats([t["err"] for t in sub], [t["excess_ms"] for t in sub])))
    add("all", "all configurations", lambda t: True)
    add("region", "core grid (100 Mbit/s, initial window 10)", lambda t: not t["away"])
    add("region", "away from the calibration point", lambda t: t["away"])
    for r in sorted({A.f(t["rtt_ms"]) for t in table}):
        add("RTT (ms)", f"{r:g}", lambda t, r=r: A.f(t["rtt_ms"]) == r)
    for m in sorted({int(t["mtu"]) for t in table}):
        add("MTU (B)", f"{m}", lambda t, m=m: int(t["mtu"]) == m)
    for w in sorted({int(t["icw"]) for t in table}):
        add("initial window", f"{w}", lambda t, w=w: int(t["icw"]) == w)
    for d in sorted({int(t["depth"]) for t in table}):
        add("chain depth", f"{d}", lambda t, d=d: int(t["depth"]) == d)
    for s in sorted({t["suite"] for t in table}):
        add("suite", SHORT.get(s, s), lambda t, s=s: t["suite"] == s)
    with open(os.path.join(HERE, "results", "residual_groups.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(groups[0].keys()))
        w.writeheader()
        for g in groups:
            w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in g.items()})

    # worst configurations
    worst = sorted(table, key=lambda t: -abs(t["err"]))[:5]
    with open(os.path.join(HERE, "results", "residual_worst.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["suite", "depth", "mtls", "req", "rtt_ms", "rate_mbps", "mtu", "icw", "excess_ms", "model_stack_ms", "err_ms"])
        for t in worst:
            w.writerow([t["suite"], t["depth"], t["mtls"], t["req"], t["rtt_ms"], t["rate_mbps"], t["mtu"], t["icw"], t["excess_ms"], t["model_stack_ms"], round(t["err"], 3)])

    # LaTeX
    allg = groups[0]
    nums = {"resRmse": f"{allg['rmse']:.2f}", "resNmae": f"{100 * allg['nmae']:.1f}", "resMaeLo": f"{allg['lo']:.2f}", "resMaeHi": f"{allg['hi']:.2f}"}
    byk = {(g["kind"], g["label"]): g for g in groups}
    core, away = byk[("region", "core grid (100 Mbit/s, initial window 10)")], byk[("region", "away from the calibration point")]
    nums.update(resCoreN=str(core["n"]), resCoreMae=f"{core['mae']:.2f}", resAwayN=str(away["n"]), resAwayMae=f"{away['mae']:.2f}")
    rtts = [g for g in groups if g["kind"] == "RTT (ms)"]
    nums["resNmaeRttLo"] = f"{100 * min(g['nmae'] for g in rtts):.1f}"
    nums["resNmaeRttHi"] = f"{100 * max(g['nmae'] for g in rtts):.1f}"
    nums["resMaeRttLo"] = f"{min(g['mae'] for g in rtts):.2f}"
    nums["resMaeRttHi"] = f"{max(g['mae'] for g in rtts):.2f}"
    wt = worst[0]
    nums.update(resWorstErr=f"{abs(wt['err']):.1f}", resWorstSuite=SHORT.get(wt["suite"], wt["suite"]), resWorstRtt=f"{A.f(wt['rtt_ms']):g}",
                resWorstDepth=str(int(wt["depth"])), resWorstMtu=str(int(wt["mtu"])), resWorstIcw=str(int(wt["icw"])))
    # fraction of configurations with |error| under 5 % of the excess latency
    nums["resUnderFive"] = str(sum(abs(t["err"]) <= 0.05 * t["excess_ms"] for t in table))
    P.write_numbers(os.path.join(a.latex, "numbers_residuals.tex"), nums, "residual_analysis.py")
    tex = ["\\begin{tabular}{@{}llrrrrr@{}}", "\\toprule",
           "Group & Value & $n$ & MAE (ms) & RMSE (ms) & MAE / mean excess (\\%) & MAE 95\\% interval (ms) \\\\", "\\midrule"]
    last = None
    for g in groups:
        if last is not None and g["kind"] != last:
            tex.append("\\midrule")
        last = g["kind"]
        kind = "" if g["kind"] in ("all", "region") else g["kind"]
        tex.append(f"{kind} & {g['label']} & {g['n']} & {g['mae']:.2f} & {g['rmse']:.2f} & {100 * g['nmae']:.1f} & {g['lo']:.2f}--{g['hi']:.2f} \\\\")
    tex += ["\\bottomrule", "\\end{tabular}"]
    os.makedirs(os.path.join(a.latex, "tables"), exist_ok=True)
    open(os.path.join(a.latex, "tables", "tab_residuals.tex"), "w").write("\n".join(tex) + "\n")

    # figure
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 2, figsize=(9, 3.4))
    suites = sorted({t["suite"] for t in table})
    mk = "os^Dvp"
    for i, s in enumerate(suites):
        x = [A.f(t["rtt_ms"]) * (1 + 0.04 * (i - 2.5)) for t in table if t["suite"] == s]
        y = [t["err"] for t in table if t["suite"] == s]
        ax[0].scatter(x, y, s=14, marker=mk[i % 6], label=SHORT.get(s, s), alpha=0.8)
    ax[0].axhline(0, color="k", lw=0.6)
    ax[0].set_xscale("log")
    ax[0].set_xticks([5, 30, 100])
    ax[0].set_xticklabels(["5", "30", "100"])
    ax[0].minorticks_off()
    ax[0].set_xlabel("round-trip time (ms)")
    ax[0].set_ylabel("model $-$ measurement (ms)")
    ax[1].scatter([t["excess_ms"] for t in table], [t["err"] for t in table], s=12, c=["tab:orange" if t["away"] else "tab:blue" for t in table], alpha=0.8)
    ax[1].axhline(0, color="k", lw=0.6)
    ax[1].set_xscale("log")
    ax[1].set_xticks([10, 30, 100, 300, 1000])
    ax[1].set_xticklabels(["10", "30", "100", "300", "1000"])
    ax[1].minorticks_off()
    ax[1].set_xlabel("measured excess latency (ms)")
    ax[1].set_ylabel("model $-$ measurement (ms)")
    ax[1].set_title("blue: core grid, orange: away from it", fontsize=7)
    ax[0].legend(fontsize=7, frameon=False, loc="upper left")
    fig.tight_layout()
    os.makedirs(os.path.join(a.latex, "figures"), exist_ok=True)
    fig.savefig(os.path.join(a.latex, "figures", "fig_residuals.pdf"))
    print(f"{len(table)} configurations; MAE {allg['mae']:.2f} ms [{allg['lo']:.2f}, {allg['hi']:.2f}], RMSE {allg['rmse']:.2f}, nMAE {100 * allg['nmae']:.1f} %")
    print(f"core {core['n']}: MAE {core['mae']:.2f}; away {away['n']}: MAE {away['mae']:.2f}")
    for g in groups:
        print(f"  {g['kind']:16s} {g['label']:38s} n={g['n']:3d} MAE={g['mae']:.2f} RMSE={g['rmse']:.2f} nMAE={100*g['nmae']:.1f}% bias={g['bias']:+.2f} max={g['mx']:.1f}")
    print("worst:", [(SHORT.get(t['suite'], t['suite']), t['depth'], t['rtt_ms'], t['mtu'], t['icw'], round(t['err'], 1)) for t in worst])


if __name__ == "__main__":
    main()
