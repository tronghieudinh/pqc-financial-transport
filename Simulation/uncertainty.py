#!/usr/bin/env python3
"""
uncertainty.py - propagation of PARAMETER uncertainty to the headline results.

The wired model is deterministic, so there is no Monte Carlo error; what is uncertain are the inputs that no
standard or measurement fixes. Each is drawn from the prior below (a documented assumption, not a fitted
posterior), the headline metrics are recomputed on a reference scenario, and we report medians, 90 % intervals,
the probability that a qualitative conclusion holds, and Spearman rank correlations of every input with each
metric.

  leaf_meta   U(600, 1400) B     ca_meta  U(350, 800) B  (drawn with a shared quantile, so they move together)
  cpu_scale   log-U(1, 16)       1 = measured Cortex-X925; 2 = A725 core, 4 = HSM-like, 16 = constrained device
  penalty     U(0, 24) ms        transport penalty pi (0 = no middlebox effect)
  threshold   U{2..16} segments  theta
  init_cwnd   {10: 0.6, 32: 0.3, 64: 0.1}   RFC 6928 default and larger production windows

Reference scenario: 100 Mbps, 30 ms RTT, MTU 1500, SWIFT_MX cold, chain depth 2 (4 for the per-certificate cost).

    python3 uncertainty.py [--n 4000] -> uncertainty_summary.csv, uncertainty_corr.csv
"""
import argparse
import csv
import os

import numpy as np

import pqc_sim as ps

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = ps.BASELINE
ML, FA, SF, SS = ("ML-DSA-65|ML-KEM-768", "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768",
                  "SLH-DSA-128s|ML-KEM-768")
PROTO = "SWIFT_MX"
INPUTS = ["leaf_meta", "cpu_scale", "penalty", "threshold", "init_cwnd"]


def draw(rng, n):
    q = rng.uniform(size=n)
    return dict(
        leaf_meta=600 + q * 800,
        ca_meta=350 + q * 450,
        cpu_scale=np.exp(rng.uniform(0, np.log(16), n)),
        penalty=rng.uniform(0, 24, n),
        threshold=rng.integers(2, 17, n),
        init_cwnd=rng.choice([10, 32, 64], n, p=[0.6, 0.3, 0.1]),
    )


def lat(su, d, p, i, cache):
    key = (su, d, int(p["leaf_meta"][i]), int(p["ca_meta"][i]))
    if key not in cache:
        m = ps.Model(leaf_meta=key[2], ca_meta=key[3])
        cache[key] = ps.build_flow(su, PROTO, d, "cold", False, m)
    net = ps.Net(100.0, 30.0, 1500, float(p["penalty"][i]), int(p["threshold"][i]),
                 int(p["init_cwnd"][i]), int(p["init_cwnd"][i]))
    return ps.run_flow(cache[key], net, float(p["cpu_scale"][i]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    p = draw(np.random.default_rng(a.seed), a.n)
    cache, out = {}, {k: np.empty(a.n) for k in
                      ["ml_ms", "ml_factor", "falcon_factor", "slhf_factor", "slhs_factor",
                       "ml_percert_ms", "ml_overhead_gt_cpu", "order_holds", "ml_pen_share"]}
    for i in range(a.n):
        b = lat(BASE, 2, p, i, cache)["total"]
        r = {s: lat(s, 2, p, i, cache) for s in (ML, FA, SF, SS)}
        out["ml_ms"][i] = r[ML]["total"]
        out["ml_factor"][i] = r[ML]["total"] / b
        out["falcon_factor"][i] = r[FA]["total"] / b
        out["slhf_factor"][i] = r[SF]["total"] / b
        out["slhs_factor"][i] = r[SS]["total"] / b
        out["ml_percert_ms"][i] = (lat(ML, 4, p, i, cache)["total"] - lat(ML, 1, p, i, cache)["total"]) / 3
        o = r[ML]["ser"] + r[ML]["ssw"] + r[ML]["pen"]
        out["ml_overhead_gt_cpu"][i] = float(o > r[ML]["cpu"])
        out["order_holds"][i] = float(r[FA]["total"] < r[ML]["total"] < r[SF]["total"])
        out["ml_pen_share"][i] = r[ML]["pen"] / r[ML]["total"]
    rows = [["metric", "median", "p5", "p95", "mean"]]
    for k, v in out.items():
        rows.append([k] + [round(float(x), 3) for x in (np.median(v), *np.percentile(v, [5, 95]), v.mean())])
    with open(os.path.join(HERE, "uncertainty_summary.csv"), "w", newline="") as fh:
        csv.writer(fh).writerows(rows)

    def rank(x):
        return np.argsort(np.argsort(x)).astype(float)
    cr = [["metric"] + INPUTS]
    for k in ["ml_ms", "ml_factor", "falcon_factor", "ml_percert_ms"]:
        cr.append([k] + [round(float(np.corrcoef(rank(p[x]), rank(out[k]))[0, 1]), 3) for x in INPUTS])
    with open(os.path.join(HERE, "uncertainty_corr.csv"), "w", newline="") as fh:
        csv.writer(fh).writerows(cr)
    names = {"ml_ms": "ML-DSA-65 latency (ms)", "ml_factor": "ML-DSA-65 factor over baseline",
             "falcon_factor": "Falcon-512 factor", "slhf_factor": "SLH-DSA-128f factor",
             "slhs_factor": "SLH-DSA-128s factor", "ml_percert_ms": "ML-DSA-65 cost per extra certificate (ms)",
             "ml_overhead_gt_cpu": "P(overhead $>$ crypto time)", "order_holds": "P(Falcon $<$ ML-DSA $<$ SLH-f)"}
    tex = ["\\begin{tabular}{@{}lrrr@{}}\\toprule", "Metric & Median & 5th pct & 95th pct \\\\\\midrule"]
    for r in rows[1:]:
        if r[0] in ("ml_overhead_gt_cpu", "order_holds"):
            tex.append(f"{names[r[0]]} & {r[4]:.2f} & \\multicolumn{{2}}{{c}}{{--}} \\\\")
        elif r[0] in names:
            tex.append(f"{names[r[0]]} & {r[1]:.2f} & {r[2]:.2f} & {r[3]:.2f} \\\\" if r[1] < 10 else
                       f"{names[r[0]]} & {r[1]:.1f} & {r[2]:.1f} & {r[3]:.1f} \\\\")
    tex.append("\\bottomrule\\end{tabular}")
    tdir = os.path.join(HERE, "..", "paper", "tables")
    if os.path.isdir(tdir):
        open(os.path.join(tdir, "tab_uncertainty.tex"), "w").write("\n".join(tex) + "\n")
    # numbers quoted in the text of paper 1 (\\input as numbers_uncertainty.tex)
    q = lambda v, lo=5, hi=95: (float(np.median(v)), *[float(x) for x in np.percentile(v, [lo, hi])])
    nums = {}
    for tag, key in (("MlFactor", "ml_factor"), ("FalFactor", "falcon_factor"), ("MlPerCert", "ml_percert_ms")):
        m_, lo_, hi_ = q(out[key])
        nums[f"u{tag}Med"], nums[f"u{tag}Lo"], nums[f"u{tag}Hi"] = (f"{m_:.2f}" if key != "ml_percert_ms" else f"{m_:.1f}",
                                                                 f"{lo_:.2f}" if key != "ml_percert_ms" else f"{lo_:.1f}",
                                                                 f"{hi_:.2f}" if key != "ml_percert_ms" else f"{hi_:.1f}")
    nums["uOverheadShare"] = f"{100 * out['ml_overhead_gt_cpu'].mean():.0f}"
    cs = p["cpu_scale"]
    nums["uOverheadLowCpu"] = f"{100 * out['ml_overhead_gt_cpu'][cs < 4].mean():.0f}"
    nums["uOverheadHighCpu"] = f"{100 * out['ml_overhead_gt_cpu'][(cs >= 12) & (cs <= 16)].mean():.0f}"
    nums["uOrderHolds"] = f"{100 * out['order_holds'].mean():.0f}"
    rho = dict(zip(cr[0][1:], cr[[r[0] for r in cr].index('ml_factor')][1:]))
    rho2 = dict(zip(cr[0][1:], cr[[r[0] for r in cr].index('ml_percert_ms')][1:]))
    nums["uRhoCwndFactor"], nums["uRhoCwndPerCert"] = f"{rho['init_cwnd']:.2f}", f"{rho2['init_cwnd']:.2f}"
    nums["uRhoCpuFactor"], nums["uRhoPenFactor"] = f"{rho['cpu_scale']:.2f}", f"{rho['penalty']:.2f}"
    for w, name in ((10, "Ten"), (32, "ThirtyTwo"), (64, "SixtyFour")):
        sel = p["init_cwnd"] == w
        m_, lo_, hi_ = q(out["ml_percert_ms"][sel])
        nums[f"uPerCertW{name}Med"], nums[f"uPerCertW{name}Lo"], nums[f"uPerCertW{name}Hi"] = f"{m_:.1f}", f"{lo_:.1f}", f"{hi_:.1f}"
    ndir = os.path.join(HERE, "..", "paper")
    if os.path.isdir(ndir):
        with open(os.path.join(ndir, "numbers_uncertainty.tex"), "w") as fh:
            fh.write("% Generated by Simulation/uncertainty.py - do not edit\n")
            for k, v in nums.items():
                fh.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    for r in rows + cr:
        print(*r, sep="\t")


if __name__ == "__main__":
    main()
