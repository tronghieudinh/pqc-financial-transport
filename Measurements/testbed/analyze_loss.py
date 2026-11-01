#!/usr/bin/env python3
"""
analyze_loss.py - packet loss on the testbed against the lossy stack model (paper 2, WP4).

    python3 analyze_loss.py results/loss.csv [--trials 3000] [--out results/loss_summary.csv]

Input: runs of `run_testbed.py --profile loss` (see run_loss.sh): n transactions per configuration under netem loss of 0, 0.1, 0.5, 1 and 2 %
and an unshaped base per suite and depth. The model is Simulation/loss_sim.py (validated stack, fast retransmit, tail-loss probe, RTO,
1-s SYN timeout), run `--trials` times per configuration with the probe's message sizes.

Measured times are shifted by the median of the unshaped base transactions (this removes computation and local overhead, as in paper 1);
modelled times are the transport time (total minus the computation steps). For every configuration it reports mean, median, 95th and
99th percentile of both, and the mean number of retransmissions per transaction (TCP_INFO `retrans`) against the model's.
The tails are where this model is weakest (timer values of the real stack, SYN retransmission, delayed ACKs): read them as a check, not a fit.
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "Simulation"))
import analyze_testbed as A  # noqa: E402
import loss_sim as L  # noqa: E402
import pqc_sim as S  # noqa: E402


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--trials", type=int, default=3000)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    rows = [r for r in A.load(a.csv, False) if r["topology"] == "direct" and r["resume"] == "0"]
    agg = A.aggregate(rows)
    base = {(c["suite"], c["depth"], c["mtls"]): c["med"] for c in agg.values() if c["net_id"] == "base"}
    out = []
    for c in sorted(agg.values(), key=lambda c: (c["suite"], int(c["depth"]), A.f(c["loss_pct"]))):
        if c["net_id"] != "shaped":
            continue
        k = (c["suite"], c["depth"], c["mtls"])
        if k not in base:
            continue
        flow, _ = A.model_for(c)                                  # cold flow with the probe's message sizes
        cpu = sum(s[1] for s in flow.steps if s[0] == "cpu")
        net = S.Net(A.f(c["rate_mbps"]), A.f(c["rtt_ms"]), int(c["mtu"]), 0.0, 4, init_cwnd=int(c["icw"]))
        p = A.f(c["loss_pct"]) / 100.0
        sims = [L.run_flow_lossy(flow, net, p, f"an|{c['suite']}|{c['depth']}|{p}|{t}") for t in range(a.trials)]
        mod = [s["total"] - cpu for s in sims]
        mea = [t - base[k] for t in c["times"]]
        out.append(dict(suite=c["suite"], depth=c["depth"], rtt_ms=c["rtt_ms"], loss_pct=c["loss_pct"], n=c["n"],
                        meas_mean=round(st.mean(mea), 2), model_mean=round(st.mean(mod), 2),
                        meas_p50=round(q(mea, .5), 2), model_p50=round(q(mod, .5), 2),
                        meas_p95=round(q(mea, .95), 2), model_p95=round(q(mod, .95), 2),
                        meas_p99=round(q(mea, .99), 2), model_p99=round(q(mod, .99), 2),
                        meas_retx=round(c["retrans"], 3), model_retx=round(st.mean(s["retx"] for s in sims), 3)))
    if not out:
        sys.exit("no shaped configuration with an unshaped base in " + a.csv)
    dst = a.out or os.path.join(os.path.dirname(a.csv), "loss_summary.csv")
    with open(dst, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"{len(out)} configurations -> {dst}")
    print(f"{"suite":24s} d  rtt   loss%  n   mean meas/model   p50 meas/model   p95 meas/model   p99 meas/model   retx meas/model")
    for o in out:
        print(f"{o['suite'][:24]:24s} {o['depth']} {A.f(o['rtt_ms']):4g}ms {A.f(o['loss_pct']):4g} {o['n']:4d}  {o['meas_mean']:7.1f}/{o['model_mean']:7.1f}  {o['meas_p50']:7.1f}/{o['model_p50']:7.1f}  "
              f"{o['meas_p95']:7.1f}/{o['model_p95']:7.1f}  {o['meas_p99']:7.1f}/{o['model_p99']:7.1f}  {o['meas_retx']:6.3f}/{o['model_retx']:6.3f}")
    e = [abs(o["meas_mean"] - o["model_mean"]) for o in out]
    print(f"mean absolute error of the mean: {st.mean(e):.1f} ms; at loss 0: {st.mean([abs(o['meas_mean'] - o['model_mean']) for o in out if A.f(o['loss_pct']) == 0] or [float('nan')]):.1f} ms")


if __name__ == "__main__":
    main()
