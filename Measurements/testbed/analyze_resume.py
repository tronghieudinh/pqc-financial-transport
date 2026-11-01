#!/usr/bin/env python3
"""
analyze_resume.py - TLS 1.3 session resumption on the testbed: measured against the stack model, and against the full handshake.

    python3 analyze_resume.py [results/resume.csv ...] [--out results/resume_summary.csv]

Input: runs of `run_testbed.py --resume` (see run_resume.sh). Every measured transaction is a RESUMED one on a new TCP connection;
`prime_ms` is the total time of the full transaction that obtained the ticket just before, under the same network conditions.

For every shaped configuration it reports (all excess latencies are shaped median minus the unshaped median of the same suite,
depth and kind, so that computation cancels as in paper 1):
  resumed_excess     measured excess latency of the resumed transaction
  resumed_model      stack model (mode "resumed")
  full_excess        measured excess latency of the full transaction (prime_ms)
  full_model         stack model (mode "cold")
  gain_measured / gain_model   full minus resumed
  size_ratio         bytes read and written by the client against the model (resumed flow, including the new ticket)
and prints the mean absolute errors and the gain per suite.
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", default=[os.path.join(HERE, "results", "resume.csv")])
    ap.add_argument("--out", default=os.path.join(HERE, "results", "resume_summary.csv"))
    ap.add_argument("--full-ref", default="core_a,segs,segs2,knee,grid_b",
                    help="earlier runs of FULL transactions without tickets (same suite, depth, RTT, rate, MTU, window): the reference for the gain; "
                         "prime_ms is a full transaction WITH a ticket, which the model has no mode for")
    ap.add_argument("--cwnd-slack", type=int, default=0, help="Net.cwnd_slack of the model (WP5 refuted slack > 0; kept for the record)")
    ap.add_argument("--nst-early", action="store_true", help="model the NewSessionTicket as its own earlier write (Net.nst_early, Paper 2)")
    a = ap.parse_args()
    A.SLACK = a.cwnd_slack
    A.NST_EARLY = a.nst_early
    rows = []
    for p in a.files:
        rows += [r for r in A.load(p, False) if r["resume"] == "1" and r["err"] == "" and A.f(r["t_total_ms"]) > 0 and r.get("reused") == "1"]
    if not rows:
        sys.exit("no successful resumed transactions in " + ", ".join(a.files))
    # medians of the full (priming) transaction per configuration
    prime = {}
    for r in rows:
        k = (r["suite"], r["depth"], r["mtls"], f"{A.f(r['rtt_ms']):g}", f"{A.f(r['rate_mbps']):g}", r["mtu"], r["icw"], r["net_id"])
        if A.f(r.get("prime_ms", "-1")) > 0:
            prime.setdefault(k, []).append(A.f(r["prime_ms"]))
    tab = [t for t in A.build_table(A.aggregate(rows), 500) if A.f(t["loss_pct"]) == 0]
    base_pr = {k[:3]: st.median(v) for k, v in prime.items() if k[7] == "base"}
    ref = {}
    ref_rows = []
    for n in a.full_ref.split(","):
        p = os.path.join(HERE, "results", n + ".csv")
        if os.path.exists(p):
            ref_rows += [r for r in A.load(p, False) if r["topology"] == "direct" and r["cc"] == "reno" and r["resume"] == "0"]
    for t in A.build_table(A.aggregate(ref_rows), 200):
        ref[(t["suite"], t["depth"], t["mtls"], t["req"], t["resp"], f"{A.f(t['rtt_ms']):g}", f"{A.f(t['rate_mbps']):g}", t["mtu"], t["icw"])] = t["excess_ms"]
    out = []
    for t in tab:
        k = (t["suite"], t["depth"], t["mtls"], f"{A.f(t['rtt_ms']):g}", f"{A.f(t['rate_mbps']):g}", t["mtu"], t["icw"], "shaped")
        if k not in prime or k[:3] not in base_pr:
            continue
        prime_excess = st.median(prime[k]) - base_pr[k[:3]]
        rk = (t["suite"], t["depth"], t["mtls"], t["req"], t["resp"], f"{A.f(t['rtt_ms']):g}", f"{A.f(t['rate_mbps']):g}", t["mtu"], t["icw"])
        full_excess = ref.get(rk, prime_excess)
        full_src = "ref" if rk in ref else "prime"
        flow_c, m_c = A.model_for(dict(t, resume="0"), cwnd_validation=True, segmentation="openssl")
        res_model = t["model_stack_ms"]
        full_model = m_c["total"] - m_c["cpu"]
        out.append(dict(suite=t["suite"], depth=t["depth"], mtls=t["mtls"], req=t["req"], resp=t["resp"], rtt_ms=t["rtt_ms"], rate_mbps=t["rate_mbps"], mtu=t["mtu"], icw=t["icw"],
                        resumed_excess=round(t["excess_ms"], 2), resumed_model=round(res_model, 2), full_excess=round(full_excess, 2), full_source=full_src, prime_excess=round(prime_excess, 2),
                        full_model=round(full_model, 2), gain_measured=round(full_excess - t["excess_ms"], 2),
                        gain_model=round(full_model - res_model, 2), size_ratio=t["size_ratio"]))
    if not out:
        sys.exit("no shaped configuration with a priming transaction and an unshaped base")
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    mae = lambda xs: st.mean(abs(x) for x in xs)
    e_r = [o["resumed_model"] - o["resumed_excess"] for o in out]
    e_f = [o["full_model"] - o["full_excess"] for o in out]
    e_g = [o["gain_model"] - o["gain_measured"] for o in out]
    print(f"{len(out)} shaped configurations ({sum(1 for _ in rows)} resumed transactions)")
    print(f"resumed:  MAE of the stack model {mae(e_r):.2f} ms (bias {st.mean(e_r):+.2f}, max {max(map(abs, e_r)):.1f})")
    print(f"full:     MAE of the stack model {mae(e_f):.2f} ms (bias {st.mean(e_f):+.2f}, max {max(map(abs, e_f)):.1f}); reference: "
          f"{sum(o['full_source'] == 'ref' for o in out)} configurations from earlier ticketless runs, {sum(o['full_source'] == 'prime' for o in out)} from the priming transactions (with ticket)")
    pe = [o["prime_excess"] - o["full_excess"] for o in out if o["full_source"] == "ref"]
    if pe:
        print(f"a full transaction WITH a ticket (prime) is slower than the ticketless one by a median of {st.median(pe):.1f} ms (mean {st.mean(pe):.1f}, max {max(pe):.1f})")
    print(f"gain:     MAE {mae(e_g):.2f} ms; measured gain median {st.median(o['gain_measured'] for o in out):.1f} ms, "
          f"model {st.median(o['gain_model'] for o in out):.1f} ms; size ratio median {st.median(o['size_ratio'] for o in out):.3f}")
    for sz in sorted({(o["req"], o["resp"]) for o in out}):
        g = [o for o in out if (o["req"], o["resp"]) == sz]
        print(f"request {sz[0]} B / response {sz[1]} B: {len(g)} configurations, resumed MAE {mae([o['resumed_model'] - o['resumed_excess'] for o in g]):.2f} ms, "
              f"gain MAE {mae([o['gain_model'] - o['gain_measured'] for o in g]):.2f} ms")
    for su in sorted({o["suite"] for o in out}):
        s = [o for o in out if o["suite"] == su]
        print(f"  {su:28s} n={len(s):3d} resumed excess {st.median(o['resumed_excess'] for o in s):7.1f}  full excess {st.median(o['full_excess'] for o in s):7.1f}  "
              f"gain {st.median(o['gain_measured'] for o in s):7.1f} (model {st.median(o['gain_model'] for o in s):7.1f})")


if __name__ == "__main__":
    main()
