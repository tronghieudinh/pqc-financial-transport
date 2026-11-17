#!/usr/bin/env python3
"""analyze_ipv4_offload.py - scores the pre-registered criteria of results/ipv4_offload_predictions.md.
    python3 analyze_ipv4_offload.py --v6 ipv4flip_v6_M.csv --v4 ipv4flip_v4_M.csv [--offload offload_M.csv --standard results/replication/<run>/model_vs_testbed.csv]
Excess = median t_total of the shaped configuration - median t_total of the unshaped base of the same suite, depth, mTLS, request and response.
Experiment A (IPv4): F1 the 8 flip cells: excess(IPv4) - excess(IPv6) in [-35, -22] ms in >= 7 of 8; F2 the 6 controls: |IPv4 - IPv6| <= 3 ms in >= 5 of 6;
F3 stack model with header 40: MAE <= 2 ms over the 14 cells and 0 cells above 0.4 RTT (IPv6 with header 60 is shown for reference).
Experiment B (offload): OFF-1 median |excess(offload) - excess(standard run of the same machine)| <= 1 ms over the 24 cells; OFF-2 the unchanged model leaves 0 cells above 0.4 RTT."""
import argparse, csv, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
def rd(f): return list(csv.DictReader(l for l in open(f) if not l.startswith("#")))
def excess(f):
    c = {}
    for r in rd(f):
        if r["err"] == "": c.setdefault((r["suite"], r["depth"], r["mtls"], r["req"], r["resp"], r["net_id"]), []).append(float(r["t_total_ms"]))
    out = {}
    for k, v in c.items():
        if k[5] == "shaped" and k[:5] + ("base",) in c: out[k[:5]] = st.median(v) - st.median(c[k[:5] + ("base",)])
    return out
ap = argparse.ArgumentParser(); ap.add_argument("--v6"); ap.add_argument("--v4"); ap.add_argument("--offload"); ap.add_argument("--standard"); a = ap.parse_args()
P = {}
for r in rd(os.path.join(HERE, "results", "ipv4_offload_predictions.csv")): P[(r["experiment"], r["suite"], r["depth"], r["mtls"], r["req"], r["resp"])] = r
if a.v6 and a.v4:
    e6, e4 = excess(a.v6), excess(a.v4)
    keys = [k for k in e6 if k in e4 and ("ipv4_flip",) + k in P]
    flip = [k for k in keys if abs(float(P[("ipv4_flip",) + k]["d_ipv4_minus_ipv6"])) > 5]; ctrl = [k for k in keys if k not in flip]
    print(f"== Experiment A (IPv4 against IPv6), {len(keys)} cells: {len(flip)} flip, {len(ctrl)} controls")
    d = {k: e4[k] - e6[k] for k in keys}
    f1 = sum(-35 <= d[k] <= -22 for k in flip); f2 = sum(abs(d[k]) <= 3 for k in ctrl)
    print(f"  F1 flip cells with IPv4 - IPv6 in [-35, -22] ms: {f1} of {len(flip)} (need >= 7 of 8) -> {'MET' if f1 >= 7 else 'NOT MET'}")
    print(f"  F2 controls with |IPv4 - IPv6| <= 3 ms: {f2} of {len(ctrl)} (need >= 5 of 6) -> {'MET' if f2 >= 5 else 'NOT MET'}")
    for h, e, lab in ((40, e4, "IPv4, header 40"), (60, e6, "IPv6, header 60")):
        errs = [(float(P[("ipv4_flip",) + k]["model_hdr%d" % h]) - e[k], float(P[("ipv4_flip",) + k]["rtt_ms"])) for k in keys]
        mae = st.mean(abs(x) for x, _ in errs); big = sum(abs(x) > 0.4 * t for x, t in errs)
        print(f"  F3 stack model, {lab}: MAE {mae:.2f} ms, bias {st.mean(x for x, _ in errs):+.2f}, cells above 0.4 RTT {big}" + (f" -> {'MET' if mae <= 2 and big == 0 else 'NOT MET'}" if h == 40 else " (reference)"))
    print("  per cell (req resp suite depth | model v6 v4 | measured v6 v4 | measured diff | predicted diff):")
    for k in sorted(keys, key=lambda k: (k[0], int(k[3]), int(k[4]))):
        p = P[("ipv4_flip",) + k]; print(f"   {k[0][:6]:6s} d{k[1]} {k[3]:>5} {k[4]:>5} | {float(p['model_hdr60']):7.1f} {float(p['model_hdr40']):7.1f} | {e6[k]:7.1f} {e4[k]:7.1f} | {d[k]:+7.1f} | {float(p['d_ipv4_minus_ipv6']):+6.1f}")
if a.offload and a.standard:
    eo = excess(a.offload); std = {}
    for r in rd(a.standard):      # the standard run has many network settings: keep those of the offload cells (RTT 30 ms, 100 Mbit/s, MTU 1500, icw 10)
        if (float(r["rtt_ms"]), float(r["rate_mbps"]), int(r["mtu"]), int(r["icw"])) == (30.0, 100.0, 1500, 10): std[(r["suite"], r["depth"], r["mtls"], r["req"], r["resp"])] = float(r["excess_ms"])
    keys = [k for k in eo if k in std and ("offload",) + k in P]
    diff = [eo[k] - std[k] for k in keys]; m = st.median(abs(x) for x in diff)
    big = sum(abs(float(P[("offload",) + k]["model_hdr60"]) - eo[k]) > 0.4 * float(P[("offload",) + k]["rtt_ms"]) for k in keys)
    print(f"== Experiment B (offload on, IPv6), {len(keys)} cells against the standard run: median |difference| {m:.2f} ms (signed median {st.median(diff):+.2f}, max |d| {max(abs(x) for x in diff):.1f}) -> OFF-1 {'MET' if m <= 1 else 'NOT MET'}")
    errs = [float(P[("offload",) + k]["model_hdr60"]) - eo[k] for k in keys]
    print(f"   model against offload data: MAE {st.mean(abs(x) for x in errs):.2f} ms, bias {st.mean(errs):+.2f}, cells above 0.4 RTT {big} -> OFF-2 {'MET' if big == 0 else 'NOT MET'}")
