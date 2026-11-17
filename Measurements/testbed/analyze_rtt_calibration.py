#!/usr/bin/env python3
"""analyze_rtt_calibration.py - does the RTT that the testbed really delivers explain the systematic residual of the stack model?
    python3 analyze_rtt_calibration.py results/replication/<run>/model_vs_testbed.csv --over 5:0.25,30:0.325        # offsets in ms per nominal RTT (flat above the largest key)
    python3 analyze_rtt_calibration.py FILE.csv --cal results/netem_cal_<host>_<kernel>_<date>.json               # offsets from netem_calibrate.py (over_ms per nominal RTT)
Prints the stack-model MAE and bias (model minus measurement) with the nominal RTT and with RTT + offset (the model is run with the corrected RTT; the measured excess is unchanged).
A first trial on 2026-11-15 used the median of the kernel's smoothed RTT (TCP_INFO) as the offset: it halved the Arm error (2.35 -> 1.18 ms) and over-corrected the x86 runs, so the offset
must come from a measurement that does not include serialisation and processing: netem_calibrate.py (ICMP through the same veth pair)."""
import argparse, csv, json, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import analyze_testbed as A
S = A.S
ap = argparse.ArgumentParser(); ap.add_argument("csv", nargs="+"); ap.add_argument("--over", default=""); ap.add_argument("--cal", default="")
a = ap.parse_args()
over = {}
if a.cal:
    for k, v in json.load(open(a.cal))["cells"].items(): over[float(k)] = v["over_ms"]
for kv in filter(None, a.over.split(",")): k, v = kv.split(":"); over[float(k)] = float(v)
if not over: sys.exit("give --over or --cal")
def off(r):
    ks = sorted(over); t = float(r["rtt_ms"])
    return over[max(k for k in ks if k <= t)] if t >= ks[0] else over[ks[0]]
def predict(c, delta):
    flow = S.build_flow(c["suite"], A.probe_protocol(c["mtls"], c["req"], c["resp"], c["depth"]), int(c["depth"]), "cold", False)
    net = S.Net(float(c["rate_mbps"]), float(c["rtt_ms"]) + delta, int(c["mtu"]), penalty_ms=0.0, thr=4, init_cwnd=int(c["icw"]), cwnd_validation=True, segmentation="openssl", cwnd_slack=0)
    r = S.run_flow(flow, net); return r["total"] - r["cpu"]
for f in a.csv:
    rows = [r for r in csv.DictReader(open(f))]
    for label, d in (("nominal RTT", False), ("RTT + offset", True)):
        e = [predict(r, off(r) if d else 0.0) - float(r["excess_ms"]) for r in rows]
        print(f"{os.path.basename(os.path.dirname(os.path.abspath(f)))[:40]:40s} {label:13s} MAE {st.mean(abs(x) for x in e):5.2f} ms  bias {st.mean(e):+5.2f} ms  ({len(e)} configurations)")
