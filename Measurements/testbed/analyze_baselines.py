#!/usr/bin/env python3
"""analyze_baselines.py - two simpler baselines against the stack model on the 226 configurations of Paper 1 (paper1/Latex_v8/data/testbed_configurations.csv).
    python3 analyze_baselines.py [FILE ...]     # FILE: results/replication/<run>/model_vs_testbed.csv of a replication run (default: the original validation)
Models (excess latency = model total - model CPU time, compared with the measured excess):
  stack       Linux window validation + OpenSSL write pattern (the paper's model)
  idealized   ceil(bytes/MSS) segments, window += segments of every flight (the paper's baseline)
  stateless   textbook slow start per flight: every flight starts at the initial window, nothing is carried between flights (Net.carry = False)
  threshold   size-versus-window rule of the size analyses: a flight takes serialisation + RTT/2, plus one RTT iff its segments exceed the initial window (Net.thresh_rule = True)
The two baselines were defined after the data were collected, on the same configurations; they are comparisons, not pre-registered predictions.
Prints MAE, the number of configurations off by more than 0.4 RTT and the largest error."""
import csv, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import analyze_testbed as A
S = A.S
DEF = next((f for f in (os.path.join(HERE, "..", "..", *d, "testbed_configurations.csv") for d in (("paper1", "Latex_v8", "data"), ("paper1", "Latex", "data"), ("manuscript", "data"))) if os.path.exists(f)), "")   # private repository or public release layout
def predict(c, kind):
    flow = S.build_flow(c["suite"], A.probe_protocol(c["mtls"], c["req"], c["resp"], c["depth"]), int(c["depth"]), "resumed" if c.get("resume") == "1" else "cold", False)
    kw = dict(stack=dict(cwnd_validation=True, segmentation="openssl"), idealized=dict(cwnd_validation=False, segmentation="ideal"),
              stateless=dict(cwnd_validation=False, segmentation="ideal", carry=False), threshold=dict(cwnd_validation=False, segmentation="ideal", thresh_rule=True))[kind]
    net = S.Net(float(c["rate_mbps"]), float(c["rtt_ms"]), int(c["mtu"]), penalty_ms=0.0, thr=4, init_cwnd=int(c["icw"]), cwnd_slack=0, **kw)
    r = S.run_flow(flow, net); return r["total"] - r["cpu"]
def report(label, rows):
    print(f"{label}: {len(rows)} configurations")
    for kind in ("stack", "idealized", "stateless", "threshold"):
        e = [(predict(r, kind) - float(r["excess_ms"]), float(r["rtt_ms"])) for r in rows]
        print(f"  {kind:10s} MAE {st.mean(abs(x) for x, _ in e):5.2f} ms   off by more than 0.4 RTT: {sum(abs(x) > 0.4 * t for x, t in e):3d}   max |error| {max(abs(x) for x, _ in e):6.1f} ms")
def main():
    if len(sys.argv) > 1:
        for f in sys.argv[1:]:
            report(os.path.basename(os.path.dirname(os.path.abspath(f))), [r for r in csv.DictReader(open(f))])
    else:
        report("original validation", [r for r in csv.DictReader(open(DEF)) if r["net_id"] == "shaped"])
if __name__ == "__main__":
    main()
