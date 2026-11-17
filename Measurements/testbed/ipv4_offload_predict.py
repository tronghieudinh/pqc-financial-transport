#!/usr/bin/env python3
"""ipv4_offload_predict.py - writes the predictions of the stack model for the IPv4 / offload experiment of Paper 1 (results/ipv4_offload_predictions.csv).
Run it and COMMIT AND PUSH the result BEFORE the measurement. Two experiments:
  ipv4_flip  results/ipv4_flip_configs.csv: 14 configurations chosen so that the 20 bytes smaller header of IPv4 (MSS 1460 instead of 1440 at MTU 1500) moves a flight across the
             10-segment window (found by scanning request and response sizes): ECDSA-P256 depth 2 with response 14 400 / 14 500 B or request 11 500 / 11 600 B, ML-DSA-65 depth 1
             with response 23 000 to 23 300 B, and controls on both sides of each window. The model predicts one round trip less with IPv4 in the 8 flip cells and no change in the 6 controls.
  offload    results/offload_configs.csv: the 24 configurations of the production-like run, with Reno (as the standard run); offload on does not change the model (it has no offload term); the prediction is the model
             of the standard run (IPv6, header 60).
Columns: model excess (T - T_cpu, ms) with header 60 (IPv6), 40 (IPv4), 72 (IPv6 + timestamps), 52 (IPv4 + timestamps) and the difference IPv4 minus IPv6."""
import csv, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import analyze_testbed as A
S = A.S
FILES = (("ipv4_flip", "ipv4_flip_configs.csv"), ("offload", "offload_configs.csv"))
out = []
for exp, fn in FILES:
    for c in csv.DictReader(open(os.path.join(HERE, "results", fn))):
        fl = S.build_flow(c["suite"], A.probe_protocol(c["mtls"], c["req"], c["resp"], c["depth"]), int(c["depth"]), "cold", False)
        pr = {}
        for h in (60, 40, 72, 52):
            n = S.Net(float(c["rate_mbps"]), float(c["rtt_ms"]), int(c["mtu"]), penalty_ms=0.0, thr=4, init_cwnd=int(c["icw"]), cwnd_validation=True, segmentation="openssl", cwnd_slack=0, hdr=h)
            r = S.run_flow(fl, n); pr[h] = r["total"] - r["cpu"]
        out.append(dict(experiment=exp, suite=c["suite"], depth=c["depth"], mtls=c["mtls"], req=c["req"], resp=c["resp"], rtt_ms=c["rtt_ms"], rate_mbps=c["rate_mbps"], mtu=c["mtu"], icw=c["icw"],
                        model_hdr60=round(pr[60], 3), model_hdr40=round(pr[40], 3), model_hdr72=round(pr[72], 3), model_hdr52=round(pr[52], 3), d_ipv4_minus_ipv6=round(pr[40] - pr[60], 3)))
p = os.path.join(HERE, "results", "ipv4_offload_predictions.csv")
w = csv.DictWriter(open(p, "w", newline=""), fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
big = [o for o in out if o["experiment"] == "ipv4_flip" and abs(o["d_ipv4_minus_ipv6"]) > 5]
print(f"{len(out)} rows -> {p}; in the ipv4_flip experiment IPv4 changes the predicted excess by more than 5 ms in {len(big)} of 14 configurations:")
for o in out:
    if o["experiment"] == "ipv4_flip": print(f"  {o['suite']:22s} d{o['depth']} req {o['req']:>5} resp {o['resp']:>5}: IPv6 {o['model_hdr60']:7.2f} -> IPv4 {o['model_hdr40']:7.2f} ms ({o['d_ipv4_minus_ipv6']:+.1f})")
