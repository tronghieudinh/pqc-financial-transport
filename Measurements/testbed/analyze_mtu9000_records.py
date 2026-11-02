#!/usr/bin/env python3
"""
analyze_mtu9000_records.py - the MTU 9000 anomaly of the TLS cells is the write pattern of OpenSSL (paper 2, WP6 B5b). No root.

    python3 analyze_mtu9000_records.py

OpenSSL sends application data as one write() per TLS record of up to 16,384 bytes. With TCP_NODELAY, every record that ends in a partial segment leaves that partial segment at once if the
window has room. At MTU 1500 a 16-KB record is 11.4 segments and the partial tail is small; at MTU 9000 it is 1.8 segments: a response flight shows 8,940, 7,466, 8,940, 7,466, ... bytes on the wire
(server capture of the race run), so five records use ten segments of the window although they hold 82 KB, not 89 KB. The model option Model(app_records=True) writes the messages record by
record. The option is off by default (Paper 1: its application messages are below one record in the validated cases, 0 of 32 flows differ). No parameter is fitted.
Compares the resumed MTU-9000 cells of the receive-buffer test (default and raised tcp_rmem) and the 240 cells of the `gen` scenario with and without the option.
"""
import csv, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "..", "Simulation"))
import analyze_testbed as A  # noqa: E402
import pqc_sim as S  # noqa: E402
f = float
WM = {"ECDSA-P256|X25519": 0, "ML-DSA-44|ML-KEM-768": 12, "ML-DSA-65|ML-KEM-768": 15}

def pred(su, rq, rs, rtt, rate, mtu, flag, wm=0):
    flow = S.build_flow(su, A.probe_protocol("1", str(rq), str(rs), "2"), 2, "resumed", False, S.Model(app_records=flag))
    net = S.Net(rate, rtt, mtu, penalty_ms=0.0, thr=4, init_cwnd=10, cwnd_validation=True, segmentation="openssl", nst_early=True, srv_cwnd_acked=wm)
    m = S.run_flow(flow, net)
    return m["total"] - m["cpu"]

def report(label, rows, wmeas=False):
    for flag in (False, True):
        e = [pred(r["suite"], int(r["req"]), int(r["resp"]), f(r["rtt_ms"]), f(r["rate_mbps"]), int(r["mtu"]), flag, WM[r["suite"]] if wmeas else 0) - f(r["resumed_excess"]) for r in rows]
        w = sum(abs(x) > 0.5 * f(r["rtt_ms"]) for x, r in zip(e, rows))
        print(f"{label:48s} app_records={flag!s:5s}: n={len(e):3d}  MAE {st.mean(abs(x) for x in e):6.2f} ms  max {max(abs(x) for x in e):6.1f}  wrong by a round trip: {w}")

def main():
    R = os.path.join(HERE, "results")
    for tag in ("default", "large"):
        p = os.path.join(R, f"resume_summary_wp6_mtu9000_{tag}.csv")
        if os.path.exists(p):
            report(f"MTU 9000 cells, tcp_rmem {tag}", list(csv.DictReader(open(p))))
    p = os.path.join(R, "resume_summary_wp6_gen.csv")
    if os.path.exists(p):
        rows = list(csv.DictReader(open(p)))
        report("gen, all cells", rows); report("gen, MTU 9000", [r for r in rows if r["mtu"] == "9000"]); report("gen, MTU below 9000", [r for r in rows if r["mtu"] != "9000"])
        report("gen, all cells, windows 10/12/15 after the ticket", rows, True)
    n = d = 0
    for su in WM:
        for rq, rs in ((302, 222), (10900, 3600)):
            for dep in (1, 2, 3, 4):
                a = S.build_flow(su, A.probe_protocol("1", str(rq), str(rs), str(dep)), dep, "cold", False, S.Model())
                b = S.build_flow(su, A.probe_protocol("1", str(rq), str(rs), str(dep)), dep, "cold", False, S.Model(app_records=True))
                n += 1; d += a.writes != b.writes
    print(f"Paper 1 flows (3 suites x ISO 8583 and SWIFT-sized x depth 1-4) whose writes change with the option: {d} of {n}")

if __name__ == "__main__":
    main()
