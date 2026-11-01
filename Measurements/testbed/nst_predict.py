#!/usr/bin/env python3
"""
nst_predict.py - pre-registration of the stage-D test (WP5): is the session ticket its own, EARLIER write in a resumed TLS 1.3 transaction?

Hypothesis H_nst (Net.nst_early): an OpenSSL server writes the NewSessionTicket as soon as the client's Finished has arrived (the first
small segment of the client's last flight), not together with the response. If the client's request flight needs an extra round trip
(window-limited), the ticket is acknowledged before the response leaves, and the server's response flight no longer contains it; otherwise
the ticket and the response share the server's window. The alternative H_joined (the model's default, Net.nst_early = False) always puts
the ticket in the response flight.

Test design (run_nst_tls.sh): resumed TLS 1.3, ECDSA-P256 and ML-DSA-44/-65/-87 at depth 2 (mutual TLS, the ticket embeds the client
certificate: 1, 4, 5 and 6 segments), RTT 100 ms, MTU 1500, a small request (302 B: the client flight fits the window) and a large one
(19,460 B: the client flight needs an extra round trip for ECDSA, ML-DSA-44 and -65, not for -87), and responses whose size gives k = 3..12
segments. The two hypotheses disagree wherever the ticket decides whether the server flight crosses the window.
Run once, commit the output BEFORE measuring.
"""
import csv, hashlib, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze_testbed as A  # noqa: E402

SUITES = ["ECDSA-P256|X25519", "ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768", "ML-DSA-87|ML-KEM-1024"]
MSS = 1440
REQS = [302, 19460]
KS = list(range(3, 13))


def resp_bytes(k):
    return k * MSS - 700


def main():
    out = os.path.join(HERE, "results", "nst_predictions.csv")
    if os.path.exists(out) and "--force" not in sys.argv:
        sys.exit(f"{out} exists (pre-registered); delete it deliberately to redo")
    rows = []
    for su in SUITES:
        for rq in REQS:
            for k in KS:
                c = dict(suite=su, depth="2", mtls="1", req=str(rq), resp=str(resp_bytes(k)), rtt_ms="100", rate_mbps="100", mtu="1500", icw="10", resume="1")
                flow = A.S.build_flow(su, A.probe_protocol("1", c["req"], c["resp"], "2"), 2, "resumed", False)
                r = dict(suite=su, req=rq, resp=resp_bytes(k), resp_segments=k)
                for name, ne in (("joined", False), ("early", True)):
                    net = A.S.Net(100.0, 100.0, 1500, penalty_ms=0.0, thr=4, init_cwnd=10, cwnd_validation=True, segmentation="openssl", nst_early=ne)
                    m = A.S.run_flow(flow, net)
                    r[f"model_{name}_ms"] = round(m["total"] - m["cpu"], 2)
                r["differ"] = int(abs(r["model_joined_ms"] - r["model_early_ms"]) > 50)
                rows.append(r)
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    sim = os.path.join(HERE, "..", "..", "Simulation", "pqc_sim.py")
    print(f"{len(rows)} predictions, {sum(r['differ'] for r in rows)} on which the hypotheses differ by a round trip -> {out}")
    print(f"written {time.strftime('%Y-%m-%d %H:%M:%S')}  pqc_sim.py sha256 {hashlib.sha256(open(sim, 'rb').read()).hexdigest()}")
    for su in SUITES:
        for rq in REQS:
            print(f"{su:24s} req {rq:6d}: differing k = {[r['resp_segments'] for r in rows if r['suite'] == su and r['req'] == rq and r['differ']]}")


if __name__ == "__main__":
    main()
