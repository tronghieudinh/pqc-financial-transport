#!/usr/bin/env python3
"""
asymmetric_depth.py - does the 60 ms of Paper 1 (ML-DSA-65, SWIFT MX, depth 1 -> 4 at BOTH peers) come from the server chain, the client
chain, or both? The main model gives the two mutual-TLS chains the same depth; build_flow(..., depth_client=) lifts that.

    python3 asymmetric_depth.py [--out asymmetric_depth.csv]

Reference scenario: cold, mutual TLS, 100 Mbit/s, RTT 30 ms, MTU 1500, initial window 10, pi = 0. For ML-DSA-65 and the ECDSA-P256 baseline:
the latency for every pair (server depth, client depth) in 1..4, and the increase from (1,1) when only the server chain, only the client chain,
or both chains grow to depth 4. Chains in which a certificate of one algorithm is signed by a CA of another algorithm are NOT modeled.
"""
import argparse, csv, os
import pqc_sim as ps

HERE = os.path.dirname(os.path.abspath(__file__))
SUITES = {"ECDSA-P256": ps.BASELINE, "ML-DSA-65": "ML-DSA-65|ML-KEM-768"}
PROTO = "SWIFT_MX"

def lat(suite, ds, dc, mtu=1500, icw=10, rtt=30.0):
    f = ps.build_flow(suite, PROTO, ds, "cold", False, ps.Model(), dc)
    return ps.run_flow(f, ps.Net(100.0, rtt, mtu, 0.0, 4, icw, icw), 1.0)["total"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "asymmetric_depth.csv"))
    a = ap.parse_args()
    rows = [["suite", "mtu", "icw", "server_depth", "client_depth", "latency_ms"]]
    summ = [["suite", "mtu", "icw", "both_1to4_ms", "server_only_1to4_ms", "client_only_1to4_ms", "sum_of_single_ms"]]
    for name, suite in SUITES.items():
        for mtu, icw in ((1500, 10), (1500, 32), (1280, 10), (9000, 10)):
            L = {(ds, dc): lat(suite, ds, dc, mtu, icw) for ds in range(1, 5) for dc in range(1, 5)}
            for (ds, dc), v in L.items():
                rows.append([name, mtu, icw, ds, dc, round(v, 3)])
            b = L[(4, 4)] - L[(1, 1)]; s = L[(4, 1)] - L[(1, 1)]; c = L[(1, 4)] - L[(1, 1)]
            summ.append([name, mtu, icw, round(b, 1), round(s, 1), round(c, 1), round(s + c, 1)])
    csv.writer(open(a.out, "w", newline="")).writerows(rows)
    for r in summ: print(*r, sep="\t")
    # the matrix of the reference scenario
    print("\nlatency (ms), ML-DSA-65, MTU 1500, icw 10: rows = server depth, columns = client depth")
    for ds in range(1, 5): print(ds, *[f"{lat(SUITES['ML-DSA-65'], ds, dc):7.1f}" for dc in range(1, 5)])

if __name__ == "__main__":
    main()
