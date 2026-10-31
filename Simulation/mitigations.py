#!/usr/bin/env python3
"""
mitigations.py - how much of the post-quantum penalty each mitigation recovers.

Mitigations: none (cold TCP + TLS 1.3), cached_info (RFC 7924), Merkle Tree Certificates (draft),
PSK resumption (calibrated on OpenSSL 3.5), QUIC (no TCP handshake, 3x anti-amplification limit),
QUIC + resumption. Suites include composite (hybrid) certificates. Wired reference path and the
5G sub-6 radio channel (SimPy Monte Carlo; QUIC only on the wired model).

    python3 mitigations.py [trials] -> mitigations.csv
"""
import csv
import itertools
import os
import statistics as st
import sys
from concurrent.futures import ProcessPoolExecutor

import pqc_sim as S
import radio_sim as R

SUITES = ["ECDSA-P256|X25519", "ECDSA-P256|X25519MLKEM768", "ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768",
          "Falcon-512|ML-KEM-768", "ML-DSA-44+ECDSA-P256|X25519MLKEM768", "ML-DSA-65+ECDSA-P256|X25519MLKEM768"]
PROTOS = ["FAPI2", "ISO_20022", "SWIFT_MX"]
MITIG = {  # name: (mode, Model kwargs, quic)
    "none": ("cold", {}, False),
    "cached_info": ("cold", {"cached_info": True}, False),
    "mtc": ("cold", {"mtc": True}, False),
    "resumption": ("resumed", {}, False),
    "quic": ("cold", {}, True),
    "quic+resumption": ("resumed", {}, True),
}
SINRS = [30.0, 10.0, 0.0, -5.0]
PROF = "5G-NR sub-6 (eMBB)"


def flow(su, pr, mit):
    mode, kw, _ = MITIG[mit]
    return S.build_flow(su, pr, S.PROTOCOLS[pr].default_depth, mode, False, S.Model(**kw))


def radio_task(args):
    pr, mit, sinr, trials = args
    rows = []
    for su in SUITES:
        f = flow(su, pr, mit)
        lat = [R.run_radio_flow(f, R.PROFILES[PROF], sinr, 20.0, 1500, f"env|mit|{pr}|{sinr}|{t}",
                                f"pkt|{su}|{mit}|{pr}|{sinr}|{t}")["total"] for t in range(trials)]
        lat.sort()
        rows.append([pr, mit, "radio", sinr, su, round(st.mean(lat), 3), round(lat[int(0.99 * (len(lat) - 1))], 3)])
    return rows


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mitigations.csv")
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["protocol", "mitigation", "network", "sinr_db", "suite", "mean_ms", "p99_ms"])
        for pr, mit, su in itertools.product(PROTOS, MITIG, SUITES):
            q = MITIG[mit][2]
            for name, net in (("wired", S.Net(100.0, 30.0, 1500, 6.0, 4, quic=q)),
                              ("wired_slow", S.Net(10.0, 100.0, 1500, 6.0, 4, quic=q))):
                t = S.run_flow(flow(su, pr, mit), net)["total"]
                w.writerow([pr, mit, name, "", su, round(t, 3), round(t, 3)])
        tasks = [(pr, mit, s, trials) for pr in PROTOS for mit in MITIG if not MITIG[mit][2] for s in SINRS]
        with ProcessPoolExecutor(12) as ex:
            for rows in ex.map(radio_task, tasks):
                w.writerows(rows)
    print(f"[mitigations] written {out}")


if __name__ == "__main__":
    main()
