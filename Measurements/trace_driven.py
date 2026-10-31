#!/usr/bin/env python3
"""
trace_driven.py - real OpenSSL 3.5 TLS 1.3 handshakes replayed over the stochastic 5G/6G channel.

No kernel network emulation is available without administrator rights (tc/netem), so the experiment
is trace-driven: the handshake flights (ClientHello, server flight, client flight) are the bytes
measured on real handshakes (tls_trace.py), the certificates embedded in application signatures are
the real leaf certificates, and the handshake CPU equals the measured loopback handshake time. These
"trace" flows (T) and the calibrated model flows (M) are replayed through the same SimPy radio
channel with common random numbers, and through the wired model.

    python3 trace_driven.py [trials]  -> data/trace_driven_radio.csv, data/trace_driven_wired.csv
"""
import csv
import itertools
import os
import statistics as st
import sys
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "data")
sys.path.insert(0, os.path.join(HERE, "..", "Simulation"))
import pqc_sim as S                       # noqa: E402
import radio_sim as R                     # noqa: E402
import analyze_measurements as A          # noqa: E402

SUITES = ["ECDSA-P256|X25519", "ECDSA-P256|X25519MLKEM768", "RSA-2048|ECDHE-P256", "ML-DSA-44|ML-KEM-768",
          "ML-DSA-65|ML-KEM-768", "ML-DSA-87|ML-KEM-1024"]
PROTOS = ["FAPI2", "ISO_20022", "OIDC"]
PROFILES = ["5G-NR sub-6 (eMBB)", "5G-NR URLLC", "6G upper mid-band (FR3, assumed)"]
SINRS = [30.0, 10.0, 0.0, -5.0]
DEPTHS = [1, 2, 3, 4]
BASE = "ECDSA-P256|X25519"


def load_trace():
    t = {}
    for r in csv.DictReader(open(os.path.join(D, "tls_trace.csv"))):
        if r["ch_bytes"]:
            t[(r["suite"], int(r["depth"]), r["mtls"] == "1")] = (int(r["ch_bytes"]), int(r["sf_bytes"]),
                                                                    int(r["cf_bytes"]), float(r["hs_ms_median"]))
    return t


def real_meta():
    """Leaf / CA metadata of the generated certificates (cert_sizes.csv)."""
    return {r["alg"]: (int(r["leaf_meta"]), int(r["ca_meta"]))
            for r in csv.DictReader(open(os.path.join(D, "cert_sizes.csv")))}


def flows(suite, proto, depth, trace, metas):
    """(M) calibrated-model flow and (T) trace-driven flow for one configuration."""
    mtls = S.PROTOCOLS[proto].mtls
    sig = S.SUITES[suite].sig
    m_model = S.Model()
    fm = S.build_flow(suite, proto, depth, "cold", False, m_model)
    lm, cm = metas[sig]
    m_real = S.Model(leaf_meta=lm, ca_meta=cm)
    base = S.build_flow(suite, proto, depth, "cold", False, m_real)
    ch, sf, cf, hs_ms = trace[(suite, depth, mtls)]
    _, _, cf_model = A.model_flights(suite, S.cert_chain(S.SIGS[sig], depth, m_real), mtls, m_real)
    sg, kx = S.SIGS[sig], S.KEXS[S.SUITES[suite].kex]
    hs_cpu = kx.gen_ms + kx.server_ms + sg.sign_ms + kx.derive_ms + (depth + 1) * sg.verify_ms
    if mtls:
        hs_cpu += sg.sign_ms + (depth + 1) * sg.verify_ms
    steps = list(base.steps)
    assert steps[2][0] == "x" and steps[4][0] == "x" and steps[6][0] == "x"
    steps[2] = ("x", 0, ch)
    steps[4] = ("x", 1, sf)
    steps[6] = ("x", 0, steps[6][2] - cf_model + cf)
    steps.insert(3, ("cpu", max(0.0, hs_ms - hs_cpu)))    # unmodelled handshake work seen on loopback
    ft = S.Flow(base.mode, tuple(steps), base.sizes, 0.0, 0.0, 0.0, 0.0)
    return fm, ft


def task(args):
    prof, proto, depth, trials, trace, metas = args
    out = []
    for suite in SUITES:
        fm, ft = flows(suite, proto, depth, trace, metas)
        for sinr in SINRS:
            res = {}
            for tag, f in (("M", fm), ("T", ft)):
                lat = []
                for t in range(trials):
                    key = f"td|{prof}|{sinr}|{proto}|{depth}|{t}"
                    lat.append(R.run_radio_flow(f, R.PROFILES[prof], sinr, 20.0, 1500, "env|" + key,
                                                f"pkt|{suite}|" + key)["total"])
                lat.sort()
                res[tag] = (st.mean(lat), lat[int(0.99 * (len(lat) - 1))])
            out.append([prof, sinr, proto, depth, suite, round(res["M"][0], 3), round(res["T"][0], 3),
                        round(res["M"][1], 3), round(res["T"][1], 3)])
    return out


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    trace, metas = load_trace(), real_meta()
    # wired, deterministic: reference network, all depths
    with open(os.path.join(D, "trace_driven_wired.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["proto", "depth", "suite", "bw_mbps", "rtt_ms", "model_ms", "trace_ms", "model_bytes", "trace_bytes"])
        for proto, depth, suite, (bw, rtt) in itertools.product(PROTOS, DEPTHS, SUITES, ((100.0, 30.0), (10.0, 100.0))):
            fm, ft = flows(suite, proto, depth, trace, metas)
            net = S.Net(bw, rtt, 1500, 6.0, 4)
            bm = sum(s[2] for s in fm.steps if s[0] == "x")
            bt = sum(s[2] for s in ft.steps if s[0] == "x")
            w.writerow([proto, depth, suite, bw, rtt, round(S.run_flow(fm, net)["total"], 3),
                        round(S.run_flow(ft, net)["total"], 3), bm, bt])
    tasks = [(p, pr, d, trials, trace, metas) for p in PROFILES for pr in PROTOS for d in DEPTHS]
    with ProcessPoolExecutor(12) as ex, open(os.path.join(D, "trace_driven_radio.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["profile", "sinr_db", "proto", "depth", "suite", "model_mean", "trace_mean", "model_p99", "trace_p99"])
        for rows in ex.map(task, tasks):
            w.writerows(rows)
    print(f"[trace_driven] {len(tasks) * len(SUITES) * len(SINRS)} radio cells x {trials} trials x 2 variants")


if __name__ == "__main__":
    main()
