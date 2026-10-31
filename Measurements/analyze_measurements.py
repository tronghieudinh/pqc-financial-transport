#!/usr/bin/env python3
"""
analyze_measurements.py - compare real OpenSSL 3.5 artefacts with the simulator's model.

Outputs (data/):
  cpu_summary.csv     v1 illustrative inputs vs measured X925 / A725 medians
  cert_sizes.csv      real DER sizes vs the certificate model
  compression.csv     zlib-9 on real chains vs the compression model
  tls_vs_model.csv    real handshake flights vs model flights (real chain sizes / bank metadata)
"""
import csv
import importlib.util
import json
import math
import os
import statistics as st
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "data")
sys.path.insert(0, os.path.join(HERE, "..", "Simulation"))
import pqc_sim as S   # noqa: E402  (v2 simulator, measured CPU inputs)

O = os.path.expanduser("~/opt/openssl-3.5/bin/openssl")
ENV = dict(os.environ, LD_LIBRARY_PATH=os.path.expanduser("~/opt/openssl-3.5/lib"))
CERT_ALG = {"RSA-2048": "RSA-2048", "RSA-3072": "RSA-3072", "ECDSA-P256": "ECDSA-P256", "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65", "ML-DSA-87": "ML-DSA-87", "SLH-DSA-128s": "SLH-DSA-SHA2-128s",
            "SLH-DSA-128f": "SLH-DSA-SHA2-128f"}


def v1_module():
    p = os.path.join(HERE, "..", "..", "v1", "Simulation", "pqc_sim.py")
    spec = importlib.util.spec_from_file_location("pqc_sim_v1", p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pqc_sim_v1"] = mod          # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


def der_len(pem):
    out = subprocess.run([O, "x509", "-in", pem, "-outform", "DER"], env=ENV, capture_output=True, check=True).stdout
    return len(out)


def chain_lengths(alg, depth):
    """DER lengths of the certificates a peer sends at chain depth `depth` (leaf first)."""
    d = os.path.join(HERE, "certs", CERT_ALG[alg], f"d{depth}")
    ls = [der_len(os.path.join(d, "server.pem"))]
    for i in range(depth - 1, 0, -1):
        ls.append(der_len(os.path.join(d, f"ca{i}.pem")))
    return ls


def chain_bytes(alg, depth):
    d = os.path.join(HERE, "certs", CERT_ALG[alg], f"d{depth}")
    pems = [os.path.join(d, "server.pem")] + [os.path.join(d, f"ca{i}.pem") for i in range(depth - 1, 0, -1)]
    return [subprocess.run([O, "x509", "-in", p, "-outform", "DER"], env=ENV, capture_output=True, check=True).stdout
            for p in pems]


# ------------------------------------------------------------------ 1. CPU
def cpu_summary():
    v1 = v1_module()
    mi = json.load(open(os.path.join(D, "measured_inputs.json")))
    rows = []
    for n in S.SIGS:
        for op in ("sign_ms", "verify_ms"):
            a = getattr(v1.SIGS[n], op)
            x = mi["X925"]["sigs"][n][op]
            e = mi["A725"]["sigs"][n][op]
            rows.append([n, op.replace("_ms", ""), a, round(x, 5), round(e, 5), round(x / a, 2), round(e / x, 2),
                         mi["X925"]["sigs"][n]["source"]])
    for n in S.KEXS:
        for op in ("gen_ms", "derive_ms", "server_ms"):
            a = getattr(v1.KEXS[n], op)
            x = mi["X925"]["kex"][n][op]
            e = mi["A725"]["kex"][n][op]
            rows.append([n, op.replace("_ms", ""), a, round(x, 5), round(e, 5), round(x / a, 2), round(e / x, 2), "OpenSSL 3.5.4"])
    with open(os.path.join(D, "cpu_summary.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["alg", "op", "v1_assumed_ms", "x925_ms", "a725_ms", "x925_over_v1", "a725_over_x925", "source"])
        w.writerows(rows)
    lib = mi["X925"]["sigs"]["ML-DSA-65"]["liboqs_cross_check"]
    print(f"[cpu] ML-DSA-65 sign: OpenSSL {mi['X925']['sigs']['ML-DSA-65']['sign_ms']:.3f} ms vs liboqs {lib['sign_ms']:.3f} ms")


# ------------------------------------------------------------------ 2. certificate sizes
def cert_sizes():
    rows = []
    meta = {}
    for alg in CERT_ALG:
        sg = S.SIGS[alg]
        ls = chain_lengths(alg, 4)                  # leaf, ca3, ca2, ca1
        leaf, ca = ls[0], st.median(ls[1:])
        fixed = sg.pk + sg.spki_hdr + sg.sig + 4
        meta[alg] = (leaf - fixed, ca - fixed)
        rows.append([alg, leaf, int(ca), leaf - fixed, int(ca - fixed)])
    ml, mc = meta["ECDSA-P256"]                     # calibrate on the classical certificate ...
    out = []
    for alg, leaf, ca, m_l, m_c in rows:            # ... and predict every other algorithm
        sg = S.SIGS[alg]
        pl = ml + sg.pk + sg.spki_hdr + sg.sig + 4
        pc = mc + sg.pk + sg.spki_hdr + sg.sig + 4
        out.append([alg, leaf, ca, m_l, m_c, pl, pc, round(100 * (pl - leaf) / leaf, 2), round(100 * (pc - ca) / ca, 2)])
    with open(os.path.join(D, "cert_sizes.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["alg", "leaf_der", "ca_der", "leaf_meta", "ca_meta", "pred_leaf_from_ecdsa_meta",
                    "pred_ca_from_ecdsa_meta", "err_leaf_pct", "err_ca_pct"])
        w.writerows(out)
    print("[certs] max |prediction error| = %.2f %%" % max(max(abs(r[7]), abs(r[8])) for r in out))
    return meta


# ------------------------------------------------------------------ 3. compression on real chains
def compression(meta):
    rows = []
    m = S.Model()
    for alg in CERT_ALG:
        sg = S.SIGS[alg]
        for d in (1, 2, 3, 4):
            ders = chain_bytes(alg, d)
            body = b"\x00" + sum((5 + len(x) for x in ders), 0).to_bytes(3, "big") + \
                b"".join(len(x).to_bytes(3, "big") + x + b"\x00\x00" for x in ders)
            real = len(zlib.compress(body, 9))
            rnd = sg.pk + sg.sig
            model = m.comp_fixed + sum(rnd + (len(x) + 5 - rnd) * (m.r_first if i == 0 else m.r_next)
                                       for i, x in enumerate(ders))
            rows.append([alg, d, len(body), real, int(math.ceil(model)), round(real / len(body), 3),
                         round(model / len(body), 3)])
    with open(os.path.join(D, "compression.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["alg", "depth", "uncompressed", "zlib9", "model", "ratio_real", "ratio_model"])
        w.writerows(rows)
    err = [abs(r[3] - r[4]) / r[3] for r in rows]
    print(f"[compression] model vs zlib-9 on real chains: median |err| {100 * st.median(err):.1f} %, max {100 * max(err):.1f} %")


# ------------------------------------------------------------------ 4. TLS flights vs model
def model_flights(suite, chain, mtls, m):
    """CH, SF, CF of the TLS 1.3 handshake as computed inside pqc_sim.build_flow."""
    su = S.SUITES[suite]
    sg, kx = S.SIGS[su.sig], S.KEXS[su.kex]
    cert_wire = 4 + (1 + 3 + sum(5 + L for L in chain))
    cv = 4 + 2 + 2 + sg.sig
    fin = 4 + m.finished
    ch = m.ch_base + kx.client_share
    srv = [m.enc_ext] + ([m.cert_req] if mtls else []) + [cert_wire, cv, fin]
    cli = ([cert_wire, cv] if mtls else []) + [fin]
    rec = (lambda msgs: sum(S.rec_ovh(x) for x in msgs)) if m.record_per_message else (lambda msgs: S.rec_ovh(sum(msgs)))
    sf = m.sh_base + kx.server_share + 6 + sum(srv) + rec(srv)
    cf = 6 + sum(cli) + rec(cli)
    return ch, sf, cf


def tls_vs_model():
    p = os.path.join(D, "tls_trace.csv")
    rows = [r for r in csv.DictReader(open(p)) if r["ch_bytes"]]
    m = S.Model()
    out = []
    for r in rows:
        su, d, mt = r["suite"], int(r["depth"]), r["mtls"] == "1"
        sig = S.SUITES[su].sig
        real_chain = chain_lengths(sig, d)
        bank_chain = S.cert_chain(S.SIGS[sig], d, m)
        a = model_flights(su, real_chain, mt, m)
        b = model_flights(su, bank_chain, mt, m)
        meas = (int(r["ch_bytes"]), int(r["sf_bytes"]), int(r["cf_bytes"]))
        tot_m, tot_a, tot_b = sum(meas), sum(a), sum(b)
        sg, kx = S.SIGS[sig], S.KEXS[S.SUITES[su].kex]
        cpu = kx.gen_ms + kx.server_ms + sg.sign_ms + kx.derive_ms + (d + 1) * sg.verify_ms
        if mt:
            cpu += sg.sign_ms + (d + 1) * sg.verify_ms
        out.append([su, d, int(mt), *meas, *a, round(100 * (tot_a - tot_m) / tot_m, 2), *b,
                    round(100 * (tot_b - tot_m) / tot_m, 2), r["hs_ms_median"], round(cpu, 4)])
    with open(os.path.join(D, "tls_vs_model.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["suite", "depth", "mtls", "ch_real", "sf_real", "cf_real", "ch_model", "sf_model", "cf_model",
                    "err_total_pct_realchain", "ch_bank", "sf_bank", "cf_bank", "err_total_pct_bankmeta", "hs_ms_median",
                    "model_hs_cpu_ms"])
        w.writerows(out)
    e = [abs(x[9]) for x in out]
    print(f"[tls] model framing with real chains: median |err| {st.median(e):.2f} %, max {max(e):.2f} % over {len(out)} configs")
    for x in out:
        if x[1] in (1, 4) and x[2] == 1:
            print(f"   {x[0]:28s} d{x[1]} mTLS  loopback hs {float(x[14]):6.2f} ms  model CPU {x[15]:6.2f} ms")


if __name__ == "__main__":
    cpu_summary()
    meta = cert_sizes()
    compression(meta)
    if os.path.exists(os.path.join(D, "tls_trace.csv")):
        tls_vs_model()
