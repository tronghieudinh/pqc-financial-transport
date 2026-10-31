#!/usr/bin/env python3
"""
make_inputs.py - turn the CPU measurements into simulator inputs.

Reads data/cpu_openssl_core{19,4}.csv (OpenSSL 3.5.4) and data/cpu_liboqs_core{19,4}.csv
(liboqs 0.14.0, Falcon only), writes data/measured_inputs.json and patches the SIGS/KEXS tables
of ../Simulation/pqc_sim.py with the performance-core (Cortex-X925) values in milliseconds.

    python3 make_inputs.py
"""
import csv
import json
import os
import re
import statistics as st

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "data")
SIM = os.path.join(HERE, "..", "Simulation", "pqc_sim.py")
CORES = {"X925": 19, "A725": 4}
OSSL_SIG = {"RSA-2048": "RSA-2048", "RSA-3072": "RSA-3072", "ECDSA-P256": "ECDSA-P256", "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65", "ML-DSA-87": "ML-DSA-87", "SLH-DSA-128s": "SLH-DSA-SHA2-128s",
            "SLH-DSA-128f": "SLH-DSA-SHA2-128f"}
OQS_SIG = {"Falcon-512": "Falcon-padded-512", "Falcon-1024": "Falcon-padded-1024"}


def load(core):
    t = {}
    for r in csv.DictReader(open(os.path.join(D, f"cpu_openssl_core{core}.csv"))):
        t[(r["alg"], r["op"])] = float(r["median_us"]) / 1000.0
    oqs = {}
    for r in csv.DictReader(open(os.path.join(D, f"cpu_liboqs_core{core}.csv"))):
        oqs.setdefault((r["alg"], r["op"]), []).append(float(r["median_us"]) / 1000.0)
    for k, v in oqs.items():
        t[("oqs:" + k[0], k[1])] = st.median(v)
    return t


def inputs(t):
    sig = {n: {"sign_ms": t[(a, "sign")], "verify_ms": t[(a, "verify")], "source": "OpenSSL 3.5.4"} for n, a in OSSL_SIG.items()}
    for n, a in OQS_SIG.items():
        sig[n] = {"sign_ms": t[("oqs:" + a, "sign")], "verify_ms": t[("oqs:" + a, "verify")], "source": "liboqs 0.14.0"}
    sig["ML-DSA-65"]["liboqs_cross_check"] = {"sign_ms": t[("oqs:ML-DSA-65", "sign")], "verify_ms": t[("oqs:ML-DSA-65", "verify")]}
    x = {k: t[("X25519", k)] for k in ("keygen", "derive")}
    p = {k: t[("P-256", k)] for k in ("keygen", "derive")}
    m768 = {k: t[("ML-KEM-768", k)] for k in ("keygen", "encaps", "decaps")}
    m1024 = {k: t[("ML-KEM-1024", k)] for k in ("keygen", "encaps", "decaps")}
    kex = {   # client: gen before ClientHello, derive after ServerHello; server: its whole share
        "ECDHE-P256": {"gen_ms": p["keygen"], "derive_ms": p["derive"], "server_ms": p["keygen"] + p["derive"]},
        "X25519": {"gen_ms": x["keygen"], "derive_ms": x["derive"], "server_ms": x["keygen"] + x["derive"]},
        "X25519MLKEM768": {"gen_ms": x["keygen"] + m768["keygen"], "derive_ms": x["derive"] + m768["decaps"],
                           "server_ms": x["keygen"] + x["derive"] + m768["encaps"]},
        "ML-KEM-768": {"gen_ms": m768["keygen"], "derive_ms": m768["decaps"], "server_ms": m768["encaps"]},
        "ML-KEM-1024": {"gen_ms": m1024["keygen"], "derive_ms": m1024["decaps"], "server_ms": m1024["encaps"]},
    }
    return {"sigs": sig, "kex": kex}


def r4(v):
    return float(f"{v:.4g}")


def main():
    out = {c: inputs(load(n)) for c, n in CORES.items()}
    out["env"] = open(os.path.join(D, "env.txt")).read()
    json.dump(out, open(os.path.join(D, "measured_inputs.json"), "w"), indent=1)
    src = open(SIM).read()
    x = out["X925"]
    for n, v in x["sigs"].items():
        pat = re.compile(r'(Sig\("' + re.escape(n) + r'",\s*"[a-z]+",\s*\d+,\s*\d+,\s*\d+,\s*)([0-9.]+),\s*([0-9.]+)\)')
        src, k = pat.subn(lambda m: f"{m.group(1)}{r4(v['sign_ms'])}, {r4(v['verify_ms'])})", src)
        assert k == 1, n
    for n, v in x["kex"].items():
        pat = re.compile(r'(Kex\("' + re.escape(n) + r'",\s*"[a-z]+",\s*\d+,\s*\d+,\s*)([0-9.]+),\s*([0-9.]+),\s*([0-9.]+)\)')
        src, k = pat.subn(lambda m: f"{m.group(1)}{r4(v['gen_ms'])}, {r4(v['derive_ms'])}, {r4(v['server_ms'])})", src)
        assert k == 1, n
    open(SIM, "w").write(src)
    ratio = st.median(out["A725"]["sigs"][n][op] / x["sigs"][n][op] for n in x["sigs"] for op in ("sign_ms", "verify_ms"))
    print(f"patched {SIM}; median A725/X925 slowdown = {ratio:.2f}")


if __name__ == "__main__":
    main()
