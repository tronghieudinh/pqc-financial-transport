#!/usr/bin/env python3
"""
analyze_capacity.py - server capacity from capacity_test.py against the sum of the measured primitive costs (paper 2, WP2).

    python3 analyze_capacity.py results/capacity_<machine>.csv [--costs x925|x86] [--out results/capacity_summary_<machine>.csv]

For every suite, authentication mode, chain depth and resumption it prints
  cpu_ms_per_hs      measured server CPU per transaction (user + system, whole process: TLS, kernel, event loop)
  primitive_ms       the server-side cryptography of the model: key establishment + CertificateVerify signature + (mutual TLS)
                     verification of the client chain and signature; nothing for a resumed handshake
  overhead           cpu_ms_per_hs / primitive_ms: how much of the measured cost the primitives explain
  hs_per_s_core      1000 / cpu_ms_per_hs, the capacity of a saturated core
  vs_baseline        cpu_ms_per_hs over that of ECDSA-P256 + X25519 in the same mode (the post-quantum capacity factor)
Rows with util < 0.9 are flagged: the load generator or the kernel, not the server, limited the rate there.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MEAS = os.path.join(HERE, "..")
sys.path.insert(0, MEAS)
sys.path.insert(0, os.path.join(MEAS, "x86"))
sys.path.insert(0, os.path.join(MEAS, "..", "Simulation"))
import make_inputs as MI  # noqa: E402
import pqc_sim as S  # noqa: E402
import analyze_cpu_x86 as X  # noqa: E402

BASE = "ECDSA-P256|X25519"


def install(costs):
    inp = MI.inputs(MI.load(19)) if costs == "x925" else MI.inputs(X.load_x86(os.path.join(MEAS, "x86", "data")))
    for n, v in inp["sigs"].items():
        S.SIGS[n] = dataclasses.replace(S.SIGS[n], sign_ms=v["sign_ms"], verify_ms=v["verify_ms"])
    for n, v in inp["kex"].items():
        S.KEXS[n] = dataclasses.replace(S.KEXS[n], gen_ms=v["gen_ms"], derive_ms=v["derive_ms"], server_ms=v["server_ms"])


def primitive_ms(suite, depth, mtls, resume):
    kex_name, sig_name = (suite.split("|")[1], suite.split("|")[0])
    sig, kex = S.SIGS[sig_name], S.KEXS[kex_name]
    cost = kex.server_ms
    if not resume:
        cost += sig.sign_ms + ((depth + 1) * sig.verify_ms if mtls else 0.0)
    return cost


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--costs", choices=["x925", "x86"], default="x925", help="primitive costs of the machine the CSV was measured on")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    install(a.costs)
    rows = [r for r in csv.DictReader(open(a.csv)) if r["cpu_ms_per_hs"] != ""]
    out = []
    base = {(int(r["mtls"]), int(r["resume"]), int(r["depth"]), int(r["server_cores"])): float(r["cpu_ms_per_hs"]) for r in rows if r["suite"] == BASE}
    for r in rows:
        d, m, rs, c = int(r["depth"]), int(r["mtls"]), int(r["resume"]), int(r["server_cores"])
        cpu = float(r["cpu_ms_per_hs"])
        try:
            prim = primitive_ms(r["suite"], d, m, rs)
        except KeyError:
            prim = float("nan")
        b = base.get((m, rs, d, c)) or base.get((m, rs, 1, c))
        out.append(dict(machine=r["machine"], server=r["server"], suite=r["suite"], depth=d, mtls=m, resume=rs, cores=c, cpu_ms_per_hs=cpu,
                        primitive_ms=round(prim, 4), overhead=round(cpu / prim, 2) if prim == prim and prim > 0 else "",
                        hs_per_s_core=round(1000 / cpu, 0), vs_baseline=round(cpu / b, 2) if b else "", util=float(r["util"]),
                        p99_ms=r["p99_ms"], flag="CLIENT-LIMITED" if float(r["util"]) < 0.9 else ""))
    dst = a.out or a.csv.replace(".csv", "_summary.csv")
    with open(dst, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"{len(out)} rows -> {dst}")
    print(f"{'suite':28s} d mtls res  cpu_ms  prim_ms  ovh   hs/s/core  vs_base  util")
    for o in sorted(out, key=lambda o: (o["mtls"], o["resume"], o["depth"], o["cpu_ms_per_hs"])):
        print(f"{o['suite']:28s} {o['depth']} {o['mtls']:4d} {o['resume']:3d} {o['cpu_ms_per_hs']:7.3f} {o['primitive_ms']:8.4f} {str(o['overhead']):>5s} {o['hs_per_s_core']:9.0f} {str(o['vs_baseline']):>8s}  {o['util']:.2f} {o['flag']}")
    ov = [o["overhead"] for o in out if o["overhead"] != ""]
    if ov:
        print(f"overhead over the primitives: median {st.median(ov):.2f}, range {min(ov):.2f}-{max(ov):.2f}")


if __name__ == "__main__":
    main()
