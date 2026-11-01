#!/usr/bin/env python3
"""
config_selector.py - which suite and mitigation to deploy where: Pareto front of latency, server CPU and wire bytes, against published budgets.

    python3 config_selector.py [--out config_selector.csv] [--capacity ../Measurements/testbed/results/capacity_gx10.csv]

Latency and bytes: the validated wired model (pqc_sim.py; Linux window validation, OpenSSL write pattern, pi = 0; TCP only, no loss).
Server CPU per transaction: MEASURED where capacity_test.py measured it (suite, mutual TLS, chain depth, full or resumed), else ESTIMATED as the
primitive costs of the model plus the fixed per-connection cost measured on the same machine (the intercept of measured minus primitive).
Mitigation states: cold TLS 1.3 connection, resumed connection (PSK), and for the server chain only the cached-chain and Merkle-tree
variants of the model (drafts; not validated, shown only where the model has them).

Budgets (the only thresholds used; none is set by us):
  OBIE  Open Banking UK, Operational Guidelines v3.1.4, "Availability and performance" (published 20 Dec 2019): recommended benchmark of an
        average time to last byte of 750 ms per endpoint response (payment initiation, all but file payments) and per response or page of up to
        100 records (account information). Whether the benchmark counts connection set-up is not stated: we apply it to a transaction that
        opens a new connection (the conservative reading).
  TIPS  ECB, "Focus Session: TIPS - how it meets your needs", 18 April 2023, slide "How fast is TIPS?": TIPS SLA 5 s, SCT Inst scheme target
        10 s, TIPS average latency below 100 ms; availability SLA 99.9 % (unplanned downtime up to 2.16 h per quarter). These bound the whole
        processing; we report the share of the 5 s that the transport of one message takes, not a pass/fail verdict.
  No public latency threshold was found for card authorisation (ISO 8583) or for SWIFT MX messages: those scenarios have no budget.
The output marks a configuration "within" when its latency is below the budget and ranks the Pareto-optimal ones; it is a screening tool for
the transport cost of authentication, not a statement about compliance of any institution.

Security classes. Latency, server CPU and bytes alone always favour the classical suite, so the front is computed WITHIN a class of equal
security goal: "classical" (ECDSA-P256, X25519), "PQ key exchange" (hybrid X25519MLKEM768, classical certificates) and "PQ authentication"
(ML-DSA-44/65, Falcon-512, composites; Falcon-512 is not yet standardised, FIPS 206 in development on 2026-10-31). The classical row is the
reference that the cost of each class is read against.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pqc_sim as S  # noqa: E402
import mitigations as M  # noqa: E402

PATHS = {"metro 100 Mbit/s 12 ms": (100.0, 12.0, 1500), "national 100 Mbit/s 30 ms": (100.0, 30.0, 1500),
         "international 100 Mbit/s 100 ms": (100.0, 100.0, 1500), "branch 10 Mbit/s 100 ms": (10.0, 100.0, 1500)}
BUDGETS = {  # scenario: (protocol, budget ms, source)
    "OBIE payment initiation (FAPI 2.0)": ("FAPI2", 750.0, "OBIE v3.1.4: average TTLB 750 ms per endpoint response"),
    "TIPS instant payment (ISO 20022 pacs.008)": ("ISO_20022", 5000.0, "ECB 2023-04-18: TIPS SLA 5 s (share reported)"),
    "SWIFT MX message (no public threshold)": ("SWIFT_MX", None, "none found"),
    "Card authorisation ISO 8583 (no public threshold)": ("ISO_8583", None, "none found"),
}
CLASS = {"ECDSA-P256|X25519": "classical", "ECDSA-P256|X25519MLKEM768": "PQ key exchange"}   # everything else: PQ authentication
NOT_STANDARDISED = ("Falcon-512",)
STATES = {"cold": ("cold", {}), "resumed": ("resumed", {}), "cached chain (model)": ("cold", {"cached_info": True}),
          "Merkle tree certs (model)": ("cold", {"mtc": True})}


def server_cpu_model(capacity_csv):
    """(measured table, fixed per-connection cost) from capacity_test.py output."""
    meas, ov = {}, []
    if capacity_csv and os.path.exists(capacity_csv):
        for r in csv.DictReader(open(capacity_csv)):
            if r["cpu_ms_per_hs"] == "":
                continue
            meas[(r["suite"], int(r["depth"]), int(r["mtls"]), int(r["resume"]))] = float(r["cpu_ms_per_hs"])
    return meas


def primitive_ms(suite, depth, mtls, resume):
    sig_name, kex_name = suite.split("|")[0], suite.split("|")[1]
    sig, kex = S.SIGS[sig_name], S.KEXS[kex_name]
    cost = kex.server_ms
    if not resume:
        cost += sig.sign_ms + ((depth + 1) * sig.verify_ms if mtls else 0.0)
    return cost


def pareto(rows, keys):
    out = []
    for i, r in enumerate(rows):
        dom = any(all(o[k] <= r[k] for k in keys) and any(o[k] < r[k] for k in keys) for j, o in enumerate(rows) if j != i)
        out.append(not dom)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "config_selector.csv"))
    ap.add_argument("--capacity", default=os.path.join(HERE, "..", "Measurements", "testbed", "results", "capacity_gx10.csv"))
    a = ap.parse_args()
    meas = server_cpu_model(a.capacity)
    # fixed per-connection cost: median of (measured - primitives) over the measured rows
    diffs = sorted(v - primitive_ms(k[0], k[1], k[2], k[3]) for k, v in meas.items() if k[0] in S.SIGS.keys() or True
                   if k[0].split("|")[0] in S.SIGS and k[0].split("|")[1] in S.KEXS)
    fixed = diffs[len(diffs) // 2] if diffs else 0.1
    rows = []
    for scen, (proto, budget, src) in BUDGETS.items():
        pr = S.PROTOCOLS[proto]
        for pname, (bw, rtt, mtu) in PATHS.items():
            cand = []
            for su in M.SUITES:
                for state, (mode, kw) in STATES.items():
                    f = S.build_flow(su, proto, pr.default_depth, mode, False, S.Model(**kw))
                    net = S.Net(bw, rtt, mtu, 0.0, 4, nst_early=True)   # Paper 2: the ticket is an earlier write (WP5 stage D)
                    res = S.run_flow(f, net)
                    resume = 1 if mode == "resumed" else 0
                    key = (su, 1 if resume else pr.default_depth, int(pr.mtls), resume)      # resumed rows were measured at depth 1 (the ticket carries the leaf)
                    cpu = meas.get(key)
                    est = cpu is None
                    if est:
                        cpu = primitive_ms(su, pr.default_depth, int(pr.mtls), resume) + fixed
                    cand.append(dict(scenario=scen, path=pname, suite=su, state=state, security=CLASS.get(su, "PQ authentication"),
                                     standardised=int(not su.startswith(NOT_STANDARDISED)), latency_ms=round(res["total"], 1),
                                     server_cpu_ms=round(cpu, 3), cpu_source="estimated" if est else "measured",
                                     wire_kb=round(res["wire"] / 1000, 1), budget_ms=budget if budget else "", budget_source=src,
                                     within_budget="" if budget is None else int(res["total"] <= budget),
                                     budget_share=round(res["total"] / budget, 3) if budget else ""))
            for cls in ("classical", "PQ key exchange", "PQ authentication"):
                for state in STATES:                                   # a resumed connection is not a substitute for a cold one: separate fronts
                    sub = [c for c in cand if c["security"] == cls and c["state"] == state]
                    std = [c for c in sub if c["standardised"]]
                    for c, on in zip(std, pareto(std, ("latency_ms", "server_cpu_ms", "wire_kb"))):
                        c["pareto"] = int(on)                          # among standardised schemes
                    for c, on in zip(sub, pareto(sub, ("latency_ms", "server_cpu_ms", "wire_kb"))):
                        c["pareto_if_falcon"] = int(on)                # if Falcon-512 were available
            rows += cand
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {a.out}; fixed per-connection server cost {fixed:.3f} ms ({len(meas)} measured capacity rows)")
    for scen in BUDGETS:
        for pname in ("national 100 Mbit/s 30 ms", "branch 10 Mbit/s 100 ms"):
            sel = [r for r in rows if r["scenario"] == scen and r["path"] == pname]
            ref = min((r for r in sel if r["security"] == "classical" and r["state"] == "cold"), key=lambda r: r["latency_ms"])
            hdr = f"\n{scen} | {pname} | classical cold reference {ref['latency_ms']:.1f} ms, server CPU {ref['server_cpu_ms']:.3f} ms"
            if sel[0]["budget_ms"] != "":
                bad = [r for r in sel if r["within_budget"] == 0]
                hdr += f" | budget {sel[0]['budget_ms']:.0f} ms: {len(sel) - len(bad)}/{len(sel)} within"
            print(hdr)
            for state in ("cold", "resumed"):
                front = sorted((r for r in sel if r["security"] == "PQ authentication" and r["state"] == state and r["standardised"] and r["pareto"]),
                               key=lambda r: r["latency_ms"])
                fal = [r for r in sel if r["security"] == "PQ authentication" and r["state"] == state and not r["standardised"] and r["pareto_if_falcon"]]
                for r in front:
                    print(f"   [PQ auth, {state:7s}] {r['suite'][:36]:36s} {r['latency_ms']:7.1f} ms  cpu {r['server_cpu_ms']:6.3f} ms ({r['cpu_source'][:4]})  {r['wire_kb']:6.1f} KB")
                for r in fal:
                    print(f"   [PQ auth, {state:7s}] {r['suite'][:36]:36s} {r['latency_ms']:7.1f} ms  cpu {r['server_cpu_ms']:6.3f} ms ({r['cpu_source'][:4]})  {r['wire_kb']:6.1f} KB  (Falcon-512, not standardised: on the front only if it were)")
            for r in [r for r in sel if r["within_budget"] == 0]:
                print(f"   OVER BUDGET: {r['suite'][:36]:36s} {r['state']:24s} {r['latency_ms']:7.1f} ms")

if __name__ == "__main__":
    main()
