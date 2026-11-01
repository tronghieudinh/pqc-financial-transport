#!/usr/bin/env python3
"""
supp_paper1_extra.py - two supplementary tables of paper 1 from measurements made after the main campaign.

    python3 supp_paper1_extra.py [--latex ../../paper]

Reads results/resume_summary.csv (analyze_resume.py) and results/capacity_gx10_summary.csv (analyze_capacity.py) and writes
    <latex>/tables/tab_ticket.tex       a full transaction that also issues a session ticket against the ticketless one of the main campaign
    <latex>/tables/tab_srvcpu.tex       CPU per handshake of an event-driven OpenSSL server against the primitive costs of the model
    <latex>/numbers_extra.tex           the numbers quoted in the text
Missing inputs are skipped (the macros are then defined as "n/a" so that the paper still compiles).
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics as st

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
SHORT = {"ECDSA-P256|X25519": "ECDSA-P256", "ECDSA-P256|X25519MLKEM768": "ECDSA-P256 + hybrid KEM", "RSA-2048|ECDHE-P256": "RSA-2048",
         "ML-DSA-44|ML-KEM-768": "ML-DSA-44", "ML-DSA-65|ML-KEM-768": "ML-DSA-65", "ML-DSA-87|ML-KEM-1024": "ML-DSA-87"}
NUMS = {}


def rd(name):
    p = os.path.join(RES, name)
    return list(csv.DictReader(open(p))) if os.path.exists(p) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--latex", default=os.path.join(HERE, "..", "..", "paper"))
    a = ap.parse_args()
    os.makedirs(os.path.join(a.latex, "tables"), exist_ok=True)
    f = float
    rs = rd("resume_summary.csv")
    if rs:
        ref = [r for r in rs if r["full_source"] == "ref" and r["req"] == "302"]
        d = [(f(r["prime_excess"]) - f(r["full_excess"]), r) for r in ref]
        slow = [x for x in d if x[0] > 3]
        NUMS["tickN"] = len(ref)
        NUMS["tickSlowN"] = len(slow)
        if slow:
            NUMS["tickSlowFrac"] = f"{st.median(x[0] / f(x[1]['rtt_ms']) for x in slow):.2f}"
        NUMS["tickMedDiff"] = f"{st.median(x[0] for x in d):.1f}"
        groups = {}
        for dif, r in d:
            groups.setdefault((r["suite"], int(r["depth"]), r["mtu"]), {})[f(r["rtt_ms"])] = (dif, f(r["full_excess"]), f(r["prime_excess"]))
        tex = ["\\begin{tabular}{@{}lrrrrrr@{}}", "\\toprule", "Suite & depth & MTU & \\multicolumn{3}{c}{ticket minus no ticket (ms) at RTT} & in RTT \\\\",
               "\\cmidrule(lr){4-6}", " & & & 5\\,ms & 30\\,ms & 100\\,ms & (30, 100\\,ms) \\\\", "\\midrule"]
        for (su, dep, mtu), g in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], int(kv[0][2]))):
            cells = [f"{g[r][0]:+.1f}" if r in g else "--" for r in (5.0, 30.0, 100.0)]
            fr = [g[r][0] / r for r in (30.0, 100.0) if r in g]
            tex.append(f"{SHORT.get(su, su)} & {dep} & {mtu} & " + " & ".join(cells) + f" & {st.mean(fr):+.2f} \\\\" if fr else f"{SHORT.get(su, su)} & {dep} & {mtu} & " + " & ".join(cells) + " & -- \\\\")
        tex += ["\\bottomrule", "\\end{tabular}"]
        open(os.path.join(a.latex, "tables", "tab_ticket.tex"), "w").write("\n".join(tex) + "\n")
    cs = rd("capacity_gx10_summary.csv")
    if cs:
        key = {(r["suite"], int(r["depth"]), int(r["mtls"]), int(r["resume"])): r for r in cs}
        cols = [("server auth, depth 2", 2, 0, 0), ("mutual TLS, depth 2", 2, 1, 0), ("resumed, mutual TLS", 1, 1, 1)]
        tex = ["\\begin{tabular}{@{}l" + "rrr" * len(cols) + "@{}}", "\\toprule", "Suite" + "".join(f" & \\multicolumn{{3}}{{c}}{{{c[0]}}}" for c in cols) + " \\\\",
               "".join(f"\\cmidrule(lr){{{2 + 3 * i}-{4 + 3 * i}}}" for i in range(len(cols))), " & measured & primitives & ratio" * len(cols) + " \\\\", "\\midrule"]
        for su in ("ECDSA-P256|X25519", "ECDSA-P256|X25519MLKEM768", "RSA-2048|ECDHE-P256", "ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768", "ML-DSA-87|ML-KEM-1024"):
            cells = []
            for _, dep, m, rs_ in cols:
                r = key.get((su, dep, m, rs_))
                cells += [f"{f(r['cpu_ms_per_hs']):.3f}", f"{f(r['primitive_ms']):.3f}", f"{f(r['overhead']):.1f}"] if r else ["--"] * 3
            tex.append(SHORT[su] + " & " + " & ".join(cells) + " \\\\")
        tex += ["\\bottomrule", "\\end{tabular}"]
        open(os.path.join(a.latex, "tables", "tab_srvcpu.tex"), "w").write("\n".join(tex) + "\n")
        full = [r for r in cs if r["resume"] == "0"]
        pq = [f(r["overhead"]) for r in full if r["suite"].split("|")[0] in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "RSA-2048")]
        ec = [f(r["overhead"]) for r in full if r["suite"].split("|")[0] == "ECDSA-P256"]
        NUMS["srvPqOvhMin"], NUMS["srvPqOvhMax"] = f"{min(pq):.2f}", f"{max(pq):.2f}"
        NUMS["srvEcOvhMin"], NUMS["srvEcOvhMax"] = f"{min(ec):.1f}", f"{max(ec):.1f}"
    for k in ("tickN", "tickSlowN", "tickSlowFrac", "tickMedDiff", "srvPqOvhMin", "srvPqOvhMax", "srvEcOvhMin", "srvEcOvhMax"):
        NUMS.setdefault(k, "n/a")
    with open(os.path.join(a.latex, "numbers_extra.tex"), "w") as fh:
        fh.write("% Generated by Measurements/testbed/supp_paper1_extra.py - do not edit\n")
        for k, v in NUMS.items():
            fh.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print({k: v for k, v in NUMS.items()})


if __name__ == "__main__":
    main()
