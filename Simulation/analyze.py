#!/usr/bin/env python3
"""
analyze.py - answers the four research questions from pqc_sim.py output.

    python3 analyze.py results [--thr results_thr]

Writes <dir>/report.md (tables), and <dir>/fig_*.png if matplotlib is present.
Reference operating point for single-point tables (override with --bw/--rtt/--mtu/--pen):
100 Mbps, 30 ms RTT, MTU 1500, penalty 6 ms, threshold 4 segments.
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics as st
from collections import defaultdict

NUM = {"depth", "bw_mbps", "rtt_ms", "mtu", "penalty_ms", "thr", "total_ms", "cpu_ms", "ser_ms",
       "prop_ms", "ssw_ms", "pen_ms", "segs", "wire_bytes", "max_flight", "pen_flights",
       "l7_bytes", "tls_cert_bytes", "obj_alg_bytes", "cc_total_ms", "cc_saved_ms",
       "cc_cert_bytes", "decomp_kb_cli", "decomp_kb_srv", "break_even_ms_per_kb"}
PROFILES = ["server-class", "phone/laptop", "embedded", "very-slow"]
BASE = "ECDSA-P256|X25519"
SCALES = (1, 4, 16)           # CPU multipliers: server core, HSM-class, constrained device
MATERIAL_MS = 1.0             # "materially reduces latency" threshold for RQ4

OUT = []


def emit(s=""):
    print(s)
    OUT.append(s)


def table(header, rows, align=None):
    emit("| " + " | ".join(str(h).replace("|", " + ") for h in header) + " |")
    emit("|" + "|".join((":---" if i == 0 else "---:") for i in range(len(header))) + "|")
    for r in rows:
        emit("| " + " | ".join(str(c).replace("|", " + ") for c in r) + " |")
    emit()


def load(path):
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            for k in NUM:
                v = r.get(k, "")
                r[k] = float(v) if v != "" else None
            for p in PROFILES:
                v = r.get(f"cc_net_{p}", "")
                r[f"cc_net_{p}"] = float(v) if v != "" else None
            rows.append(r)
    return rows


def f1(x):
    return f"{x:,.1f}"


def pct(x):
    return f"{100 * x:.0f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--thr", default=None, help="dir of a threshold-sweep run (optional)")
    ap.add_argument("--bw", type=float, default=100.0)
    ap.add_argument("--rtt", type=float, default=30.0)
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--pen", type=float, default=6.0)
    a = ap.parse_args()

    R = load(os.path.join(a.dir, "results.csv"))
    SZ = list(csv.DictReader(open(os.path.join(a.dir, "sizes.csv"))))
    suites = list(dict.fromkeys(r["suite"] for r in R))
    protos = list(dict.fromkeys(r["protocol"] for r in R))
    idx = {}
    for r in R:
        idx[(r["suite"], r["protocol"], r["mode"], int(r["depth"]), r["bw_mbps"], r["rtt_ms"],
             int(r["mtu"]), r["penalty_ms"], int(r["thr"]))] = r
    cold = [r for r in R if r["mode"] == "cold"]

    def at(s, p, d, bw=a.bw, rtt=a.rtt, mtu=a.mtu, pen=a.pen, thr=4, mode="cold"):
        return idx[(s, p, mode, 0 if mode == "warm" else d, float(bw), float(rtt), int(mtu), float(pen), thr)]

    emit("# PQC vs classical cryptography in financial messaging - simulation report")
    emit()
    emit(f"{len(R):,} configurations ({len(cold):,} cold-connection, {len(R) - len(cold):,} warm). "
         f"Single-point tables use {a.bw:g} Mbps, {a.rtt:g} ms RTT, MTU {a.mtu}, "
         f"transport penalty {a.pen:g} ms, threshold 4 segments. `cold` = new TCP+TLS 1.3 "
         f"connection per transaction; `warm` = reused connection. Baseline = `{BASE}`.")
    emit()

    # ------------------------------------------------------------------ RQ1
    emit("## RQ1 - Serialized size of a transaction plus its certificate chain")
    emit()
    emit("Application-layer bytes of one complete cold transaction (TLS handshake incl. "
         "certificate chain(s) + all protocol messages + signatures/keys + TLS record framing), "
         "at each protocol's reference chain depth. Factor is relative to the baseline.")
    emit()
    szi = {(r["suite"], r["protocol"], int(r["depth"]), int(r["cc"])): r for r in SZ}
    pdepth = {"ISO_8583": 2, "ISO_20022": 2, "SWIFT_MX": 3, "OAUTH2_RFC6749": 2, "OIDC": 2, "FAPI2": 2}
    hdr = ["suite"] + [f"{p} (d={pdepth[p]})" for p in protos]
    rows = []
    for s in suites:
        row = [s]
        for p in protos:
            t = int(szi[(s, p, pdepth[p], 0)]["total_l7"])
            b = int(szi[(BASE, p, pdepth[p], 0)]["total_l7"])
            row.append(f"{t / 1024:.1f} KB ({t / b:.1f}x)")
        rows.append(row)
    table(hdr, rows)

    emit("### Where the extra bytes come from - SWIFT MX, chain depth 3 (KB)")
    emit()
    cols = ["payload_fixed", "obj_alg", "tls_cert", "tls_cv", "tls_kex", "tls_other", "total_l7"]
    names = ["protocol payload", "app sigs/keys/certs", "TLS cert chains", "TLS CertVerify",
             "TLS key shares", "TLS other+records", "total"]
    rows = [[s] + [f"{int(szi[(s, 'SWIFT_MX', 3, 0)][c]) / 1024:.1f}" for c in cols] for s in suites]
    table(["suite"] + names, rows)

    emit("### Growth with chain depth - ISO 20022 (total KB; TCP segments at MTU 1280 / 1500 / 9000)")
    emit()
    rows = []
    for s in suites:
        rows.append([s] + [f"{int(szi[(s, 'ISO_20022', d, 0)]['total_l7']) / 1024:.1f}" for d in (1, 2, 3, 4)] +
                    [f"{szi[(s, 'ISO_20022', 4, 0)]['segs_' + m]}" for m in ("1280", "1500", "9000")])
    table(["suite", "d=1", "d=2", "d=3", "d=4", "segs@1280 (d=4)", "segs@1500 (d=4)", "segs@9000 (d=4)"], rows)

    emit("### Warm connections (no handshake, no certificates)")
    emit()
    rows = []
    for s in suites:
        row = [s]
        for p in protos:
            r = at(s, p, 0, mode="warm")
            b = at(BASE, p, 0, mode="warm")
            row.append(f"{int(r['l7_bytes']) / 1024:.1f} KB ({r['l7_bytes'] / b['l7_bytes']:.1f}x)")
        rows.append(row)
    table(["suite"] + protos, rows)

    # ------------------------------------------------------------------ RQ2
    emit("## RQ2 - Chain depth x TCP segmentation x transport threshold")
    emit()
    P = "SWIFT_MX"
    emit(f"### End-to-end latency (ms) vs chain depth - {P}, cold, reference network")
    emit()
    rows = []
    for s in suites:
        lat = [at(s, P, d) for d in (1, 2, 3, 4)]
        rows.append([s] + [f1(x["total_ms"]) for x in lat] +
                    [f"{int(lat[0]['max_flight'])}->{int(lat[3]['max_flight'])}",
                     f1(lat[3]["total_ms"] - lat[0]["total_ms"])])
    table(["suite", "d=1", "d=2", "d=3", "d=4", "largest flight (segs) d1->d4", "d4-d1 (ms)"], rows)

    emit("### Decomposition of the d=1 -> d=4 increase (ms)")
    emit()
    rows = []
    for s in suites:
        x1, x4 = at(s, P, 1), at(s, P, 4)
        rows.append([s] + [f1(x4[c] - x1[c]) for c in ("cpu_ms", "ser_ms", "ssw_ms", "pen_ms")] +
                    [f1(x4["total_ms"] - x1["total_ms"])])
    table(["suite", "cpu", "serialization", "slow-start wait (extra RTTs)", "transport penalty", "total"], rows)

    ml = "ML-DSA-65|ML-KEM-768"
    emit(f"### Interaction: added latency per extra certificate, `{ml}` / {P} (ms per cert = (d4-d1)/3)")
    emit()
    emit(f"MTU x transport penalty (reference bandwidth {a.bw:g} Mbps, RTT {a.rtt:g} ms):")
    emit()
    pens = (0.0, 3.0, 6.0, 12.0, 24.0)
    rows = [[mtu] + [f1((at(ml, P, 4, mtu=mtu, pen=p)["total_ms"] - at(ml, P, 1, mtu=mtu, pen=p)["total_ms"]) / 3)
                     for p in pens] for mtu in (1280, 1500, 9000)]
    table(["MTU \\ penalty (ms)"] + [f"{p:g}" for p in pens], rows)
    emit(f"MTU x RTT (penalty {a.pen:g} ms):")
    emit()
    rtts = (5.0, 12.0, 30.0, 50.0, 100.0)
    rows = [[mtu] + [f1((at(ml, P, 4, mtu=mtu, rtt=r)["total_ms"] - at(ml, P, 1, mtu=mtu, rtt=r)["total_ms"]) / 3)
                     for r in rtts] for mtu in (1280, 1500, 9000)]
    table(["MTU \\ RTT (ms)"] + [f"{r:g}" for r in rtts], rows)

    emit("### First chain depth that costs an extra slow-start round trip")
    emit()
    emit(f"{P}, cold, penalty 0, RTT {a.rtt:g} ms: smallest depth whose slow-start wait is >= RTT/2 "
         "(a flight no longer fits in the congestion window). `-` = never within depth 1-4; "
         "`<=1` = already at depth 1.")
    emit()
    rows = []
    for s in suites:
        row = [s]
        for mtu in (1280, 1500, 9000):
            dd = [d for d in (1, 2, 3, 4) if at(s, P, d, mtu=mtu, pen=0)["ssw_ms"] >= a.rtt / 2]
            row.append("-" if not dd else ("<=1" if dd[0] == 1 else str(dd[0])))
        rows.append(row)
    table(["suite", "MTU 1280", "MTU 1500", "MTU 9000"], rows)

    if a.thr and os.path.exists(os.path.join(a.thr, "results.csv")):
        T = load(os.path.join(a.thr, "results.csv"))
        emit(f"### Transport-threshold sensitivity - `{ml}`, {P}, cold (latency ms; penalty from the run)")
        emit()
        ti = {(r["suite"], r["protocol"], r["mode"], int(r["depth"]), int(r["mtu"]), int(r["thr"]),
               r["penalty_ms"]): r for r in T}
        thrs = sorted({int(r["thr"]) for r in T})
        pe = max({r["penalty_ms"] for r in T})
        rows = []
        for mtu in (1280, 1500, 9000):
            for d in (1, 2, 3, 4):
                rows.append([mtu, d] + [f1(ti[(ml, P, "cold", d, mtu, t, pe)]["total_ms"]) for t in thrs])
        table(["MTU", "depth"] + [f"thr={t}" for t in thrs], rows)

    # ------------------------------------------------------------------ RQ3
    emit("## RQ3 - When does transport/serialization outweigh cryptographic execution?")
    emit()
    emit("size-dependent transport overhead = serialization + slow-start wait + transport penalty "
         "(fixed handshake RTTs excluded; they are identical for every algorithm). "
         "Crypto = CPU time of all signatures, verifications and KEM operations on the critical path. "
         "CPU scale x1 = server core, x4 = HSM-class, x16 = constrained device.")
    emit()
    emit("### Share of cold configurations where overhead > crypto")
    emit()
    rows = []
    for s in suites:
        sub = [r for r in cold if r["suite"] == s]
        row = [s]
        for k in SCALES:
            row.append(pct(sum((r["ser_ms"] + r["ssw_ms"] + r["pen_ms"]) > k * r["cpu_ms"] for r in sub) / len(sub)))
        row.append(f1(st.median((r["ser_ms"] + r["ssw_ms"] + r["pen_ms"]) / r["cpu_ms"] for r in sub)))
        rows.append(row)
    table(["suite", "CPU x1", "CPU x4", "CPU x16", "median overhead/crypto (x1)"], rows)

    emit("### Share where overhead > crypto, by bandwidth (CPU x1, cold)")
    emit()
    bws = sorted({r["bw_mbps"] for r in cold})
    rows = []
    for s in suites:
        row = [s]
        for bw in bws:
            sub = [r for r in cold if r["suite"] == s and r["bw_mbps"] == bw]
            row.append(pct(sum((r["ser_ms"] + r["ssw_ms"] + r["pen_ms"]) > r["cpu_ms"] for r in sub) / len(sub)))
        rows.append(row)
    table(["suite"] + [f"{b:g} Mbps" for b in bws], rows)

    emit(f"### Overhead / crypto ratio by bandwidth - {P}, d=3, RTT {a.rtt:g} ms, MTU {a.mtu}, penalty {a.pen:g} ms (CPU x1)")
    emit()
    emit("Values > 1 mean transport/serialization costs more than cryptography.")
    emit()
    rows = []
    for s in suites:
        row = [s]
        for bw in bws:
            r = at(s, P, 3, bw=bw)
            row.append(f"{(r['ser_ms'] + r['ssw_ms'] + r['pen_ms']) / r['cpu_ms']:.1f}")
        rows.append(row)
    table(["suite"] + [f"{b:g} Mbps" for b in bws], rows)

    emit("### Incremental view vs baseline: share of configs where added overhead > added crypto (cold, CPU x1)")
    emit()
    rows = []
    for s in suites:
        if s == BASE:
            continue
        n = w = 0
        dov, dcp = [], []
        for r in cold:
            if r["suite"] != s:
                continue
            b = idx[(BASE, r["protocol"], "cold", int(r["depth"]), r["bw_mbps"], r["rtt_ms"],
                     int(r["mtu"]), r["penalty_ms"], int(r["thr"]))]
            o = (r["ser_ms"] + r["ssw_ms"] + r["pen_ms"]) - (b["ser_ms"] + b["ssw_ms"] + b["pen_ms"])
            c = r["cpu_ms"] - b["cpu_ms"]
            n += 1
            w += o > c
            dov.append(o)
            dcp.append(c)
        rows.append([s, pct(w / n), f1(st.median(dov)), f1(st.median(dcp))])
    table(["suite", "added overhead > added crypto", "median added overhead (ms)", "median added crypto (ms)"], rows)

    emit("### Warm connections - total latency penalty vs baseline (ms, reference network)")
    emit()
    rows = []
    for s in suites:
        rows.append([s] + [f1(at(s, p, 0, mode="warm")["total_ms"] - at(BASE, p, 0, mode="warm")["total_ms"]) for p in protos])
    table(["suite"] + protos, rows)

    # ------------------------------------------------------------------ RQ4
    emit("## RQ4 - Certificate compression (RFC 8879)")
    emit()
    emit(f"Latency saved by compressing the Certificate message(s), before decompression cost. "
         f"'Material' = saves >= {MATERIAL_MS:g} ms. Net = saved - decompression - compression cost "
         f"(client decompress speed per profile: " +
         ", ".join(f"{k} {v} ms/KB" for k, v in
                   {"server-class": 0.003, "phone/laptop": 0.03, "embedded": 0.3, "very-slow": 3.0}.items()) + ").")
    emit()
    rows = []
    for s in suites:
        sub = [r for r in cold if r["suite"] == s]
        red = st.mean(1 - r["cc_cert_bytes"] / r["tls_cert_bytes"] for r in sub if r["tls_cert_bytes"])
        sv = [r["cc_saved_ms"] for r in sub]
        sr = [r["cc_saved_ms"] / r["rtt_ms"] for r in sub]
        rows.append([s, pct(red), pct(sum(x >= MATERIAL_MS for x in sv) / len(sv)),
                     f1(st.median(sv)), f"{max(sr):.2f}"])
    table(["suite", "cert bytes saved (mean)", "configs w/ material gain", "median saved (ms)",
           "max saved / RTT"], rows)

    emit("### Share of configurations where compression is net-harmful (net <= -1 ms) / net-beneficial (net >= +1 ms)")
    emit()
    rows = []
    for s in suites:
        sub = [r for r in cold if r["suite"] == s]
        row = [s]
        for p in PROFILES:
            v = [r[f"cc_net_{p}"] for r in sub]
            row.append(f"{pct(sum(x <= -1 for x in v) / len(v))} / {pct(sum(x >= 1 for x in v) / len(v))}")
        rows.append(row)
    table(["suite (harmful / beneficial)"] + PROFILES, rows)

    emit(f"### Break-even client decompression cost (ms per KB inflated), configurations with a material saving (>= {MATERIAL_MS:g} ms)")
    emit()
    rows = []
    for s in suites:
        v = sorted(r["break_even_ms_per_kb"] for r in cold if r["suite"] == s and r["cc_saved_ms"] >= MATERIAL_MS
                   and r["break_even_ms_per_kb"] is not None)
        if v:
            rows.append([s, len(v), f"{v[len(v) // 10]:.3f}", f"{st.median(v):.3f}", f"{v[(9 * len(v)) // 10]:.3f}"])
        else:
            rows.append([s, 0, "-", "-", "-"])
    table(["suite", "configs", "10th pct", "median", "90th pct"], rows)

    for s in ("RSA-2048|ECDHE-P256", ml):
        emit(f"### Latency saved (ms) by compression - `{s}`, {P}, d=4, MTU {a.mtu}, penalty {a.pen:g} ms")
        emit()
        rows = [[f"{bw:g} Mbps"] + [f1(at(s, P, 4, bw=bw, rtt=r)["cc_saved_ms"]) for r in rtts] for bw in bws]
        table(["bandwidth \\ RTT (ms)"] + [f"{r:g}" for r in rtts], rows)

    emit("### Saved ms by MTU - median over bandwidth, RTT and penalty; d=4, SWIFT MX")
    emit()
    rows = []
    for s in suites:
        row = [s]
        for mtu in (1280, 1500, 9000):
            row.append(f1(st.median(r["cc_saved_ms"] for r in cold if r["suite"] == s and r["protocol"] == P
                                    and r["mtu"] == mtu and r["depth"] == 4)))
        rows.append(row)
    table(["suite", "MTU 1280", "MTU 1500", "MTU 9000"], rows)

    os.makedirs(a.dir, exist_ok=True)
    with open(os.path.join(a.dir, "report.md"), "w") as fh:
        fh.write("\n".join(OUT) + "\n")
    print(f"\n[analyze] wrote {os.path.join(a.dir, 'report.md')}")
    figures(a, R, cold, suites, idx, at, P, ml, bws, rtts)


def figures(a, R, cold, suites, idx, at, P, ml, bws, rtts):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[analyze] matplotlib not installed - skipping figures")
        return
    # Fig 1: latency vs depth, one panel per MTU
    show = [BASE, "RSA-2048|ECDHE-P256", "ML-DSA-65|ML-KEM-768", "Falcon-512|ML-KEM-768",
            "SLH-DSA-128f|ML-KEM-768"]
    fig, axs = plt.subplots(1, 3, figsize=(15, 4.6), sharey=True)
    for ax, mtu in zip(axs, (1280, 1500, 9000)):
        for s in show:
            ax.plot((1, 2, 3, 4), [at(s, P, d, mtu=mtu)["total_ms"] for d in (1, 2, 3, 4)], marker="o", label=s)
        ax.set_title(f"MTU {mtu}")
        ax.set_xlabel("certificate chain depth")
        ax.set_xticks((1, 2, 3, 4))
        ax.grid(alpha=.3)
    axs[0].set_ylabel(f"{P} latency (ms)")
    axs[0].legend(fontsize=8)
    fig.suptitle(f"RQ2: latency vs chain depth ({a.bw:g} Mbps, {a.rtt:g} ms RTT, penalty {a.pen:g} ms)")
    fig.tight_layout()
    fig.savefig(os.path.join(a.dir, "fig_rq2_depth.png"), dpi=140)
    plt.close(fig)
    # Fig 2: overhead / crypto heatmap
    fig, ax = plt.subplots(figsize=(8, 5.5))
    import math
    data = [[math.log10(max(1e-3, (at(s, P, 3, bw=b)["ser_ms"] + at(s, P, 3, bw=b)["ssw_ms"] + at(s, P, 3, bw=b)["pen_ms"])
                           / at(s, P, 3, bw=b)["cpu_ms"])) for b in bws] for s in suites]
    im = ax.imshow(data, cmap="RdBu_r", vmin=-2, vmax=2, aspect="auto")
    ax.set_xticks(range(len(bws)), [f"{b:g}" for b in bws])
    ax.set_yticks(range(len(suites)), suites, fontsize=8)
    ax.set_xlabel("bandwidth (Mbps)")
    for i, row in enumerate(data):
        for j, v in enumerate(row):
            ax.text(j, i, f"{10 ** v:.1f}", ha="center", va="center", fontsize=7)
    fig.colorbar(im, label="log10(transport overhead / crypto time)")
    ax.set_title(f"RQ3: transport/crypto ratio, {P}, d=3 (red > 1: transport dominates)")
    fig.tight_layout()
    fig.savefig(os.path.join(a.dir, "fig_rq3_ratio.png"), dpi=140)
    plt.close(fig)
    # Fig 3: compression saving vs net per profile
    fig, axs = plt.subplots(1, 2, figsize=(13, 4.6))
    sub = [s for s in suites if s != "SLH-DSA-128s|ML-KEM-768"]
    for ax, key, ttl in ((axs[0], "cc_saved_ms", "latency saved before decompression (ms)"),
                         (axs[1], None, "share of configs net-harmful (net <= -1 ms)")):
        if key:
            vals = [[r[key] for r in cold if r["suite"] == s] for s in sub]
            ax.boxplot(vals, showfliers=False)
            ax.set_xticks(range(1, len(sub) + 1), [s.split("|")[0] for s in sub])
            ax.set_yscale("symlog", linthresh=1)
        else:
            w = 0.2
            for k, p in enumerate(PROFILES):
                ax.bar([i + k * w for i in range(len(sub))],
                       [sum(r[f"cc_net_{p}"] <= -1 for r in cold if r["suite"] == s) /
                        sum(1 for r in cold if r["suite"] == s) for s in sub], w, label=p)
            ax.set_xticks([i + 1.5 * w for i in range(len(sub))], [s.split("|")[0] for s in sub])
            ax.legend(fontsize=8)
        ax.tick_params(axis="x", rotation=60, labelsize=8)
        ax.set_title(ttl)
        ax.grid(alpha=.3)
    fig.suptitle("RQ4: certificate compression (cold connections, full grid)")
    fig.tight_layout()
    fig.savefig(os.path.join(a.dir, "fig_rq4_compression.png"), dpi=140)
    plt.close(fig)
    print(f"[analyze] wrote figures to {a.dir}/")


if __name__ == "__main__":
    main()
