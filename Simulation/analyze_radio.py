#!/usr/bin/env python3
"""
analyze_radio.py - tables and figures from radio_sim.py output.

    .venv/bin/python analyze_radio.py radio_results

Writes <dir>/report_radio.md and fig_radio_*.png.
Latencies are whole-transaction times (new TCP+TLS connection = `cold`, reused = `warm`)
seen by the terminal, including a fixed wired RTT between the RAN and the bank server.
"""
from __future__ import annotations

import argparse
import csv
import os

BASE = "ECDSA-P256|X25519"
SHOW = [BASE, "RSA-2048|ECDHE-P256", "ECDSA-P256|X25519MLKEM768", "ML-DSA-65|ML-KEM-768",
        "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]
FOCUS = [("FAPI2", "mobile open-banking (FAPI 2.0)"), ("ISO_8583", "POS / ATM card authorisation (ISO 8583)"),
         ("ISO_20022", "payment initiation over wireless (ISO 20022)")]
OUT = []


def emit(s=""):
    print(s)
    OUT.append(s)


def table(header, rows):
    emit("| " + " | ".join(str(h).replace("|", " + ") for h in header) + " |")
    emit("|" + "|".join((":---" if i == 0 else "---:") for i in range(len(header))) + "|")
    for r in rows:
        emit("| " + " | ".join(str(c).replace("|", " + ") for c in r) + " |")
    emit()


def load(path, floats):
    rows = []
    for r in csv.DictReader(open(path, newline="")):
        for k in floats:
            if k in r and r[k] != "":
                r[k] = float(r[k])
        rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    a = ap.parse_args()
    L = load(os.path.join(a.dir, "radio_links.csv"),
             ["sinr_db", "dl_mbps", "ul_mbps", "bler_first_tx", "tx_per_tb", "harq_fail", "blockage",
              "ran_rtt_floor_ms"])
    R = load(os.path.join(a.dir, "radio_results.csv"),
             ["sinr_db", "depth", "wired_rtt_ms", "mtu", "trials", "mean_ms", "std_ms", "p50_ms", "p95_ms",
              "p99_ms", "max_ms", "miss_200ms", "miss_500ms", "miss_1000ms", "retx_per_tb",
              "rlc_per_flow", "loss_per_flow", "dl_mbps", "ul_mbps", "cpu_ms", "l7_bytes", "segs"])
    profs = list(dict.fromkeys(r["profile"] for r in L))
    sinrs = sorted({r["sinr_db"] for r in L}, reverse=True)
    suites = list(dict.fromkeys(r["suite"] for r in R))
    trials = int(R[0]["trials"])
    idx = {(r["profile"], r["sinr_db"], r["suite"], r["protocol"], r["mode"]): r for r in R}
    li = {(r["profile"], r["sinr_db"]): r for r in L}
    wired = R[0]["wired_rtt_ms"]
    cdepth = int(next(r["depth"] for r in R if r["mode"] == "cold"))
    sh = lambda p: p.replace(" (assumed)", "*")
    sn = lambda s: f"{s:g} dB"

    def get(p, s, su, pr, mode="cold"):
        return idx[(p, s, su, pr, mode)]

    def matrix(title, fn, fmt="{:.0f}", note=""):
        emit(f"**{title}**")
        if note:
            emit(note)
        emit()
        table(["profile \\ SINR"] + [sn(s) for s in sinrs],
              [[sh(p)] + [fmt.format(fn(p, s)) for s in sinrs] for p in profs])

    emit("# PQC over 5G / 6G radio links with different noise levels")
    emit()
    emit(f"{len(R):,} configurations x {trials} Monte Carlo transactions. Wired RAN-to-server RTT = {wired:g} ms, "
         f"MTU {int(R[0]['mtu'])}, chain depth {cdepth} (cold). `*` = 6G profile built from ASSUMED IMT-2030-style "
         "targets, not measurements. Noise level = mean downlink SINR (uplink 4-10 dB lower, profile dependent).")
    emit()

    # ---------------------------------------------------------------- links
    emit("## Link behaviour vs noise")
    emit()
    emit("Per-user DL / UL rate (Mbps) after rank + MCS adaptation, load share and TDD split:")
    emit()
    table(["profile \\ SINR"] + [sn(s) for s in sinrs],
          [[sh(p)] + [f"{li[(p, s)]['dl_mbps']:.1f} / {li[(p, s)]['ul_mbps']:.1f}" for s in sinrs] for p in profs])
    emit("Mean transmissions per transport block (HARQ; 1.00 = no retransmissions) and probability that a TB "
         "exhausts all HARQ attempts (escalates to RLC ARQ):")
    emit()
    table(["profile \\ SINR"] + [sn(s) for s in sinrs],
          [[sh(p)] + [f"{li[(p, s)]['tx_per_tb']:.2f} / {li[(p, s)]['harq_fail']:.0e}" for s in sinrs] for p in profs])

    # ---------------------------------------------------------------- per protocol
    for pr, desc in FOCUS:
        emit(f"## {pr} - {desc}")
        emit()
        matrix(f"Mean latency (ms), `{BASE}` (deployed classical baseline), cold connection",
               lambda p, s: get(p, s, BASE, pr)["mean_ms"])
        for su in ("ECDSA-P256|X25519MLKEM768", "ML-DSA-65|ML-KEM-768", "Falcon-512|ML-KEM-768",
                   "SLH-DSA-128f|ML-KEM-768"):
            matrix(f"Mean-latency factor of `{su}` vs baseline (cold)",
                   lambda p, s, su=su: get(p, s, su, pr)["mean_ms"] / get(p, s, BASE, pr)["mean_ms"],
                   "{:.2f}x")
        emit("**P99 latency (ms), cold: baseline / ML-DSA-65**")
        emit()
        table(["profile \\ SINR"] + [sn(s) for s in sinrs],
              [[sh(p)] + [f"{get(p, s, BASE, pr)['p99_ms']:.0f} / {get(p, s, 'ML-DSA-65|ML-KEM-768', pr)['p99_ms']:.0f}"
                          for s in sinrs] for p in profs])
        for key, lab in (("miss_500ms", "500 ms"), ("miss_1000ms", "1 s")):
            emit(f"**Probability a cold transaction takes longer than {lab}: baseline -> ML-DSA-65**")
            emit()
            table(["profile \\ SINR"] + [sn(s) for s in sinrs],
                  [[sh(p)] + [f"{100 * get(p, s, BASE, pr)[key]:.0f}% -> "
                              f"{100 * get(p, s, 'ML-DSA-65|ML-KEM-768', pr)[key]:.0f}%" for s in sinrs] for p in profs])
        if ("warm" in {r["mode"] for r in R}):
            matrix(f"Warm (reused) connection: mean-latency factor of `ML-DSA-65|ML-KEM-768` vs baseline",
                   lambda p, s: get(p, s, "ML-DSA-65|ML-KEM-768", pr, "warm")["mean_ms"] /
                   get(p, s, BASE, pr, "warm")["mean_ms"], "{:.2f}x")

    # ---------------------------------------------------------------- SINR needed
    emit("## Noise tolerance: lowest SINR in the grid that keeps the P99 transaction time within an SLA")
    emit()
    emit("Cold connection, FAPI 2.0. `none` = SLA missed at every tested SINR; cells give the weakest SINR (most noise) "
         "that still meets it.")
    emit()
    for sla in (500.0, 1000.0):
        emit(f"**P99 <= {sla:g} ms**")
        emit()
        rows = []
        for su in suites:
            row = [su]
            for p in profs:
                ok = []
                for s in sinrs:                       # sinrs is sorted high -> low
                    if get(p, s, su, "FAPI2")["p99_ms"] > sla:
                        break                         # stop at the first violation
                    ok.append(s)
                row.append("none" if not ok else f"{min(ok):g} dB")
            rows.append(row)
        table(["suite"] + [sh(p) for p in profs], rows)

    # ---------------------------------------------------------------- 5G vs 6G head-to-head
    for s in (10.0, 0.0):
        if s not in sinrs:
            continue
        emit(f"## 5G vs 6G head-to-head at {s:g} dB SINR - cold FAPI 2.0, mean / P99 latency (ms)")
        emit()
        table(["suite"] + [sh(p) for p in profs],
              [[su] + [f"{get(p, s, su, 'FAPI2')['mean_ms']:.0f} / {get(p, s, su, 'FAPI2')['p99_ms']:.0f}" for p in profs]
               for su in suites])

    emit("## Radio-layer activity (FAPI 2.0, ML-DSA-65, cold)")
    emit()
    emit("HARQ retransmissions per transport block / RLC ARQ cycles per transaction / lost IP packets per transaction:")
    emit()
    table(["profile \\ SINR"] + [sn(s) for s in sinrs],
          [[sh(p)] + [f"{get(p, s, 'ML-DSA-65|ML-KEM-768', 'FAPI2')['retx_per_tb']:.2f} / "
                      f"{get(p, s, 'ML-DSA-65|ML-KEM-768', 'FAPI2')['rlc_per_flow']:.1f} / "
                      f"{get(p, s, 'ML-DSA-65|ML-KEM-768', 'FAPI2')['loss_per_flow']:.2f}" for s in sinrs] for p in profs])

    emit("## Monte Carlo accuracy")
    emit()
    emit(f"Each cell is {trials} independent transactions (paired random numbers across suites, so factors between "
         "suites are more accurate than the absolute values). Standard error of the mean latency over all configurations:")
    emit()
    rows = []
    for p in profs:
        se = sorted(r["std_ms"] / r["trials"] ** 0.5 for r in R if r["profile"] == p)
        rows.append([sh(p), f"{se[len(se) // 2]:.1f}", f"{se[int(.95 * (len(se) - 1))]:.1f}", f"{se[-1]:.1f}"])
    table(["profile", "median SE (ms)", "95th pct SE (ms)", "max SE (ms)"], rows)
    emit("Profiles with blockage (mmWave, sub-THz, FR3) have heavy tails: their P99 rests on a handful of samples and "
         "can be non-monotonic in SINR; treat differences of a few tens of ms there as noise, and rerun with "
         "`--trials 2000` for publication.")
    emit()

    with open(os.path.join(a.dir, "report_radio.md"), "w") as fh:
        fh.write("\n".join(OUT) + "\n")
    print(f"\n[analyze_radio] wrote {os.path.join(a.dir, 'report_radio.md')}")
    figures(a, profs, sinrs, get)


def figures(a, profs, sinrs, get):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[analyze_radio] matplotlib missing - no figures")
        return
    show = ["ECDSA-P256|X25519", "ML-DSA-65|ML-KEM-768", "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]
    xs = sorted(sinrs)
    fig, axs = plt.subplots(1, len(profs), figsize=(4.0 * len(profs), 4.4), sharey=True)
    for ax, p in zip(axs, profs):
        for i, su in enumerate(show):
            c = f"C{i}"
            ax.plot(xs, [get(p, s, su, "FAPI2")["mean_ms"] for s in xs], "-o", color=c, ms=3, label=su + " mean")
            ax.plot(xs, [get(p, s, su, "FAPI2")["p99_ms"] for s in xs], "--", color=c, alpha=.7)
        ax.set_yscale("log")
        ax.set_title(p.replace(" (assumed)", "*"), fontsize=9)
        ax.set_xlabel("mean DL SINR (dB)  <- more noise")
        ax.grid(alpha=.3, which="both")
    axs[0].set_ylabel("FAPI 2.0 transaction latency (ms), solid = mean, dashed = P99")
    axs[0].legend(fontsize=6)
    fig.tight_layout()
    fig.savefig(os.path.join(a.dir, "fig_radio_latency.png"), dpi=140)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 4))
    data = [[get(p, s, "ML-DSA-65|ML-KEM-768", "FAPI2")["mean_ms"] / get(p, s, "ECDSA-P256|X25519", "FAPI2")["mean_ms"]
             for s in sorted(sinrs, reverse=True)] for p in profs]
    im = ax.imshow(data, cmap="YlOrRd", aspect="auto")
    ax.set_xticks(range(len(sinrs)), [f"{s:g}" for s in sorted(sinrs, reverse=True)])
    ax.set_yticks(range(len(profs)), [p.replace(" (assumed)", "*") for p in profs], fontsize=8)
    for i, row in enumerate(data):
        for j, v in enumerate(row):
            ax.text(j, i, f"{v:.1f}x", ha="center", va="center", fontsize=7)
    ax.set_xlabel("mean DL SINR (dB)")
    fig.colorbar(im, label="mean latency ML-DSA-65 / classical baseline")
    ax.set_title("PQC latency factor vs noise (cold FAPI 2.0)")
    fig.tight_layout()
    fig.savefig(os.path.join(a.dir, "fig_radio_factor.png"), dpi=140)
    plt.close(fig)
    print(f"[analyze_radio] wrote figures to {a.dir}/")


if __name__ == "__main__":
    main()
