#!/usr/bin/env python3
"""
app_records_effect.py - how much would the model outputs of Paper 1 change if application messages above one TLS record were written as one
write() per record? (Paper 1, appendix "Application messages above one TLS record")

    python3 app_records_effect.py [--out app_records_effect.csv] [--examples app_records_examples.csv]

The model of Paper 1 treats each application message (request or response) as one write. OpenSSL SSL_write() sends a message above
TLS_REC_MAX = 16,384 bytes as one record per 16 KB, and with TCP_NODELAY a record boundary can leave a partial segment at once.
Model(app_records=True) represents this (record_writes()); it is OFF in every Paper 1 result. No Paper 1 measurement used a message above
one record (302/222-byte and 10.9/3.6 KiB transactions), so the variant is not validated there.

Grid of the main sweep with pi = 0: 13 suites x 6 profiles x depth 1-4 (cold; one state for warm) x 6 bit rates x 5 RTTs x 3 MTUs, CPU scale 1,
initial and reused window 10. Per suite and mode: the number of flows whose write list differs, the grid rows in which the latency changes by more
than 0.5 ms, the largest change, and the share phi of rows with O > T_cpu (O = ser + ssw + pen) with and without the variant.
The second file lists the reference scenario (SWIFT MX, 100 Mbit/s, 30 ms, MTU 1500, depth 1-4) for every suite whose flows differ.
"""
import argparse, csv, dataclasses, os
import pqc_sim as ps

HERE = os.path.dirname(os.path.abspath(__file__))
BW, RTT, MTU = (10, 100, 200, 400, 800, 1600), (5, 12, 30, 50, 100), (1280, 1500, 9000)
THRESH_MS = 0.5

def run(flow, bw, rtt, mtu):
    return ps.run_flow(flow, ps.Net(float(bw), float(rtt), mtu, 0.0, 4, 10, 10), 1.0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "app_records_effect.csv"))
    ap.add_argument("--examples", default=os.path.join(HERE, "app_records_examples.csv"))
    a = ap.parse_args()
    base = ps.Model()
    alt = dataclasses.replace(base, app_records=True)
    rows, ex = [["suite", "mode", "flows", "flows_changed", "grid_rows", "rows_change_gt_0.5ms", "max_abs_change_ms",
                 "phi_base_pct", "phi_variant_pct"]], [["suite", "depth", "latency_base_ms", "latency_variant_ms", "change_ms"]]
    for su in ps.SUITES:
        for mode in ("cold", "warm"):
            nfl = nchg = nrow = ngt = 0
            mx = 0.0
            ob = oa = 0
            for pr in ps.PROTOCOLS:
                for d in ((1, 2, 3, 4) if mode == "cold" else (0,)):
                    fb = ps.build_flow(su, pr, d, mode, False, base)
                    fa = ps.build_flow(su, pr, d, mode, False, alt)
                    same = fb == fa
                    nfl += 1
                    nchg += not same
                    for bw in BW:
                        for rtt in RTT:
                            for mtu in MTU:
                                rb = run(fb, bw, rtt, mtu)
                                ra = rb if same else run(fa, bw, rtt, mtu)
                                nrow += 1
                                df = abs(ra["total"] - rb["total"])
                                ngt += df > THRESH_MS
                                mx = max(mx, df)
                                ob += rb["ser"] + rb["ssw"] + rb["pen"] > rb["cpu"]
                                oa += ra["ser"] + ra["ssw"] + ra["pen"] > ra["cpu"]
            rows.append([su, mode, nfl, nchg, nrow, ngt, f"{mx:.1f}", f"{100 * ob / nrow:.1f}", f"{100 * oa / nrow:.1f}"])
            print(*rows[-1], sep="\t")
    for su in ps.SUITES:
        for d in (1, 2, 3, 4):
            fb = ps.build_flow(su, "SWIFT_MX", d, "cold", False, base)
            fa = ps.build_flow(su, "SWIFT_MX", d, "cold", False, alt)
            if fb != fa:
                tb, ta = run(fb, 100, 30, 1500)["total"], run(fa, 100, 30, 1500)["total"]
                ex.append([su, d, f"{tb:.1f}", f"{ta:.1f}", f"{ta - tb:+.1f}"])
    csv.writer(open(a.out, "w", newline="")).writerows(rows)
    csv.writer(open(a.examples, "w", newline="")).writerows(ex)

if __name__ == "__main__":
    main()
