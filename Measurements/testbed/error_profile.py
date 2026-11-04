#!/usr/bin/env python3
"""
error_profile.py - the numbers of the paragraphs "What the error measures" and "Scope at an MTU of 9000 bytes" of Paper 1 (Section 4.4), from the table of configurations.

    python3 error_profile.py [--csv ../../manuscript/data/testbed_configurations.csv] > results/error_profile.txt

The table has one row per configuration (the direct path, Reno, no configured loss): excess_ms (measured), model_ms (idealized model), model_stack_ms (stack model), rtt_ms, mtu, suite.
"idealized wrong in the round-trip steps" = absolute error above half an RTT and above 5 ms; the same test is applied to the stack model.
"""
import argparse, csv, os, statistics as st
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--csv", default=os.path.join(HERE, "..", "..", "manuscript", "data", "testbed_configurations.csv")); a = ap.parse_args()
    rows = [r for r in csv.DictReader(open(a.csv)) if r["topology"] == "direct" and r["cc"] == "reno" and float(r["loss_pct"]) == 0 and r["net_id"] == "shaped"]
    f = lambda r, k: float(r[k])
    print(f"{len(rows)} configurations (direct, Reno, no loss, shaped)")
    ei = [abs(f(r, "model_ms") - f(r, "excess_ms")) for r in rows]; es = [abs(f(r, "model_stack_ms") - f(r, "excess_ms")) for r in rows]
    half = [0.5 * f(r, "rtt_ms") for r in rows]
    wi = [i for i in range(len(rows)) if ei[i] > half[i] and ei[i] > 5]; ws = [i for i in range(len(rows)) if es[i] > half[i] and es[i] > 5]
    print(f"idealized: error > 0.5 RTT and > 5 ms in {len(wi)}; errors {min(ei[i] for i in wi):.0f} to {max(ei[i] for i in wi):.0f} ms" if wi else "idealized: none")
    print(f"stack: same test in {len(ws)}; largest error {max(es):.1f} ms; configurations above 5 ms: {sum(e > 5 for e in es)}; above 10 ms: {sum(e > 10 for e in es)}")
    q = [i for i in range(len(rows)) if es[i] > 0.4 * f(rows[i], "rtt_ms")]
    print(f"stack: errors above 0.4 RTT: {len(q)}; their RTTs: {sorted({f(rows[i], 'rtt_ms') for i in q})}")
    print(f"stack within 1 ms: {sum(e <= 1 for e in es)} of {len(rows)}; inside the measurement interval: {sum(int(r['stack_in_ci']) for r in rows)}")
    by = {}
    for r, e in zip(rows, es): by.setdefault(r["suite"], []).append(e)
    m = {k: st.mean(v) for k, v in by.items()}
    print(f"MAE by suite: min {min(m.values()):.2f}, max {max(m.values()):.2f} ms  ({', '.join(f'{k.split(chr(124))[0]} {v:.2f}' for k, v in sorted(m.items()))})")
    print("\nby MTU: configurations, MAE stack, MAE idealized")
    for mtu in (1280, 1500, 9000):
        g = [i for i, r in enumerate(rows) if int(r["mtu"]) == mtu]
        print(f"  {mtu}: {len(g)}  {st.mean(es[i] for i in g):.2f}  {st.mean(ei[i] for i in g):.2f}")
    g = [i for i, r in enumerate(rows) if int(r["mtu"]) in (1280, 1500)]
    print(f"MTU 1280 and 1500: {len(g)} configurations, MAE stack {st.mean(es[i] for i in g):.2f} ms")

if __name__ == "__main__":
    main()
