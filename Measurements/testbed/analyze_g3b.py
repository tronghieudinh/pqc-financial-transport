#!/usr/bin/env python3
"""analyze_g3b.py - G3b (full handshakes at MTU 9000, default and raised tcp_rmem): criteria of results/wp6_pred_mtu9000_full.txt, plus a boundary/offset breakdown.
    python3 analyze_g3b.py RUN_DIR [RUN_DIR ...]        RUN_DIR = <data repo>/<machine>/scenarios/G3b/<run>   (contains data/default and data/large)
Excess latency of a cell = median(t_total_ms of the shaped cell) - median(t_total_ms of the unshaped base cell with the same suite, depth, mTLS, request, response);
error = excess - model_stack_ms of results/wp6_pred_mtu9000_full.csv. The cells are those of request 302 B (24 cells: 3 suites x 8 response sizes) and, shown separately, 19 460 B.
P1 (raised rmem): >= 80 % of the cells within 2 ms.  P2 (default rmem): >= 10 % of the cells more than 0.5 RTT (50 ms at 100 ms RTT) from the model, all above it.
Extra (not a pre-registered criterion): cells more than 50 ms off are listed; for the others the median error is the machine/session offset and the share within 2 ms after
removing that offset is reported.  P3 (exploratory): the cells whose response flight (response bytes) exceeds the advertised window (most frequent snd_wnd of the tcp_probe trace slack_trace_mtu9000.txt of the same
run) are the ones predicted to deviate; compared with the cells that deviate by more than 50 ms.  For the deviating cells the share of repetitions more than 50 ms above the model
is printed (1.00 = deterministic, not noise)."""
import csv, glob, os, sys, statistics as st, collections
HERE = os.path.dirname(os.path.abspath(__file__))
PRED = os.path.join(HERE, "results", "wp6_pred_mtu9000_full.csv")
P = {(r["suite"], r["depth"], r["mtls"], r["req"], r["resp"]): float(r["model_stack_ms"]) for r in csv.DictReader(open(PRED))}
def errors(run, tag, req):
    c = collections.defaultdict(list)
    for r in csv.DictReader(l for l in open(f"{run}/data/{tag}/tls_mtu9000_full.csv") if not l.startswith("#")):
        if r["req"] == req and not r["err"]:
            c[(r["suite"], r["depth"], r["mtls"], r["req"], r["resp"], r["net_id"])].append(float(r["t_total_ms"]))
    return {k[:5]: st.median(v) - st.median(c[k[:5] + ("base",)]) - P[k[:5]] for k, v in c.items() if k[5] == "shaped"}
def window(run, tag):
    w = collections.Counter()
    for l in open(f"{run}/data/{tag}/slack_trace_mtu9000.txt"):
        for t in l.split():
            if t.startswith("snd_wnd="): w[int(t[8:])] += 1
    return w.most_common(1)[0][0]
def p3(run):
    for tag in ("default", "large"):
        W = window(run, tag)
        for req in ("302",):
            e = errors(run, tag, req)
            pred = {k for k in e if int(k[4]) > W}; dev = {k for k, v in e.items() if abs(v) > 50}
            print(f"  P3 {tag:7s} request {req}: advertised window {W} B; cells with response above it {len(pred)} of {len(e)}; deviating cells {len(dev)}; deviating cells inside the predicted set {len(dev & pred)}; predicted but not deviating {len(pred - dev)}")
            # repetition-level determinism of the deviating cells
            c = collections.defaultdict(list)
            for r in csv.DictReader(l for l in open(f"{run}/data/{tag}/tls_mtu9000_full.csv") if not l.startswith("#")):
                if r["req"] == req and not r["err"] and r["net_id"] == "shaped": c[(r["suite"], r["depth"], r["mtls"], r["req"], r["resp"])].append(float(r["t_total_ms"]))
            for k in sorted(dev):
                v = c[k]; print(f"      {k[4]} B {k[0]}: {sum(x > P[k] + 50 for x in v)}/{len(v)} repetitions more than 50 ms above the model (total latency, so the base is a few ms)")
for run in sys.argv[1:]:
    print(f"== {run}")
    for req in ("302", "19460"):
        for tag, name in (("large", "raised rmem"), ("default", "default rmem")):
            e = errors(run, tag, req); n = len(e)
            big = sorted((k[4], k[0], round(v, 1)) for k, v in e.items() if abs(v) > 50)
            rest = [v for v in e.values() if abs(v) <= 50]; off = st.median(rest)
            print(f"  request {req:>5} B, {name:12s}: {n} cells; within 2 ms {sum(abs(v) <= 2 for v in e.values())} ({100*sum(abs(v) <= 2 for v in e.values())/n:.0f} %); MAE {st.mean(abs(v) for v in e.values()):.2f} ms; "
                  f">0.5 RTT: {len(big)} ({100*len(big)/n:.0f} %), all above the model: {all(v > 0 for *_, v in big)}")
            print(f"      cells >50 ms off: response sizes {sorted(set(b[0] for b in big))}; the other {len(rest)}: offset (median error) {off:+.2f} ms, within 2 ms raw {sum(abs(v) <= 2 for v in rest)}, after removing the offset {sum(abs(v-off) <= 2 for v in rest)}")
    p3(run)
