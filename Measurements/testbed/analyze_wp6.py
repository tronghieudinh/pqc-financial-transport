#!/usr/bin/env python3
"""
analyze_wp6.py - analysis of the WP6 scenarios (paper 2). One subcommand per scenario; each prints what it answers.

  python3 analyze_wp6.py gen        # B3: ticket rule and server window across RTT, rate, MTU (needs analyze_resume.py --out results/resume_summary_wp6_gen.csv ...)
  python3 analyze_wp6.py servonly   # B10
  python3 analyze_wp6.py clientalg  # B9
  python3 analyze_wp6.py latency    # B4
  python3 analyze_wp6.py capacity   # B7 (repeats) and B8 (perf profile)
Loss (B2) has its own script: analyze_loss.py [--resume]. Traces (B1, B5, B11): analyze_trace.py and pcap_summary.py.
"""
import collections, csv, glob, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
f = float


def rd(p):
    return list(csv.DictReader(open(p)))


def series_fit(ser, rtt):
    """ser: [(k, excess_ms)] -> (largest k with no extra round trip before the first one, first k with an extra round trip)."""
    ser = sorted(ser)
    ref = min(m for _, m in ser)
    first = next((k for k, m in ser if round((m - ref) / rtt) >= 1), None)
    return (None if first is None else first - 1), first


def gen(kind):
    pred = os.path.join(RES, f"wp6_pred_{kind}.csv")
    summ = os.path.join(RES, f"resume_summary_wp6_{kind}.csv")
    if not (os.path.exists(pred) and os.path.exists(summ)):
        sys.exit(f"need {pred} and {summ} (analyze_resume.py --out {summ} results/wp6_{kind}_tls.csv)")
    P = {(r["suite"], int(r["req"]), int(r["resp"]), f(r["rtt_ms"]), f(r["rate_mbps"]), int(r["mtu"])): r for r in rd(pred)}
    M = {(r["suite"], int(r["req"]), int(r["resp"]), f(r["rtt_ms"]), f(r["rate_mbps"]), int(r["mtu"])): f(r["resumed_excess"]) for r in rd(summ)}
    cells = [(k, P[k], M[k]) for k in P if k in M]
    print(f"{len(cells)} of {len(P)} predicted cells measured\n")
    models = ("model_joined_ms", "model_early_w10_ms", "model_early_wmeas_ms")
    print("== errors by model (a cell is wrong by a round trip when |error| > half the RTT) ==")
    nets = sorted({(k[3], k[4], k[5]) for k, _, _ in cells})
    for net in nets:
        sel = [(k, p, m) for k, p, m in cells if (k[3], k[4], k[5]) == net]
        line = []
        for mo in models:
            e = [f(p[mo]) - m for _, p, m in sel]
            line.append(f"{mo[6:-3]:12s} MAE {st.mean(abs(x) for x in e):6.2f} wrong {sum(abs(x) > 0.5 * net[0] for x in e):2d}")
        print(f"RTT {net[0]:g} ms, {net[1]:g} Mbit/s, MTU {net[2]}: " + " | ".join(line))
    print("\n== largest response (segments) that costs no extra round trip, large request ==")
    W = collections.defaultdict(dict)
    for net in nets:
        for su in sorted({k[0] for k, _, _ in cells}):
            ser = [(int(p["resp_segments"]), m) for k, p, m in cells if k[0] == su and (k[3], k[4], k[5]) == net and k[1] == 19460]
            if len(ser) >= 4:
                W[su][net] = series_fit(ser, net[0])
    for su, d in W.items():
        print(f"{su:24s} " + "  ".join(f"[{n[0]:g}ms/{n[1]:g}M/{n[2]}] {v[0]}" for n, v in d.items()))
    print("\n== reading ==")
    if kind == "gen":
        ok = True
        for su, d in W.items():
            vals = {v[0] for n_, v in d.items() if v[0] is not None and n_[2] != 9000}      # MTU 9000: a 19,460-byte request is 3 segments, no ticket race; read it apart
            print(f"{su}: fit {sorted(vals)} across {len([n_ for n_ in d if n_[2] != 9000])} networks with an MTU below 9000" + ("  -> the window after an acknowledged ticket does not depend on RTT, rate or MTU" if len(vals) == 1 else "  -> it DOES depend on the network: describe it") + "; MTU 9000 is read from the error table above")
    else:
        print("server authentication only: the ticket has one segment, so the fit should be 10 for every suite and the early-ticket model with window 10 should be right everywhere")


def clientalg():
    pred = rd(os.path.join(RES, "wp6_pred_clientalg.csv"))
    print("pair (server / client)                 measured fit  H_ticket (client)  H_server")
    for r in pred:
        tag = {"ML-DSA-65/ECDSA-P256": "srv65_cliECDSA", "ECDSA-P256/ML-DSA-65": "srvECDSA_cli65", "ML-DSA-44/ML-DSA-65": "srv44_cli65", "ML-DSA-65/ML-DSA-44": "srv65_cli44"}[f"{r['server']}/{r['client']}"]
        p = os.path.join(RES, f"resume_summary_wp6_clientalg_{tag}.csv")
        if not os.path.exists(p):
            print(f"{r['server']:>10s} / {r['client']:<12s}  (no summary: python3 analyze_resume.py --out {p} results/wp6_clientalg_{tag}.csv)")
            continue
        ser = [(int(round((f(x["resp"]) + 700) / 1440)), f(x["resumed_excess"])) for x in rd(p) if int(x["req"]) == 19460]
        fit, first = series_fit(ser, 100.0)
        verdict = "ticket" if fit == int(r["h_ticket_fit_segments"]) else ("server" if fit == int(r["h_server_fit_segments"]) else "neither")
        print(f"{r['server']:>10s} / {r['client']:<12s}  {fit}            {r['h_ticket_fit_segments']}                  {r['h_server_fit_segments']}      -> {verdict}")
    print("\nIf every pair says 'ticket', the server's window follows the size of the ticket (client certificate), not the server's algorithm.")


def latency():
    fs = sorted(glob.glob(os.path.join(RES, "wp6_latency_load_*.csv")))
    if not fs:
        sys.exit("no results/wp6_latency_load_*.csv")
    for p in fs:
        print(f"== {os.path.basename(p)}")
        rows = rd(p)
        print(f"{'suite':24s} mtls res  frac  cap/s   ok      err  drop  p50 ms   p90 ms   p99 ms  p99.9 ms  util")
        for r in sorted(rows, key=lambda r: (r["suite"], int(r["resume"]), f(r["fraction"]))):
            print(f"{r['suite'][:24]:24s} {r['mtls']:>4s} {r['resume']:>3s} {f(r['fraction']):5.2f} {f(r['capacity_per_s']):6.0f} {r['ok']:>7s} {r['err']:>4s} {r['dropped']:>5s} {f(r['p50_ms']):7.2f}  {f(r['p90_ms']):7.2f}  {f(r['p99_ms']):7.2f}  {f(r['p999_ms']):7.2f}  {r['util']}")
        print("\nQueueing premium p99(0.95) / p99(0.5): ", {(r['suite'][:12], r['resume']): round(f(r['p99_ms']) / max(f(q['p99_ms']), 1e-9), 1)
              for r in rows if f(r['fraction']) == 0.95 for q in rows if q['suite'] == r['suite'] and q['resume'] == r['resume'] and f(q['fraction']) == 0.5})


def capacity():
    g = collections.defaultdict(list)
    for p in sorted(glob.glob(os.path.join(RES, "wp6_capacity_repeat_*.csv"))):
        for r in rd(p):
            g[(r["suite"], r["mtls"])].append((f(r["cpu_ms_per_hs"]), f(r["rate_per_s"])))
    if g:
        print("== capacity repeated (one server core): mean, standard deviation and coefficient of variation ==")
        for (su, m), v in sorted(g.items()):
            c = [x[0] for x in v]; r = [x[1] for x in v]
            print(f"{su:24s} mtls={m} runs {len(v)}  CPU/handshake {st.mean(c):.4f} ms (CV {100 * st.pstdev(c) / st.mean(c):.1f}%)  rate {st.mean(r):.0f}/s (CV {100 * st.pstdev(r) / st.mean(r):.1f}%)")
    for p in sorted(glob.glob(os.path.join(RES, "wp6_perf_*.txt"))):
        print(f"\n== {os.path.basename(p)}\n" + open(p).read())


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    {"gen": lambda: gen("gen"), "servonly": lambda: gen("servonly"), "clientalg": clientalg, "latency": latency, "capacity": capacity}[sys.argv[1]]()


if __name__ == "__main__":
    main()
