#!/usr/bin/env python3
"""
analyze_rwnd.py - is the MTU 9000 anomaly a receive-window limit? (paper 2, WP6 B5b). No root.

    python3 analyze_rwnd.py [--dir results]

Hypothesis H_rwnd (pre-registered in results/wp6_pred_mtu9000_rwnd.txt): with the default initial receive buffer (tcp_rmem[1] = 131072 bytes) the receiver advertises about
63,000 bytes, which is 7 segments of 8,940 bytes at MTU 9000 (against 45 at MTU 1500), below the congestion window of 10; the sender is then limited by the receive window, not
by cwnd, `tcp_is_cwnd_limited` is false and the window does not grow by the rule. With tcp_rmem[1] raised (default 131072 -> 1048576) the MTU 9000 behaviour should follow the
closed form max(w0, min(w0 + n, 2n)) and the model of the TLS cells.
Reads results/rwnd_default/slack.csv and results/rwnd_large/slack.csv (run_slack.py stage A, configurations base and mtu9000), their tcp_probe traces (snd_wnd) and, for the TLS
cells, results/resume_summary_wp6_mtu9000_{default,large}.csv with results/wp6_pred_gen.csv. Prints the evidence and a verdict.
"""
import argparse, collections, csv, os, re, statistics as st

def closed(n, w0=10):
    return max(w0, min(w0 + n, 2 * n))

def stage_a(path):
    if not os.path.exists(path):
        return {}
    out = collections.defaultdict(lambda: collections.defaultdict(list))
    for r in csv.DictReader(open(path)):
        if r["stage"] == "A" and not r["err"]:
            out[r["cfg"]][int(r["n1"])].append(int(r["cwnd_pre2"]))
    return out

def share(cfgd):
    ok = tot = 0
    for n, v in cfgd.items():
        m = st.median(v)
        tot += 1; ok += (m == closed(n))
    return ok, tot

def wnd(path):
    if not os.path.exists(path):
        return None
    c = collections.Counter(re.findall(r"snd_wnd=(\d+)", open(path, errors="ignore").read()))
    return c.most_common(3)

def tls(summ, pred):
    if not (os.path.exists(summ) and os.path.exists(pred)):
        return None
    f = float
    P = {(r["suite"], int(r["req"]), int(r["resp"]), f(r["rtt_ms"]), f(r["rate_mbps"]), int(r["mtu"])): r for r in csv.DictReader(open(pred))}
    M = {(r["suite"], int(r["req"]), int(r["resp"]), f(r["rtt_ms"]), f(r["rate_mbps"]), int(r["mtu"])): f(r["resumed_excess"]) for r in csv.DictReader(open(summ))}
    sel = [(k, P[k], m) for k, m in M.items() if k in P and k[5] == 9000]
    if not sel:
        return None
    res = {}
    for mo in ("model_joined_ms", "model_early_w10_ms", "model_early_wmeas_ms"):
        e = [f(p[mo]) - m for _, p, m in sel]
        res[mo[6:-3]] = (st.mean(abs(x) for x in e), sum(abs(x) > 50 for x in e), len(e))      # RTT 100: wrong by a round trip when |error| > 50 ms
    return res

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    a = ap.parse_args()
    D = a.dir
    print("== plain TCP, window after an n-segment flight (stage A), median of the repetitions; closed form = max(10, min(10 + n, 2n)) ==")
    verdict = {}
    for tag in ("default", "large"):
        S = stage_a(os.path.join(D, f"rwnd_{tag}", "slack.csv"))
        for cfg in ("base", "mtu9000"):
            if cfg in S:
                ok, tot = share(S[cfg])
                row = [(n, int(st.median(S[cfg][n])), closed(n)) for n in sorted(S[cfg]) if n in (6, 8, 10, 12, 16, 24, 40)]
                print(f"rmem {tag:8s} {cfg:8s}: matches the closed form in {ok} of {tot} flight sizes; (n, measured, closed form): {row}")
                verdict[(tag, cfg)] = ok / tot
        w = wnd(os.path.join(D, f"rwnd_{tag}", "slack_trace_mtu9000.txt"))
        if w:
            print(f"rmem {tag:8s} advertised window at MTU 9000 (most frequent snd_wnd values in bytes): {w}")
    print("\n== TLS cells at MTU 9000 (resumed, RTT 100 ms, 100 Mbit/s): MAE of each model and cells wrong by a round trip ==")
    for tag in ("default", "large"):
        r = tls(os.path.join(D, f"resume_summary_wp6_mtu9000_{tag}.csv"), os.path.join(D, "wp6_pred_gen.csv"))
        if r:
            print(f"rmem {tag:8s}: " + " | ".join(f"{k}: MAE {v[0]:6.1f} ms, {v[1]}/{v[2]} wrong" for k, v in r.items()))
    print("\n== verdict ==")
    d, l = verdict.get(("default", "mtu9000")), verdict.get(("large", "mtu9000"))
    if d is None or l is None:
        print("incomplete data")
    elif l >= 0.9 and d < 0.7:
        print(f"H_rwnd CONFIRMED for plain TCP: with the default buffer {100 * d:.0f}% of the flight sizes follow the closed form at MTU 9000, with the raised buffer {100 * l:.0f}%.")
    elif l >= 0.9 and d >= 0.9:
        print("MTU 9000 already follows the closed form in this run, in both settings: the earlier deviation did not reproduce (check the kernel and the offload settings).")
    else:
        print(f"H_rwnd NOT confirmed: default {100 * d:.0f}%, raised buffer {100 * l:.0f}% of the flight sizes follow the closed form; the cause is something else (offload, MSS accounting, queue).")

if __name__ == "__main__":
    main()
