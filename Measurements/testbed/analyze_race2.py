#!/usr/bin/env python3
"""
analyze_race2.py - confirmatory test of the ticket-timing rule (paper 2, WP6 B2). No root.

    python3 analyze_race2.py [--pred results/wp6_pred_race2.csv] [--dir results/trace_race]

Reads the server-side captures of the request-size sweep (response of 16 segments), the predictions fixed in advance (race2_predict.py) and reports
  1. per cell (suite, network, request size): the median burst, the share of transactions with burst > 10, the measured median of (last ticket ACK - last request segment),
     the predicted class and whether it is right (borderline cells are listed but not scored);
  2. the success criterion: >= 90 % of the scored cells right, and the first request size with burst 10 within one segment (1,440 B) of the predicted one;
  3. out of sample: the classification of the individual transactions by the sign of (ACK - tail) - 0.049 ms, the rule of the first run, on these new transactions.
"""
import argparse, collections, csv, glob, os, re, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze_ticket_race as T  # noqa: E402
from pcap_summary import read_pcap  # noqa: E402

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", default=os.path.join(HERE, "results", "wp6_pred_race2.csv"))
    ap.add_argument("--dir", default=os.path.join(HERE, "results", "trace_race"))
    ap.add_argument("--port", type=int, default=4433)
    a = ap.parse_args()
    P = {(r["suite"], float(r["rtt"]), int(r["req"])): r for r in csv.DictReader(open(a.pred))}
    rows = []
    for f in sorted(glob.glob(os.path.join(a.dir, "*_k16_*_srv.pcap"))):
        m = T.TAG.search(os.path.basename(f))
        if not m:
            continue
        conns = collections.OrderedDict()
        for p in read_pcap(f):
            cp = p[2] if p[1] == a.port else (p[1] if p[2] == a.port else None)
            if cp is not None:
                conns.setdefault(cp, []).append(p)
        for i, (cp, ps) in enumerate(conns.items()):
            if i % 2 == 0:
                continue
            r = T.analyse_conn(ps, a.port, float(m["rtt"]) / 2000.0, int(m["req"]))
            if r and r["t_ack_tkt_minus_req_ms"] is not None:
                rows.append(dict(suite=m["suite"], rtt=float(m["rtt"]), req=int(m["req"]), **r))
    if not rows:
        sys.exit("no k16 captures found: run run_wp6c.sh first")
    cells = collections.defaultdict(list)
    for r in rows:
        cells[(r["suite"], r["rtt"], r["req"])].append(r)
    print(f"{'suite':10s} {'rtt':>4s} {'req':>6s} {'n':>2s} {'burst':>5s} {'>10':>5s} {'ack-tail':>9s} {'pred ms':>8s} {'pred':>5s} {'real':>5s} result")
    scored = right = 0
    firsts = {}
    for key in sorted(cells):
        v = cells[key]
        pr = P.get(key)
        share = sum(x["burst"] > 10 for x in v) / len(v)
        real = ">10" if share > 0.5 else "10"
        mreq = st.median(x["t_ack_tkt_minus_req_ms"] for x in v)
        if pr:
            ok = real == pr["pred_class"]
            sc = pr["scored"] == "1"
            scored += sc
            right += sc and ok
            res = ("right" if ok else "WRONG") + ("" if sc else " (borderline, not scored)")
            pm, pc = pr["pred_m_ms"], pr["pred_class"]
        else:
            res, pm, pc = "no prediction", "", ""
        print(f"{key[0]:10s} {key[1]:4g} {key[2]:6d} {len(v):2d} {st.median(x['burst'] for x in v):5.0f} {100 * share:4.0f}% {mreq:9.3f} {pm:>8s} {pc:>5s} {real:>5s} {res}")
        if real == "10":
            firsts.setdefault((key[0], key[1]), []).append(key[2])
    print(f"\nscored cells right: {right} of {scored}" + (f" ({100 * right / scored:.0f}%)" if scored else ""))
    for (su, rtt), reqs in sorted(firsts.items()):
        pr = [r for k, r in P.items() if k[0] == su and k[1] == rtt]
        pred_first = pr[0]["first_req_burst10_pred"] if pr else "?"
        print(f"{su} {rtt:g} ms: first request size with burst 10 measured {min(reqs)} B, predicted {pred_first} B")
    ok = sum((r["t_ack_tkt_minus_req_ms"] > 0.049) == (r["burst"] > 10) for r in rows)
    print(f"\nout of sample, per transaction: sign of (ACK - tail - 0.049 ms) classifies {ok} of {len(rows)} ({100 * ok / len(rows):.1f}%)")

if __name__ == "__main__":
    main()
