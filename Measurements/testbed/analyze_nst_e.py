#!/usr/bin/env python3
"""analyze_nst_e.py - stage E of WP5: the server's window for the response after an acknowledged ticket (see nst_predict_e.py).
Needs results/resume_summary_nst_e_tls.csv (analyze_resume.py --out ... results/nst_e_tls.csv)."""
import csv, os, statistics as st
HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
WS = [10, 12, 14, 16, 20]
RTT = 100.0


def main():
    summ = os.path.join(RES, "resume_summary_nst_e_tls.csv")
    if not os.path.exists(summ):
        raise SystemExit("run: python3 analyze_resume.py --out results/resume_summary_nst_e_tls.csv results/nst_e_tls.csv")
    pred = {(r["suite"], int(r["req"]), int(r["resp"])): r for r in csv.DictReader(open(os.path.join(RES, "nst_predictions_e.csv")))}
    meas = {(r["suite"], int(r["req"]), int(r["resp"])): float(r["resumed_excess"]) for r in csv.DictReader(open(summ))}
    cells = [(k, p, meas[k]) for k, p in pred.items() if k in meas]
    print(f"{len(cells)} of {len(pred)} predicted cells measured\n")
    suites = sorted({k[0] for k, _, _ in cells})
    print("== measured series: extra round trips relative to the cheapest cell of the series (k = response segments) ==")
    thr = {}
    for su in suites:
        for rq in sorted({k[1] for k, _, _ in cells}):
            ser = sorted((int(p["resp_segments"]), m) for k, p, m in cells if k[0] == su and k[1] == rq)
            if not ser:
                continue
            ref = min(m for _, m in ser)
            ex = [(k, round((m - ref) / RTT)) for k, m in ser]
            first = next((k for k, e in ex if e >= 1), None)
            thr[(su, rq)] = first
            print(f"{su:24s} req {rq:6d}: " + " ".join(f"{k}:{e}" for k, e in ex) + f"   first extra round trip at k = {first}")
    print("\n== fit of the server window W after an acknowledged ticket (cells with a large request, where the ticket is acknowledged) ==")
    best = {}
    for su in suites:
        sel = [(p, m) for k, p, m in cells if k[0] == su and k[1] == 19460]
        if not sel:
            continue
        res = {}
        for w in WS:
            e = [float(p[f"model_w{w}_ms"]) - m for p, m in sel]
            res[w] = (st.mean(abs(x) for x in e), sum(abs(x) > 50 for x in e))
        b = min(WS, key=lambda w: (res[w][1], res[w][0]))
        best[su] = b
        print(f"{su:24s} " + "  ".join(f"W={w}: MAE {res[w][0]:6.1f} wrong {res[w][1]}" for w in WS) + f"   best W = {b}")
    print("\n== control: small request (the ticket is still in flight when the response leaves; W does not matter) ==")
    for su in suites:
        sel = [(p, m) for k, p, m in cells if k[0] == su and k[1] == 302]
        if sel:
            e = [float(p["model_w10_ms"]) - m for p, m in sel]
            print(f"{su:24s} MAE {st.mean(abs(x) for x in e):6.2f} ms, cells a round trip wrong {sum(abs(x) > 50 for x in e)} of {len(e)}")
    print("\n== reading ==")
    vals = {s: best[s] for s in best}
    print("best W per suite:", vals)
    ctl = [s for s in best if s.startswith("ML-DSA-87")]
    if len(set(best.values())) == 1:
        print("one window W for all tickets: the server's window after an acknowledged ticket does not depend on the ticket's size.")
    else:
        print("W differs between suites, i.e. with the ticket's size (ECDSA: 1 segment, ML-DSA-44/-65/-87: 4, 5, 6): compare with the closed form w(n) = max(10, min(10+n, 2n)) applied to the ticket flight plus the server's first flight.")
    print("ML-DSA-87 (control, request flight fits its window, ticket not yet acknowledged): its W is not identifiable; check that its series follows the model with W = 10 or the joined ticket.")


if __name__ == "__main__":
    main()
