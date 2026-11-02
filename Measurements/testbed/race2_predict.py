#!/usr/bin/env python3
"""
race2_predict.py - pre-registration of the confirmatory ticket-timing test (paper 2, WP6 part B2). Run once; COMMIT AND PUSH results/wp6_pred_race2.csv BEFORE measuring.

Rule found in the first race run (exploratory, 134 transactions): the server's window for its response is above 10 segments when the last ACK of the ticket arrives MORE THAN
0.049 ms AFTER the last request segment, and 10 when it arrives before. Test: grow or shrink the request by whole segments. Every segment of 1,440 bytes added to the request
moves the arrival of its last segment later by its serialization time (1,500 bytes at the link rate; 0.12 ms at 100 Mbit/s), while the ticket's ACK, paced by the round trip,
does not move. So for a request of 19,460 + 1,440 j bytes (j = -3 ... +6) the rule predicts

    m(j) = m(0) - 0.12 ms * j          m(0): the median of (last ticket ACK - last request segment) of the first run at the same network and suite, request 19,460 B
    burst > 10  if m(j) > 0.049 ms + band,   burst = 10  if m(j) < 0.049 ms - band,   cells within +-band = 0.06 ms are 'borderline' and not scored.

For j < 0 the request needs fewer segments in its second flight, or none (a request of at most 12 segments is sent in the first flight): the tail then arrives even earlier, so the rule
predicts a burst above 10 (m(j) larger still). Suites: ML-DSA-44 and ML-DSA-65 (tickets of 4 and 5 segments); networks 30 ms and 100 ms at 100 Mbit/s, MTU 1500; response 16 segments.
Success criterion: at least 90 % of the scored cells have the predicted class, and the first request size with burst 10 is within one segment of the predicted one.
"""
import csv, os, statistics as st
HERE = os.path.dirname(os.path.abspath(__file__))
SLOPE_MS = 0.12          # (1,440 + 60) bytes at 100 Mbit/s
THRESH, BAND = 0.049, 0.06
SUITES = ["ML-DSA-44", "ML-DSA-65"]
NETS = [(30.0, 100.0, 1500), (100.0, 100.0, 1500)]
JS = list(range(-3, 7))

def main():
    rows = [r for r in csv.DictReader(open(os.path.join(HERE, "results", "ticket_race.csv")))]
    out = [["suite", "rtt", "rate", "mtu", "j", "req", "m0_ms", "pred_m_ms", "pred_class", "scored", "first_req_burst10_pred"]]
    for su in SUITES:
        for rtt, rate, mtu in NETS:
            sel = [float(r["t_ack_tkt_minus_req_ms"]) for r in rows if r["suite"] == su and float(r["rtt"]) == rtt and float(r["rate"]) == rate and int(r["mtu"]) == mtu
                   and int(r["req"]) == 19460 and r["t_ack_tkt_minus_req_ms"] not in ("", "None")]
            if not sel:
                raise SystemExit(f"no first-run data for {su} {rtt}:{rate}:{mtu}")
            m0 = st.median(sel)
            first = None
            for j in JS:
                m = m0 - SLOPE_MS * j
                cls = ">10" if m > THRESH else "10"
                if cls == "10" and first is None:
                    first = 19460 + 1440 * j
            for j in JS:
                m = m0 - SLOPE_MS * j
                cls = ">10" if m > THRESH else "10"
                scored = abs(m - THRESH) > BAND
                out.append([su, rtt, rate, mtu, j, 19460 + 1440 * j, round(m0, 3), round(m, 3), cls, int(scored), first if first is not None else "none"])
    path = os.path.join(HERE, "results", "wp6_pred_race2.csv")
    csv.writer(open(path, "w", newline="")).writerows(out)
    for r in out[:1] + [x for x in out[1:] if x[4] in (0, 2, 3)]:
        print(*r, sep="\t")
    print("written", path)

if __name__ == "__main__":
    main()
