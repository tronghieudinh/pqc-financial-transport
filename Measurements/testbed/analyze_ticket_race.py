#!/usr/bin/env python3
"""
analyze_ticket_race.py - what decides the window the server has for its response after a session ticket (paper 2, WP6 B1b). No root.

    python3 analyze_ticket_race.py results/trace_race/*_srv.pcap [--port 4433] [--mss auto] [--csv results/ticket_race.csv]

Input: tcpdump captures on the SERVER's link (vs0) written by `trace_run.py race`. C>S packets are time-stamped when they ARRIVE at the server. S>C packets are time-stamped
AFTER the netem egress delay of vs0 (tcpdump taps the device after the qdisc: the SYN-ACK of every capture appears RTT/2 after the SYN), so the true send time of a server
packet is its time stamp minus RTT/2 (RTT from the file name); this script applies that shift and every time below is on the server's clock. Each file holds pairs of connections (a full transaction that obtains the ticket, then the resumed one); only the
resumed ones (every second connection) are analysed.

For a resumed transaction (mutual TLS, large request, response of k segments) it extracts:
  t_fin     arrival of the client's Finished (the first C>S data segment of at most 100 bytes after the ServerHello flight)
  ticket    S>C data sent after t_fin and before the request is complete (segments, bytes)
  t_ack_tkt arrival of the first ACK that covers the whole ticket
  t_req     arrival of the last request segment (the response is written at about this time)
  t_w       the first S>C data segment of the response
  burst     response segments sent before the first ACK of response data arrives = the window the server really used
  extra     response segments sent in the same round trip but only after the ticket's ACK arrived (the ACK opened the window while the response was being sent)
and the three quantities that decide between the hypotheses:
  H_race: the window is 10 + (growth by the ticket ACK) if the ticket's ACK arrives BEFORE the response is written (t_ack_tkt <= t_w), else 10 minus the unacknowledged ticket
  H_ack_clock: the ACK of the ticket opens the window also when it arrives after the first response segments (extra > 0)
  H_const: the burst is the same on every network (the stage-E values 12 and 15)
It prints, per (suite, network, k), the medians of burst, (t_ack_tkt - t_w) in ms, the share of transactions whose ticket ACK arrived before the response was written, and the
number of response round trips; with --csv one line per transaction.
"""
import argparse, collections, csv, os, re, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pcap_summary import read_pcap  # noqa: E402

TAG = re.compile(r"(?P<suite>.+)_req(?P<req>\d+)_k(?P<k>\d+)_rtt(?P<rtt>[\d.]+)_rate(?P<rate>[\d.]+)_mtu(?P<mtu>\d+)_srv\.pcap$")


def analyse_conn(pk, port, shift=0.0, req_bytes=19460):
    """pk: packets (t, sp, dp, seq, ack, flags, dlen) of one connection, server clock. Returns a dict or None."""
    pk = [(p[0] - shift,) + tuple(p[1:]) if p[1] == port else p for p in pk]       # true send time of server packets
    srv = [p for p in pk if p[1] == port]          # S>C
    cli = [p for p in pk if p[2] == port]          # C>S
    sd = [p for p in srv if p[6] > 0]
    cd = [p for p in cli if p[6] > 0]
    if len(sd) < 3 or len(cd) < 3:
        return None
    t_sh = sd[0][0]
    fin = next((p for p in cd if p[0] > t_sh and p[6] <= 100), None)
    if fin is None:
        return None
    t_fin = fin[0]
    # the request is complete when its bytes (the client's later close_notify is not part of it) have arrived
    got, t_req = 0, None
    for p in (p for p in cd if p[0] > t_fin):
        got += p[6]
        if got >= req_bytes:
            t_req = p[0]
            break
    if t_req is None:
        return None
    after = [p for p in sd if p[0] >= t_fin]
    if not after:
        return None
    resp_start = next((p for p in after if p[0] >= t_req - 1e-4), None)
    if resp_start is None:
        return None
    t_w = resp_start[0]
    ticket = [p for p in after if p[0] < t_req - 1e-4]
    resp = [p for p in after if p[0] >= t_req - 1e-4]
    base_seq = sd[0][3]
    # ack numbers: server sequence space; the ticket ends at max(seq + len) of its segments
    tkt_end = max((p[3] + p[6] for p in ticket), default=None)
    resp_first_seq = resp[0][3]
    t_ack_tkt = None
    if tkt_end is not None:
        t_ack_tkt = next((p[0] for p in cli if p[0] >= ticket[0][0] and ((p[4] - tkt_end) & 0xFFFFFFFF) < 0x80000000), None)
    # first ACK that covers response data
    t_ack_resp = next((p[0] for p in cli if p[0] >= t_w and ((p[4] - (resp_first_seq + 1)) & 0xFFFFFFFF) < 0x80000000), None)
    burst = [p for p in resp if t_ack_resp is None or p[0] < t_ack_resp]
    ticket_acked_before_write = t_ack_tkt is not None and t_ack_tkt <= t_w + 1e-6
    extra = sum(1 for p in burst if t_ack_tkt is not None and p[0] > t_ack_tkt + 1e-6)
    # per ticket segment: when was it acknowledged (first C>S packet whose ack number covers its end)?
    ends = sorted(p[3] + p[6] for p in ticket)
    ack_times = [next((q[0] for q in cli if q[0] >= ticket[0][0] and ((q[4] - e) & 0xFFFFFFFF) < 0x80000000), None) for e in ends]
    tkt_acked_pre = sum(1 for t in ack_times if t is not None and t <= t_w + 1e-6)             # acknowledged before the response is written
    t_last_resp = burst[-1][0] if burst else t_w
    tkt_after_req = sum(1 for t in ack_times if t is not None and t > t_req + 1e-6)             # ticket segments acknowledged after the last request segment arrived
    tkt_acked_in_burst = sum(1 for t in ack_times if t is not None and t_w + 1e-6 < t <= t_last_resp)   # acknowledged while the burst is being sent (ACK clock)
    # round trips of the response: groups of response segments separated by an ACK wait larger than half the gap between t_w and t_ack_resp
    return dict(ticket_segs=len(ticket), ticket_bytes=sum(p[6] for p in ticket), resp_segs=len(resp), burst=len(burst), extra=extra,
                t_fin=t_fin, t_req=t_req, t_w=t_w, t_ack_tkt_minus_w_ms=None if t_ack_tkt is None else (t_ack_tkt - t_w) * 1000,
                tkt_acked_before_write=int(ticket_acked_before_write), tkt_acked_pre=tkt_acked_pre, tkt_acked_in_burst=tkt_acked_in_burst,
                burst_span_ms=(t_last_resp - t_w) * 1000, tkt_acked_after_req=tkt_after_req, t_ack_tkt_minus_req_ms=None if t_ack_tkt is None else (t_ack_tkt - t_req) * 1000, t_ack_resp_minus_w_ms=None if t_ack_resp is None else (t_ack_resp - t_w) * 1000,
                resp_span_ms=(resp[-1][0] - t_w) * 1000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--csv", default="")
    a = ap.parse_args()
    rows = []
    for f in a.files:
        m = TAG.search(os.path.basename(f))
        if not m:
            continue
        pk = read_pcap(f)
        conns = collections.OrderedDict()
        for p in pk:
            cport = p[2] if p[1] == a.port else (p[1] if p[2] == a.port else None)
            if cport is not None:
                conns.setdefault(cport, []).append(p)
        for i, (cport, ps) in enumerate(conns.items()):
            if i % 2 == 0:
                continue                                  # full transaction that obtains the ticket
            r = analyse_conn(ps, a.port, float(m['rtt']) / 2000.0, int(m['req']))
            if r:
                rows.append(dict(suite=m["suite"], req=int(m["req"]), k=int(m["k"]), rtt=float(m["rtt"]), rate=float(m["rate"]), mtu=int(m["mtu"]), conn=i, **r))
    if not rows:
        sys.exit("no resumed transaction could be analysed (check --port and that the files are server-side captures *_srv.pcap)")
    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
    g = collections.OrderedDict()
    for r in rows:
        g.setdefault((r["suite"], r["rate"], r["mtu"], r["rtt"], r["k"]), []).append(r)
    print(f"{'suite':12s} {'rtt':>5s} {'rate':>5s} {'mtu':>5s} {'k':>3s} {'n':>3s} {'ticket':>6s} {'burst':>5s} {'tkt acked':>9s} {'tkt acked':>9s} {'last ack-w':>10s} {'burst':>7s} {'ack-req':>10s}")
    print(f"{'':12s} {'':>5s} {'':>5s} {'':>5s} {'':>3s} {'':>3s} {'segs':>6s} {'segs':>5s} {'before w':>9s} {'in burst':>9s} {'ms':>10s} {'span ms':>7s} {'tail ms':>10s}")
    for (su, rate, mtu, rtt, k), rs in g.items():
        med = lambda key: st.median([x[key] for x in rs if x[key] is not None]) if any(x[key] is not None for x in rs) else float("nan")
        print(f"{su:12s} {rtt:5g} {rate:5g} {mtu:5d} {k:3d} {len(rs):3d} {med('ticket_segs'):6.0f} {med('burst'):5.0f} {med('tkt_acked_pre'):9.0f} {med('tkt_acked_in_burst'):9.0f} "
              f"{med('t_ack_tkt_minus_w_ms'):10.2f} {med('burst_span_ms'):7.2f} {med('t_ack_tkt_minus_req_ms'):10.2f}")



    # exploratory (post hoc, NOT pre-registered): what separates a burst of 10 from a burst above 10 in the transactions with a ticket of several segments?
    sel = [r for r in rows if r["suite"] != "ECDSA-P256" and r["mtu"] != 9000 and r["t_ack_tkt_minus_req_ms"] is not None]
    if sel:
        print("\nexploratory separation of burst > 10 from burst = 10 (ML-DSA suites, MTU below 9000), n =", len(sel))
        for key, name in (("t_ack_tkt_minus_w_ms", "last ticket ACK relative to the response write"), ("t_ack_tkt_minus_req_ms", "last ticket ACK relative to the last request segment")):
            best = None
            for th in sorted({round(r[key], 3) for r in sel}):
                acc = sum((r[key] >= th) == (r["burst"] > 10) for r in sel) / len(sel)
                if best is None or acc > best[1]:
                    best = (th, acc)
            print(f"  {name}: best threshold {best[0]:+.3f} ms classifies {100 * best[1]:.1f}% of the transactions")


if __name__ == "__main__":
    main()
