#!/usr/bin/env python3
"""
analyze_trace.py - what the SERVER's TCP did in a traced transaction (tcp:tcp_probe), paper 2, WP6 B1.

    python3 analyze_trace.py results/trace_window/*.trace.txt [--mss 1440] [--port 4433]

tcp_probe fires when a socket receives a segment and prints the state of the RECEIVING socket. Lines whose destination port is the server's
port therefore show the server's own snd_cwnd, snd_una and snd_nxt each time a client segment (data or ACK) arrives.
NOTE (corrected 2026-11-02): tcp_probe prints the address of the RECEIVING socket as `src` (its local end) and the sender as `dest`. The server's state is
therefore on the lines whose `src` port is the server port; the lines whose `dest` port is the server port show the CLIENT's state. Use --side to choose. For every server
connection it reports the peak number of segments in flight (snd_nxt - snd_una, in segments of --mss) and the largest snd_cwnd seen, and the
sequence of distinct cwnd values with the time (ms from the first segment). Connections come in pairs (full transaction that obtains the
ticket, then the resumed one): the resumed ones are marked R. The peak in flight of the RESPONSE is the window the server really had when it
sent the response, if the response was larger than the window.
"""
import argparse, collections, re, statistics as st, sys

LINE = re.compile(r"\s(\d+\.\d+): tcp_probe: .*?src=\[?([0-9a-f:.]+)\]?:(\d+) dest=\[?([0-9a-f:.]+)\]?:(\d+) .*?data_len=(\d+) snd_nxt=0x([0-9a-f]+) snd_una=0x([0-9a-f]+) snd_cwnd=(\d+) ssthresh=(\d+)")


def parse(path, port, side="server"):
    conns = collections.OrderedDict()
    for line in open(path, errors="ignore"):
        m = LINE.search(line)
        if not m:
            continue
        lp, rp = int(m.group(3)), int(m.group(5))               # local (receiving socket) and remote port
        if (lp if side == "server" else rp) != port:
            continue
        t, cport, dlen = float(m.group(1)), (rp if side == "server" else lp), int(m.group(6))
        nxt, una, cw = int(m.group(7), 16), int(m.group(8), 16), int(m.group(9))
        conns.setdefault(cport, []).append((t, dlen, (nxt - una) & 0xFFFFFFFF, cw))
    return conns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--mss", type=int, default=1440)
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--side", choices=["server", "client"], default="server", help="whose socket state to print (default: the server's, lines with src port = --port)")
    a = ap.parse_args()
    for f in a.files:
        conns = parse(f, a.port, a.side)
        print(f"== {f}: {len(conns)} server connections")
        rows = []
        for i, (cport, ev) in enumerate(conns.items()):
            t0 = ev[0][0]
            peak = max(e[2] for e in ev) / a.mss
            cmax = max(e[3] for e in ev)
            seq, last = [], None
            for t, d, o, cw in ev:
                if cw != last:
                    seq.append(f"{(t - t0) * 1000:.0f}ms:{cw}")
                    last = cw
            kind = "R" if i % 2 == 1 else "F"
            rows.append((kind, peak, cmax, seq))
        for k in ("F", "R"):
            sel = [r for r in rows if r[0] == k]
            if sel:
                print(f"  {k}: connections {len(sel)}  peak in flight (segments) median {st.median(r[1] for r in sel):.1f} max {max(r[1] for r in sel):.1f}   max cwnd median {st.median(r[2] for r in sel):.0f}")
        r = next((r for r in rows if r[0] == "R"), None)
        if r:
            print("  first resumed connection, cwnd over time:", " ".join(r[3][:24]))


if __name__ == "__main__":
    main()
