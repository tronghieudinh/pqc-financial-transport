#!/usr/bin/env python3
"""
pcap_summary.py - timeline of one TLS transaction from a tcpdump file captured on the client link (paper 2, WP6 B11/B1).
Minimal reader (classic pcap, Ethernet/IPv6/TCP, no libraries): prints, per TCP connection, every segment with its time from the first packet,
direction (C>S client to server, S>C server to client), flags and payload bytes, merging runs of same-direction segments with the same
timestamp (within --gap ms) into flights. Use: python3 pcap_summary.py results/trace_fullticket/<tag>.pcap [--conn 0] [--gap 2]
"""
import argparse, struct, sys


def read_pcap(path):
    d = open(path, "rb").read()
    magic = struct.unpack("<I", d[:4])[0]
    le = magic in (0xA1B2C3D4, 0xA1B23C4D)
    nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
    e = "<" if le else ">"
    link = struct.unpack(e + "I", d[20:24])[0]
    pos, out = 24, []
    while pos + 16 <= len(d):
        sec, frac, cap, orig = struct.unpack(e + "IIII", d[pos:pos + 16])
        pkt = d[pos + 16:pos + 16 + cap]
        pos += 16 + cap
        t = sec + frac / (1e9 if nano else 1e6)
        off = 14 if link == 1 else (16 if link == 113 else 0)
        if len(pkt) < off + 40 or pkt[off] >> 4 != 6 or pkt[off + 6] != 6:
            continue
        plen = struct.unpack(">H", pkt[off + 4:off + 6])[0]
        tcp = pkt[off + 40:]
        if len(tcp) < 20:
            continue
        sp, dp, seq, ack, offs, fl = struct.unpack(">HHIIBB", tcp[:14])
        hl = (offs >> 4) * 4
        out.append((t, sp, dp, seq, ack, fl, plen - hl))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--conn", type=int, default=-1, help="index of the connection to print (default: all, resumed and full alternating)")
    ap.add_argument("--gap", type=float, default=2.0)
    a = ap.parse_args()
    pk = read_pcap(a.pcap)
    conns = {}
    for p in pk:
        cport = p[1] if p[2] == a.port else (p[2] if p[1] == a.port else None)
        if cport is not None:
            conns.setdefault(cport, []).append(p)
    print(f"{len(conns)} connections")
    FL = {0x02: "SYN", 0x12: "SYN-ACK", 0x10: "ACK", 0x18: "PSH-ACK", 0x11: "FIN-ACK", 0x19: "FIN-PSH-ACK", 0x04: "RST", 0x14: "RST-ACK"}
    for i, (cport, ps) in enumerate(conns.items()):
        if a.conn >= 0 and i != a.conn:
            continue
        t0 = ps[0][0]
        print(f"-- connection {i} (client port {cport}) {'resumed' if i % 2 == 1 else 'full/ticket-obtaining'} (pairs assumed)")
        cur = None
        for t, sp, dp, seq, ack, fl, dl in ps:
            dirn = "C>S" if dp == a.port else "S>C"
            if dl == 0 and fl in (0x10,):
                continue          # pure ACKs omitted
            if cur and cur["dir"] == dirn and (t - cur["t_last"]) * 1000 <= a.gap and cur["fl"] == FL.get(fl, hex(fl)):
                cur["n"] += 1; cur["bytes"] += dl; cur["t_last"] = t
            else:
                if cur:
                    print(f"  {(cur['t'] - t0) * 1000:8.1f} ms {cur['dir']} {cur['fl']:12s} {cur['n']:3d} segments {cur['bytes']:6d} B")
                cur = dict(t=t, t_last=t, dir=dirn, fl=FL.get(fl, hex(fl)), n=1, bytes=dl)
        if cur:
            print(f"  {(cur['t'] - t0) * 1000:8.1f} ms {cur['dir']} {cur['fl']:12s} {cur['n']:3d} segments {cur['bytes']:6d} B")


if __name__ == "__main__":
    main()
