#!/usr/bin/env python3
"""analyze_dubetskyy_segments.py - do the server segment counts published by Dubetskyy and Cano (Information 2026, 17, 1098, doi 10.3390/info17111098, Table 6 and Figure 2)
follow from the write pattern of the stack model (a handshake flight written through a 4096-byte OpenSSL buffer, every write cut into MSS-sized segments, the partial tail leaving at once)?
POST HOC calculation (not pre-registered), made after the numbers were published; the data below are theirs, copied from Table 6 (record lengths, MTU 1500, OpenSSL 3.5.0) and Figure 2 (left).
Assumptions, stated by the authors where they exist: each connection carries the server flight (ServerHello to Finished, with record headers), two NewSessionTicket messages and a close_notify alert.
Not stated by the authors, so varied here: the header bytes (IPv4 or IPv6, with or without TCP timestamps) and how many segments tickets and alert occupy.
    python3 analyze_dubetskyy_segments.py"""
import math
FLIGHT = {"X25519 + RSA": 1305, "X25519MLKEM768 + RSA": 2393, "ML-KEM-768 + RSA": 2361, "X25519 + ML-DSA-65": 9087, "ML-KEM-768 + ML-DSA-65": 10143}   # server flight in bytes (Table 6)
SEGS = {"X25519 + RSA": (4, 4, 5), "X25519MLKEM768 + RSA": (5, 5, 5), "ML-KEM-768 + RSA": (5, 5, 5), "X25519 + ML-DSA-65": (10, 12, 12), "ML-KEM-768 + ML-DSA-65": (11, 13, 13)}   # payload segments per connection at MTU 1500 / 1400 / 1280 (Fig. 2)
MTUS = (1500, 1400, 1280)
def segments(flight, mss, extra, buffered=True):
    w, r = [], flight
    if buffered:
        while r > 0: w.append(min(4096, r)); r -= 4096
    else: w = [flight]
    return sum(math.ceil(x / mss) for x in w) + extra
def matches(hdr, extra, buffered):
    return sum(tuple(segments(f, m - hdr, extra, buffered) for m in MTUS) == SEGS[k] for k, f in FLIGHT.items())
print("Server payload segments per connection (published) against the model: 4096-byte writes, MSS = MTU - 52 (IPv4 + timestamps), tickets 1 + 1 and alert 1 segment")
for k, f in FLIGHT.items():
    m = tuple(segments(f, mt - 52, 3) for mt in MTUS); n = tuple(segments(f, mt - 52, 3, False) for mt in MTUS)
    print(f"  {k:24s} flight {f:6d} B  published {SEGS[k]}  write pattern {m} {'match' if m == SEGS[k] else 'DIFFERS'}  ceil(bytes/MSS) {n} {'match' if n == SEGS[k] else 'DIFFERS'}")
cells = sum(len(MTUS) for _ in FLIGHT)
print(f"cells matched: write pattern {sum(sum(a == b for a, b in zip(tuple(segments(f, mt - 52, 3) for mt in MTUS), SEGS[k])) for k, f in FLIGHT.items())} of {cells}; ceil(bytes/MSS) {sum(sum(a == b for a, b in zip(tuple(segments(f, mt - 52, 3, False) for mt in MTUS), SEGS[k])) for k, f in FLIGHT.items())} of {cells}")
print("\nSensitivity: scenarios (of 5) that match at all three MTUs")
print("  header bytes           4096-byte writes   one write per flight")
for hdr, name in ((40, "IPv4"), (52, "IPv4 + timestamps"), (60, "IPv6"), (72, "IPv6 + timestamps")):
    print(f"  {name:22s} {matches(hdr, 3, True):8d} of 5      {matches(hdr, 3, False):8d} of 5")
print("\n  segments taken by the two tickets and the alert (MSS = MTU - 52, 4096-byte writes): scenarios matching at all three MTUs")
for extra, what in ((0, "none (merged into the flight)"), (1, "one segment"), (2, "two segments"), (3, "three segments (each message leaves on its own)"), (4, "four segments")):
    print(f"  {extra} {what:48s} {matches(52, extra, True)} of 5")
print("\nFirst server flight alone (no tickets, no alert), segments against the initial window of 10: model at MTU 1500 / 1400 / 1280")
for k, f in FLIGHT.items(): print(f"  {k:24s}", tuple(segments(f, mt - 52, 0) for mt in MTUS))
