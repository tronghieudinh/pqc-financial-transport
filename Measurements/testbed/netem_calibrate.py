#!/usr/bin/env python3
"""
netem_calibrate.py - the RTT that the testbed REALLY delivers, recorded with every measurement run.

shaper_probe.py (2026-11-15) showed that the netem delay of the testbed overshoots the configured value by a machine-dependent amount: a nominal 30 ms
round trip measured 30.7 ms on the X250 (two runs, +0.66 to +0.79 ms) and 31.1-31.3 ms on the GX10 (+1.07 to +1.31 ms). A transaction has 3-4 round trips, so the
excess latency of a configuration is off by that many times the overshoot, which is about the size of the differences between machines that replication
criteria R2 and R5 could not explain. This tool measures the overshoot with plain `ping` through the same veth pair, shaped with the same tbnet.py code, so that every
data set carries its own number and runs on different machines or at different times can be corrected or compared.

  sudo python3 netem_calibrate.py --out FILE.json          # RTT 5 and 30 ms, 30 pings each, about 15 s; refuses if the namespaces pqcc/pqcs exist
  python3 netem_calibrate.py --dry-run                     # plan only (no root)
  python3 netem_calibrate.py --selftest                    # parser test (no root)
Output (JSON): base_rtt0_ms (unshaped ping, the stack and veth cost), and for every nominal RTT: median_ms, p10_ms, p90_ms, n, over_ms = median - base - nominal.
`over_ms` is the quantity to subtract per round trip. Never fatal for a measurement: callers ignore a non-zero exit status.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import socket
import statistics as st
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
TIME_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")


def parse_ping(text: str) -> list:
    """RTT samples (ms) of a ping run: every 'time=X ms' line (the first reply is dropped by the caller: neighbour discovery)."""
    return [float(m.group(1)) for m in TIME_RE.finditer(text)]


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))]


def summarize(samples: list) -> dict:
    s = samples[1:] if len(samples) > 3 else samples          # first reply includes neighbour discovery
    return {"n": len(s), "median_ms": round(st.median(s), 3), "p10_ms": round(pct(s, 10), 3), "p90_ms": round(pct(s, 90), 3)} if s else {"n": 0}


def selftest() -> int:
    t = "PING fd99:1::2 ...\n64 bytes from fd99:1::2: icmp_seq=1 ttl=64 time=31.9 ms\n64 bytes from fd99:1::2: icmp_seq=2 ttl=64 time=30.71 ms\n" \
        "64 bytes from fd99:1::2: icmp_seq=3 ttl=64 time=30.69 ms\n64 bytes from fd99:1::2: icmp_seq=4 ttl=64 time=30.72 ms\n--- stats ---\n"
    x = parse_ping(t)
    assert x == [31.9, 30.71, 30.69, 30.72], x
    s = summarize(x)
    assert s["n"] == 3 and abs(s["median_ms"] - 30.71) < 1e-9, s
    assert parse_ping("time<1 ms") == [1.0]
    print("selftest OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default="")
    ap.add_argument("--rtts", default="5,30", help="nominal RTTs in ms, comma separated")
    ap.add_argument("--count", type=int, default=30)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    rtts = [float(x) for x in a.rtts.split(",")]
    if a.dry_run:
        print(f"plan: build the veth pair pqcc/pqcs (tbnet.py), unshaped ping x{a.count}, then ping x{a.count} at each nominal RTT {rtts} ms (netem delay only), tear down, write {a.out or '(stdout)'}")
        return 0
    if os.geteuid() != 0:
        print("needs root", file=sys.stderr)
        return 2
    ns = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    if any(n in ns for n in ("pqcc", "pqcp", "pqcs")):
        print("namespaces pqcc/pqcp/pqcs exist (a measurement is running): not calibrating", file=sys.stderr)
        return 3
    from tbnet import Testbed, NS_C, A_P1
    tb = Testbed("direct")
    res = {"host": socket.gethostname().split(".")[0], "kernel": platform.release(), "machine": platform.machine(),
           "time": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "count": a.count, "cells": {}}
    try:
        tb.up()

        def ping():
            r = subprocess.run(["ip", "netns", "exec", NS_C, "ping", "-6", "-c", str(a.count + 1), "-i", "0.2", "-W", "2", A_P1], capture_output=True, text=True)
            return summarize(parse_ping(r.stdout))
        tb.shape(0, 0, 0, 1500, 10)                              # unshaped: veth and stack only
        base = ping()
        res["base_rtt0_ms"] = base.get("median_ms")
        for rtt in rtts:
            tb.shape(rtt, 0, 0, 1500, 10)
            c = ping()
            if c.get("n") and base.get("n"):
                c["nominal_ms"] = rtt
                c["over_ms"] = round(c["median_ms"] - base["median_ms"] - rtt, 3)
            res["cells"][f"{rtt:g}"] = c
    finally:
        tb.down()
    text = json.dumps(res, indent=1)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text + "\n")
        if os.environ.get("SUDO_UID"):
            try:
                os.chown(a.out, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"])))
            except OSError:
                pass
    print(" ".join(f"RTT {k}: median {v.get('median_ms')} ms, over {v.get('over_ms')} ms" for k, v in res["cells"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
