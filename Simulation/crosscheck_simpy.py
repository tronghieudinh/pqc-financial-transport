#!/usr/bin/env python3
"""
crosscheck_simpy.py - discrete-event cross-check of the TCP model in pqc_sim.py.

pqc_sim.run_flow() computes each transfer with a per-segment recurrence
(_tcp_xfer). This file re-implements the same physical system as a SimPy
discrete-event simulation that shares NO code with that recurrence:

    * every segment is a process that queues on a FIFO link (simpy.Resource),
      is serialized (bytes*8/bandwidth), then propagates for RTT/2;
    * the receiver emits real ACK events (one per segment, or every k-th);
    * the sender is event-driven: on each ACK, cwnd += acked, inflight -= acked,
      then it sends while inflight < cwnd (slow start, no loss);
    * cwnd/inflight persist for the life of the connection, per direction.

With the default one-ACK-per-segment the two implementations must agree to
floating-point precision on latency, serialization time, segment and byte
counts. A disagreement means one of the two has a bug.

`--ack-every 2` (delayed ACKs) is NOT expected to match; it quantifies how
sensitive the closed-form model is to its one-ACK-per-segment assumption.

    .venv/bin/python crosscheck_simpy.py                 # 5,000 random configs
    .venv/bin/python crosscheck_simpy.py --full          # whole user grid (pen 0/24)
    .venv/bin/python crosscheck_simpy.py --ack-every 2   # delayed-ACK sensitivity
"""
from __future__ import annotations

import argparse
import itertools
import math
import random
import statistics as st
import sys
import time
from concurrent.futures import ProcessPoolExecutor

import simpy

import pqc_sim as S

TOL_MS = 1e-6


class Direction:
    """One TCP sender (client->server or server->client) with persistent state.

    Independent of pqc_sim: the application hands the sender `write()` calls; the sender keeps a byte queue and
    sends a segment whenever the congestion window has room (a partial tail too: TCP_NODELAY). Slow start adds
    one segment per ACKed segment, and with `validate` (Linux tcp_is_cwnd_limited) only while cwnd is below twice
    the maximum number of segments that were in flight during the transfer.
    """

    def __init__(self, env, net: S.Net, cwnd0: int, ack_every: int):
        self.env = env
        self.mss = net.mtu - net.hdr
        self.hdr = net.hdr
        self.rate = net.bw_mbps * 1e3          # bits per ms
        self.owd = net.rtt_ms / 2
        self.link = simpy.Resource(env, capacity=1)   # FIFO serialization
        self.cwnd = cwnd0
        self.validate = net.cwnd_validation
        self.inflight = 0
        self.ack_every = ack_every
        self.busy = 0.0                         # total serialization time
        self.segments = 0
        self.wire = 0
        # state of the transfer currently being sent
        self._queued = self._total = self._delivered = self._unacked = self._nseg = self._max_out = 0
        self._done = None

    # -- sender side -----------------------------------------------------
    def _try_send(self):
        while self._queued > 0 and self.inflight < self.cwnd:
            payload = min(self._queued, self.mss)
            self._queued -= payload
            self.inflight += 1
            self._max_out = max(self._max_out, self.inflight)
            self._nseg += 1
            self.env.process(self._segment(payload))

    def _segment(self, payload):
        ser = (payload + self.hdr) * 8 / self.rate
        with self.link.request() as req:
            yield req
            yield self.env.timeout(ser)
            self.busy += ser
        self.segments += 1
        self.wire += payload + self.hdr
        yield self.env.timeout(self.owd)        # propagation to the receiver
        self._on_arrival(payload)

    # -- receiver side ---------------------------------------------------
    def _on_arrival(self, payload):
        self._delivered += payload
        self._unacked += 1
        last = self._delivered == self._total
        if self._unacked >= self.ack_every or last:    # last segment is ACKed at once
            count, self._unacked = self._unacked, 0
            self.env.process(self._ack(count))
        if last:
            self._done.succeed(self.env.now)

    def _ack(self, count):
        yield self.env.timeout(self.owd)        # ACK travels back (zero size)
        if not self.validate or self.cwnd < 2 * self._max_out:
            self.cwnd += count                  # slow start: +1 segment per ACKed segment
        self.inflight -= count
        self._try_send()

    # -- API -------------------------------------------------------------
    def transfer(self, writes):
        """Process: issue the write() calls back to back, finish when the last byte reaches the receiver."""
        self._total = sum(writes)
        self._queued = self._delivered = self._unacked = self._nseg = self._max_out = 0
        self._done = self.env.event()
        for w in writes:
            self._queued += w
            self._try_send()
        yield self._done
        return self._nseg


def run_flow_des(flow: S.Flow, net: S.Net, ack_every: int = 1) -> dict:
    env = simpy.Environment()
    cw0 = net.init_cwnd if flow.mode == "cold" else net.warm_cwnd
    sides = [Direction(env, net, cw0, ack_every) for _ in range(2)]
    out = dict(pen_flights=0, max_flight=0)
    xi = [0]

    def conversation():
        for st_ in flow.steps:
            if st_[0] == "cpu":
                yield env.timeout(st_[1])
            elif st_[0] == "hs":
                yield env.timeout(net.rtt_ms)
            else:
                writes = flow.writes[xi[0]] if (net.segmentation == "openssl" and flow.writes) else (st_[2],)
                xi[0] += 1
                n = yield env.process(sides[st_[1]].transfer(writes))
                out["max_flight"] = max(out["max_flight"], n)
                if n > net.thr:
                    out["pen_flights"] += 1
                    yield env.timeout(net.penalty_ms)

    # Stop when the transaction completes, not when the last (irrelevant) ACK lands.
    env.run(until=env.process(conversation()))
    out.update(total=env.now, ser=sum(s.busy for s in sides),
               segs=sum(s.segments for s in sides), wire=sum(s.wire for s in sides))
    return out


def compare(case, ack_every, stack="linux-openssl"):
    sn, pn, mode, depth, cc, bw, rtt, mtu, pen, thr = case
    f = S.build_flow(sn, pn, depth, mode, cc)
    net = S.Net(bw, rtt, mtu, pen, thr, **S.STACKS[stack])
    a = S.run_flow(f, net)
    b = run_flow_des(f, net, ack_every)
    return dict(case=case, closed=a["total"], des=b["total"], d_total=b["total"] - a["total"],
                d_ser=b["ser"] - a["ser"], d_segs=b["segs"] - a["segs"], d_wire=b["wire"] - a["wire"],
                d_pen=b["pen_flights"] - a["pen_flights"], d_maxf=b["max_flight"] - a["max_flight"])


def all_cases(bws, rtts, mtus, pens, thrs, depths=(1, 2, 3, 4)):
    for sn, pn in itertools.product(S.SUITES, S.PROTOCOLS):
        for mode, cc, d in [("warm", False, 0)] + [("cold", c, d) for d in depths for c in (False, True)]:
            for bw, rtt, mtu, pen, thr in itertools.product(bws, rtts, mtus, pens, thrs):
                yield (sn, pn, mode, d, cc, bw, rtt, mtu, pen, thr)


def _worker(args):
    cases, ack_every, stack = args
    return [compare(c, ack_every, stack) for c in cases]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", type=int, default=5000)
    ap.add_argument("--full", action="store_true", help="whole user grid with penalties 0 and 24")
    ap.add_argument("--ack-every", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--stack", choices=list(S.STACKS), default="linux-openssl")
    a = ap.parse_args()

    bws, rtts, mtus = (10.0, 100.0, 200.0, 400.0, 800.0, 1600.0), (5.0, 12.0, 30.0, 50.0, 100.0), (1280, 1500, 9000)
    if a.full:
        cases = list(all_cases(bws, rtts, mtus, (0.0, 24.0), (4,)))
    else:
        pool = all_cases(bws, rtts, mtus, (0.0, 3.0, 6.0, 12.0, 24.0), (2, 4, 8, 16))
        cases = random.Random(a.seed).sample(list(pool), a.samples)
    t0 = time.time()
    chunks = [(cases[i::max(1, a.jobs)], a.ack_every, a.stack) for i in range(max(1, a.jobs))]
    if a.jobs > 1:
        with ProcessPoolExecutor(a.jobs) as ex:
            res = [r for part in ex.map(_worker, chunks) for r in part]
    else:
        res = [r for c in chunks for r in _worker(c)]
    dt = time.time() - t0

    print(f"[crosscheck] {len(res):,} flows, stack={a.stack}, ack_every={a.ack_every}, {dt:.1f}s")
    if a.ack_every == 1:
        bad = [r for r in res if abs(r["d_total"]) > TOL_MS or abs(r["d_ser"]) > TOL_MS or
               r["d_segs"] or r["d_wire"] or r["d_pen"] or r["d_maxf"]]
        mx = max(abs(r["d_total"]) for r in res)
        print(f"max |latency difference| = {mx:.3e} ms (tolerance {TOL_MS:g}); "
              f"mismatches: {len(bad)}")
        if bad:
            w = max(bad, key=lambda r: abs(r["d_total"]))
            print("worst:", w)
            sys.exit(1)
        print("PASS: event-driven SimPy model reproduces the closed-form TCP model exactly.")
    else:
        print("Delayed-ACK sensitivity (SimPy - closed form), per suite, cold, latency increase:")
        print(f"{'suite':28s} {'median ms':>10s} {'p95 ms':>9s} {'max ms':>9s} {'median %':>9s}")
        for s in S.SUITES:
            rows = [r for r in res if r["case"][0] == s and r["case"][2] == "cold"]
            if not rows:
                continue
            d = sorted(r["d_total"] for r in rows)
            pc = [100 * r["d_total"] / r["closed"] for r in rows]
            print(f"{s:28s} {st.median(d):10.2f} {d[int(.95 * (len(d) - 1))]:9.2f} {d[-1]:9.2f} {st.median(pc):9.1f}")


if __name__ == "__main__":
    main()
