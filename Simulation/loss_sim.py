#!/usr/bin/env python3
"""
loss_sim.py - packet loss on the wired path (SimPy discrete-event, Monte Carlo).

Extends the event-driven TCP of crosscheck_simpy.py with Bernoulli loss of data segments
(ACKs are not lost) and Linux-like recovery:
  * fast retransmit once three later segments of the flight have arrived (dupack threshold 3),
    ssthresh = cwnd = max(cwnd/2, 2);
  * tail-loss probe: an undetected loss is retransmitted max(2 RTT, 10 ms) after transmission;
  * retransmission timeout for lost retransmissions: 200 ms, doubling, cwnd = 1;
  * slow start below ssthresh, congestion avoidance (+1/cwnd per ACK) above it;
  * a lost SYN or SYN-ACK costs the 1-s initial RTO (RFC 6298).
With loss = 0 the model reproduces pqc_sim.run_flow exactly (test_loss_sim.py).

    python3 loss_sim.py [trials] -> loss_results.csv

NOTE (v5): this module implements the v4 stack (ideal segmentation, cwnd += every flight). The validated stack of
pqc_sim (Linux congestion-window validation, OpenSSL write pattern) is not implemented here yet; update it before the
loss results are used in a paper (paper 2).
"""
from __future__ import annotations

import csv
import itertools
import os
import random
import statistics as st
import sys
from concurrent.futures import ProcessPoolExecutor

import simpy

import pqc_sim as S

RTO_MIN = 200.0
SYN_RTO = 1000.0


class LossyDirection:
    def __init__(self, env, net: S.Net, cwnd0: int, p: float, rng: random.Random):
        self.env, self.p, self.rng = env, p, rng
        self.mss, self.hdr = net.mtu - net.hdr, net.hdr
        self.rate = net.bw_mbps * 1e3
        self.rtt, self.owd = net.rtt_ms, net.rtt_ms / 2
        self.link = simpy.Resource(env, capacity=1)
        self.cwnd, self.ssthresh, self.inflight = float(cwnd0), float("inf"), 0
        self.segments = self.losses = self.retransmissions = 0

    # ------------------------------------------------------------------ transfer
    def transfer(self, nbytes):
        self.n = -(-nbytes // self.mss)
        self.last = nbytes - (self.n - 1) * self.mss
        self.next_new = 0
        self.delivered = set()
        self.later = {}            # lost segment -> later arrivals seen by the receiver
        self.attempt = {}          # segment -> number of retransmissions so far
        self.done = self.env.event()
        self._try_send()
        yield self.done
        return self.n

    def _try_send(self):
        while self.next_new < self.n and self.inflight < int(self.cwnd):
            i = self.next_new
            self.next_new += 1
            self.inflight += 1
            self.attempt[i] = 0
            self.env.process(self._segment(i, 0))

    def _segment(self, i, attempt):
        payload = self.last if i == self.n - 1 else self.mss
        ser = (payload + self.hdr) * 8 / self.rate
        with self.link.request() as req:
            yield req
            yield self.env.timeout(ser)
        self.segments += 1
        if self.rng.random() < self.p:
            self.losses += 1
            self.later.setdefault(i, 0)
            timeout = max(2 * self.rtt, 10.0) if attempt == 0 else RTO_MIN * 2 ** (attempt - 1)
            self.env.process(self._timer(i, attempt, timeout))
            return
        yield self.env.timeout(self.owd)
        self._arrival(i)

    def _timer(self, i, attempt, timeout):
        yield self.env.timeout(timeout)
        if i in self.delivered or self.attempt.get(i, 0) != attempt:
            return
        self.ssthresh = max(self.cwnd / 2, 2.0)
        self.cwnd = 1.0 if attempt >= 1 else self.ssthresh     # RTO collapses, TLP halves
        self._retransmit(i)

    def _retransmit(self, i):
        self.attempt[i] = self.attempt.get(i, 0) + 1
        self.retransmissions += 1
        self.env.process(self._segment(i, self.attempt[i]))

    def _arrival(self, i):
        if i in self.delivered:
            return
        self.delivered.add(i)
        for j in list(self.later):
            if j < i and j not in self.delivered:
                self.later[j] += 1
                if self.later[j] == 3 and self.attempt.get(j, 0) == 0:
                    self.env.process(self._fast_retransmit(j))
        if len(self.delivered) == self.n:
            self.done.succeed(self.env.now)
        self.env.process(self._ack())

    def _fast_retransmit(self, j):
        yield self.env.timeout(self.owd)                    # third duplicate ACK reaches the sender
        if j in self.delivered or self.attempt.get(j, 0) != 0:
            return
        self.ssthresh = max(self.cwnd / 2, 2.0)
        self.cwnd = self.ssthresh
        self._retransmit(j)

    def _ack(self):
        yield self.env.timeout(self.owd)
        self.inflight -= 1
        if self.cwnd < self.ssthresh:
            self.cwnd += 1.0
        else:
            self.cwnd += 1.0 / self.cwnd
        self._try_send()


def run_flow_lossy(flow: S.Flow, net: S.Net, p: float, seed) -> dict:
    env = simpy.Environment()
    rng = random.Random(seed)
    cw0 = net.init_cwnd if flow.mode == "cold" else net.warm_cwnd
    dirs = [LossyDirection(env, net, cw0, p, rng) for _ in range(2)]
    out = dict(syn_losses=0)

    def conversation():
        for step in flow.steps:
            if step[0] == "cpu":
                yield env.timeout(step[1])
            elif step[0] == "hs":
                for _ in range(2):                      # SYN, then SYN-ACK
                    k = 0
                    while rng.random() < p:
                        out["syn_losses"] += 1
                        yield env.timeout(SYN_RTO * 2 ** k)
                        k += 1
                    yield env.timeout(net.rtt_ms / 2)
            else:
                n = yield env.process(dirs[step[1]].transfer(step[2]))
                if n > net.thr:
                    yield env.timeout(net.penalty_ms)

    env.run(until=env.process(conversation()))
    return dict(total=env.now, losses=dirs[0].losses + dirs[1].losses + out["syn_losses"],
                retx=dirs[0].retransmissions + dirs[1].retransmissions)


SUITES = ["ECDSA-P256|X25519", "ECDSA-P256|X25519MLKEM768", "ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768",
          "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]
PROTOS = ["FAPI2", "SWIFT_MX"]
LOSS = [0.0, 0.001, 0.005, 0.01, 0.02]
RTTS = [30.0, 100.0]


def task(args):
    proto, p, rtt, trials = args
    rows = []
    net = S.Net(100.0, rtt, 1500, 6.0, 4)
    for su in SUITES:
        f = S.build_flow(su, proto, S.PROTOCOLS[proto].default_depth, "cold", False)
        lat = sorted(run_flow_lossy(f, net, p, f"loss|{proto}|{p}|{rtt}|{t}|{su}")["total"] for t in range(trials))
        q = lambda x: lat[min(len(lat) - 1, int(x * len(lat)))]
        rows.append([proto, p, rtt, su, round(st.mean(lat), 3), round(st.pstdev(lat) / len(lat) ** 0.5, 3),
                     round(q(0.5), 3), round(q(0.95), 3), round(q(0.99), 3)])
    return rows


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    tasks = [(pr, p, rtt, trials) for pr, p, rtt in itertools.product(PROTOS, LOSS, RTTS)]
    with ProcessPoolExecutor(min(len(tasks), 12)) as ex, open(os.path.join(os.path.dirname(__file__) or ".",
                                                                          "loss_results.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["protocol", "loss", "rtt_ms", "suite", "mean_ms", "se_ms", "p50_ms", "p95_ms", "p99_ms"])
        for rows in ex.map(task, tasks):
            w.writerows(rows)
    print(f"[loss_sim] {len(tasks) * len(SUITES)} cells x {trials} trials")


if __name__ == "__main__":
    main()
