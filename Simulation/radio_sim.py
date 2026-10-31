#!/usr/bin/env python3
"""
radio_sim.py - PQC banking transactions over 5G NR and (assumed) 6G radio links
with different noise levels.

Extends pqc_sim.py. The wired model of pqc_sim is replaced, for the terminal
side, by a stochastic radio hop; the TCP/TLS flows (sizes, CPU, flights) are
exactly those built by pqc_sim.build_flow(). Everything runs as a SimPy
discrete-event simulation with Monte Carlo trials.

Topology      client (phone / POS / ATM) -UL/DL radio- RAN/core/internet -- bank server
              data client->server : UL radio hop, then wired one-way delay
              data server->client : wired one-way delay, then DL radio hop
              ACKs                : the reverse path (small packets, never lost)

Noise         `sinr_db` = mean downlink SINR. Uplink = sinr_db - ul_sinr_offset_db.
Radio hop (per direction, per transaction)
  1. rank adaptation:  layers = clamp(1 + floor((SINR-5)/5), 1, max_layers)
  2. link adaptation:  CQI error e_la ~ N(0, sigma_la). The scheduler picks the
     spectral efficiency SE = clamp(log2(1 + SINR_rep/(gap)), se_min, se_cap) with
     SINR_rep = SINR + e_la - backoff; `backoff` is calibrated (OLLA-like) so that
     the long-run first-transmission BLER equals `bler_target`.
  3. rate  = BW * layers * SE * eff * tdd_share * user_share.
  4. TB error: BLER(margin) = 1 / (1 + 9 * exp(slope * margin_dB)) (10 % at margin 0),
     margin = SINR + e_fade - SINR_required(SE),  e_fade ~ N(0, sigma_fade) per attempt.
  5. HARQ with chase combining (gain 10*log10(attempts) dB), `max_harq` attempts,
     one retransmission round = `harq_rtt_ms`, retransmissions use air time.
  6. RLC-AM ARQ for TBs that exhaust HARQ: +`rlc_delay_ms` per cycle, `max_rlc` cycles;
     beyond that the IP packet is lost and TCP retransmits after `rto_ms`
     (cwnd is NOT reduced - simplification; losses are rare).
  7. in-order delivery (RLC/PDCP reordering): a HARQ retry delays every packet behind it.
  8. blockage (mmWave / sub-THz): alternating Exp on/off periods; a packet sent while
     blocked is delivered only after the blockage ends (+ RLC delay).

IMPORTANT - 5G profiles follow 3GPP/ITU targets and common deployments; the 6G profiles
are ASSUMPTIONS based on IMT-2030 vision targets (sub-ms air latency, >=300 Mbps
user-experienced rate), not measurements of any system. All inputs are in
`PROFILES` / `assumptions` output and overridable by editing the table.

    .venv/bin/python radio_sim.py --out radio_results
    .venv/bin/python radio_sim.py --out radio_quick --trials 30 --suites "ECDSA-P256|X25519,ML-DSA-65|ML-KEM-768"

NOTE (v5): the TCP replay here implements the v4 stack (cwnd += every flight, ideal segmentation); the validated
stack of pqc_sim is not implemented yet. Update it before the radio results are used in a paper (paper 3).
"""
from __future__ import annotations

import argparse
import bisect
import csv
import itertools
import json
import math
import os
import random
import statistics as st
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, asdict
from functools import lru_cache

import simpy

import pqc_sim as S


# =============================================================================
# 1. RADIO PROFILES (inputs; see module docstring for provenance)
# =============================================================================


@dataclass(frozen=True)
class Radio:
    name: str
    gen: str
    note: str
    bw_hz: float
    layers_dl: int
    layers_ul: int
    eff: float               # share of resources carrying user data (control/DMRS/guard excluded)
    tdd_dl: float            # fraction of time usable for DL / UL
    tdd_ul: float
    user_share: float        # share of the cell this UE gets (load)
    se_cap: float            # max spectral efficiency, bit/s/Hz per layer (modulation limit)
    ul_sinr_offset_db: float
    tti_ms: float
    harq_rtt_ms: float
    dl_base_ms: float        # RAN one-way latency excluding queueing/serialization
    ul_base_ms: float        # (UL includes scheduling-request / grant latency)
    sigma_la_db: float       # CQI estimation/aging error (per transaction)
    sigma_fade_db: float     # residual fast fading per transmission attempt
    bler_target: float       # first-transmission BLER the scheduler aims for
    rlc_delay_ms: float      # RLC-AM status/poll cycle
    p_block: float           # stationary probability of being blocked
    block_ms: float          # mean blockage duration
    max_harq: int = 4
    max_rlc: int = 4
    slope: float = 2.2       # BLER waterfall steepness (1/dB)
    gap_db: float = 2.0      # SNR gap to Shannon
    se_min: float = 0.15     # lowest MCS (QPSK, rate ~0.08)
    rto_ms: float = 200.0    # Linux minimum RTO


PROFILES = {p.name: p for p in [
    Radio("5G-NR sub-6 (eMBB)", "5G",
          "n78 100 MHz TDD, 30 kHz SCS, 4 layers DL / 1 UL, BLER target 10 %, 3GPP TR 38.913 eMBB",
          100e6, 4, 1, 0.75, 0.74, 0.25, 0.25, 7.4, 6.0, 0.5, 4.0, 2.0, 5.0,
          1.5, 2.0, 0.10, 20.0, 0.0, 0.0),
    Radio("5G-NR URLLC", "5G",
          "mini-slot, conservative MCS (BLER target 1e-3), configured grant, small user share",
          100e6, 2, 1, 0.70, 0.50, 0.50, 0.10, 6.0, 4.0, 0.143, 1.0, 0.5, 0.7,
          1.5, 2.0, 1e-3, 5.0, 0.0, 0.0),
    Radio("5G-NR mmWave (FR2)", "5G",
          "n257 400 MHz, 120 kHz SCS, 2 layers DL / 1 UL, human-body blockage",
          400e6, 2, 1, 0.70, 0.75, 0.25, 0.25, 6.0, 8.0, 0.125, 1.5, 1.0, 3.0,
          1.5, 3.0, 0.10, 15.0, 0.08, 150.0),
    Radio("6G upper mid-band (FR3, assumed)", "6G",
          "ASSUMED: 7-15 GHz, 400 MHz, 8 layers DL / 2 UL, sub-ms air interface, better CQI prediction",
          400e6, 8, 2, 0.80, 0.60, 0.40, 0.25, 8.0, 5.0, 0.125, 1.0, 0.4, 1.0,
          1.0, 2.0, 0.10, 6.0, 0.01, 60.0),
    Radio("6G sub-THz (assumed)", "6G",
          "ASSUMED: 140-300 GHz, 2 GHz, 4 layers DL / 2 UL, 0.1 ms TTI, frequent blockage",
          2e9, 4, 2, 0.75, 0.60, 0.40, 0.20, 6.0, 10.0, 0.1, 0.5, 0.15, 0.4,
          1.0, 3.0, 0.10, 3.0, 0.10, 80.0),
]}


# =============================================================================
# 2. LINK-LEVEL MATHEMATICS
# =============================================================================


def bler(margin_db: float, slope: float) -> float:
    """Block error rate for a SINR margin over the MCS threshold (10 % at 0 dB)."""
    x = max(-60.0, min(60.0, slope * margin_db))
    return 1.0 / (1.0 + 9.0 * math.exp(x))


@lru_cache(maxsize=None)
def _quad(n: int = 25, span: float = 4.0):
    zs = [-span + 2 * span * j / (n - 1) for j in range(n)]
    w = [math.exp(-z * z / 2) for z in zs]
    s = sum(w)
    return tuple(zs), tuple(x / s for x in w)


@lru_cache(maxsize=None)
def calibrate_backoff(sigma_tot: float, target: float, slope: float) -> float:
    """Back-off (dB) so that E[BLER] over N(0, sigma_tot) fading equals `target`."""
    zs, ws = _quad()
    lo, hi = -30.0, 60.0
    for _ in range(60):
        mid = (lo + hi) / 2
        mean = sum(w * bler(mid + sigma_tot * z, slope) for z, w in zip(zs, ws))
        if mean > target:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def _binom(rng: random.Random, n: int, p: float) -> int:
    if n <= 0 or p <= 0.0:
        return 0
    if p >= 1.0:
        return n
    return rng.binomialvariate(n, p)


class Blockage:
    """Alternating Exp(blocked) / Exp(clear) renewal process, stationary start."""

    def __init__(self, rng: random.Random, p: float, mean_ms: float, horizon: float = 8000.0):
        self.iv = []
        if p <= 0.0:
            self.starts = []
            return
        mean_up = mean_ms * (1 - p) / p
        t, blocked = 0.0, rng.random() < p
        while t < horizon:
            if blocked:
                d = rng.expovariate(1 / mean_ms)
                self.iv.append((t, t + d))
                t += d
            else:
                t += rng.expovariate(1 / mean_up)
            blocked = not blocked
        self.starts = [a for a, _ in self.iv]

    def until(self, t: float):
        i = bisect.bisect_right(self.starts, t) - 1
        if i >= 0 and t < self.iv[i][1]:
            return self.iv[i][1]
        return None


class Hop:
    """One radio direction for one transaction."""

    def __init__(self, env, prof: Radio, sinr_db: float, uplink: bool, rng_env, rng_pkt,
                 blk: Blockage, fixed_rate_mbps=None):
        self.env, self.p, self.rng, self.blk = env, prof, rng_pkt, blk
        self.up = uplink
        self.res = simpy.Resource(env, capacity=1)           # FIFO air-interface scheduler
        self.base = prof.ul_base_ms if uplink else prof.dl_base_ms
        self.last_delivery = 0.0
        self.tb_total = self.retx = self.rlc = self.losses = 0
        z = rng_env.gauss(0.0, 1.0)                           # per-transaction CQI error draw
        if fixed_rate_mbps is not None:                       # ideal link (validation only)
            self.rate = fixed_rate_mbps * 1e3
            self.pr = [0.0] * prof.max_harq
            self.se = float("nan")
            return
        sinr = sinr_db - (prof.ul_sinr_offset_db if uplink else 0.0)
        layers = prof.layers_ul if uplink else prof.layers_dl
        rank = max(1, min(layers, 1 + int(math.floor((sinr - 5.0) / 5.0))))
        sig_tot = math.hypot(prof.sigma_la_db, prof.sigma_fade_db)
        backoff = calibrate_backoff(round(sig_tot, 6), prof.bler_target, prof.slope)
        gap = 10 ** (prof.gap_db / 10)
        g_req = sinr + prof.sigma_la_db * z - backoff
        se = math.log2(1.0 + 10 ** (g_req / 10) / gap)
        se = max(prof.se_min, min(prof.se_cap, se))
        g_eff = 10 * math.log10(gap * (2 ** se - 1.0))        # SINR at which this MCS has 10 % BLER
        m0 = sinr - g_eff
        zs, ws = _quad()
        self.pr = [sum(w * bler(m0 + prof.sigma_fade_db * zz + 10 * math.log10(r + 1), prof.slope)
                       for zz, w in zip(zs, ws)) for r in range(prof.max_harq)]
        share = prof.tdd_ul if uplink else prof.tdd_dl
        self.se = se
        self.rate = prof.bw_hz / 1e3 * rank * se * prof.eff * share * prof.user_share   # bit/ms

    # -- one packet through HARQ / RLC --------------------------------------------
    def plan(self, nbytes: int):
        p, rng = self.p, self.rng
        bits = 8.0 * nbytes
        n_tb = max(1, math.ceil(bits / (self.rate * p.tti_ms)))
        air = bits / self.rate
        rem, rounds, retx, rlc, lost, cycle = n_tb, 0, 0, 0, False, 0
        while True:
            k = rem
            if cycle > 0:
                retx += rem                                   # RLC re-sends these TBs
            for r in range(p.max_harq):
                f = _binom(rng, k, self.pr[r])
                if f == 0:
                    k = 0
                    break
                if r < p.max_harq - 1:
                    retx += f
                    rounds += 1
                k = f
            if k == 0:
                break
            rlc += 1
            if rlc > p.max_rlc:
                lost = True
                break
            rem, cycle = k, cycle + 1
        busy = air * (n_tb + retx) / n_tb
        delay = rounds * p.harq_rtt_ms + rlc * p.rlc_delay_ms
        return n_tb, air, busy, delay, retx, rlc, lost

    def small(self) -> float:
        """Delay of a tiny packet (ACK, SYN): base latency + HARQ/RLC retries, never lost."""
        if self.p.max_harq <= 0:
            return self.base
        _, _, _, delay, _, rlc, lost = self.plan(60)
        if lost:
            delay += self.p.max_rlc * self.p.rlc_delay_ms
        bu = self.blk.until(self.env.now)
        if bu is not None:
            delay = max(delay, bu - self.env.now + self.p.rlc_delay_ms)
        return self.base + delay

    def send(self, nbytes: int):
        """Process: returns True when the packet is delivered, False if lost."""
        env = self.env
        with self.res.request() as req:
            yield req
            n_tb, air, busy, delay, retx, rlc, lost = self.plan(nbytes)
            t0 = env.now
            comp = t0 + air + delay
            bu = self.blk.until(t0)
            if bu is not None:
                comp = max(comp, bu + self.p.rlc_delay_ms + air)
                rlc += 1
            self.tb_total += n_tb
            self.retx += retx
            self.rlc += rlc
            deliver = max(comp, self.last_delivery, t0 + busy)   # in-order delivery
            self.last_delivery = deliver
            yield env.timeout(busy)
        if lost:
            self.losses += 1
            return False
        wait = deliver + self.base - env.now
        if wait > 0:
            yield env.timeout(wait)
        return True


# =============================================================================
# 3. TCP OVER THE RADIO PATH
# =============================================================================


class RDir:
    """ACK-clocked slow-start sender (same semantics as crosscheck_simpy.Direction)."""

    def __init__(self, env, side, hop, ack_fn, wired_owd, mss, hdr, cwnd0, rto):
        self.env, self.side, self.hop, self.ack_fn = env, side, hop, ack_fn
        self.owd, self.mss, self.hdr, self.rto = wired_owd, mss, hdr, rto
        self.cwnd, self.inflight = cwnd0, 0
        self.segments = self.wire = self.losses = 0
        self._n = self._sent = self._delivered = self._last_payload = 0
        self._done = None

    def _try_send(self):
        while self._sent < self._n and self.inflight < self.cwnd:
            i = self._sent
            self._sent += 1
            self.inflight += 1
            self.env.process(self._segment(i, self._last_payload if i == self._n - 1 else self.mss))

    def _segment(self, i, payload):
        env, pkt = self.env, payload + self.hdr
        while True:
            t_send = env.now
            if self.side == 1:
                yield env.timeout(self.owd)                  # server -> RAN, then DL radio
            ok = yield env.process(self.hop.send(pkt))
            if ok:
                if self.side == 0:
                    yield env.timeout(self.owd)              # UL radio, then RAN -> server
                break
            self.losses += 1
            if env.now - t_send < self.rto:
                yield env.timeout(self.rto - (env.now - t_send))
        self.segments += 1
        self.wire += pkt
        self._delivered += 1
        if self._delivered == self._n:
            self._done.succeed(env.now)
        env.process(self._ack())

    def _ack(self):
        yield self.env.timeout(self.ack_fn())
        self.cwnd += 1
        self.inflight -= 1
        self._try_send()

    def transfer(self, nbytes):
        self._n = -(-nbytes // self.mss)
        self._last_payload = nbytes - (self._n - 1) * self.mss
        self._sent = self._delivered = 0
        self._done = self.env.event()
        self._try_send()
        yield self._done
        return self._n


def run_radio_flow(flow: S.Flow, prof: Radio, sinr_db: float, wired_rtt_ms: float, mtu: int,
                   seed_env, seed_pkt, fixed_rate_mbps=None, init_cwnd=10, warm_cwnd=10) -> dict:
    env = simpy.Environment()
    rng_env, rng_pkt = random.Random(seed_env), random.Random(seed_pkt)
    blk = Blockage(rng_env, prof.p_block, prof.block_ms)
    ul = Hop(env, prof, sinr_db, True, rng_env, rng_pkt, blk, fixed_rate_mbps)
    dl = Hop(env, prof, sinr_db, False, rng_env, rng_pkt, blk, fixed_rate_mbps)
    owd = wired_rtt_ms / 2
    mss, hdr = mtu - S.IP_TCP_HDR, S.IP_TCP_HDR
    cw0 = init_cwnd if flow.mode == "cold" else warm_cwnd
    dirs = [RDir(env, 0, ul, lambda: owd + dl.small(), owd, mss, hdr, cw0, prof.rto_ms),
            RDir(env, 1, dl, lambda: ul.small() + owd, owd, mss, hdr, cw0, prof.rto_ms)]

    def conversation():
        for step in flow.steps:
            if step[0] == "cpu":
                yield env.timeout(step[1])
            elif step[0] == "hs":
                yield env.timeout(ul.small() + wired_rtt_ms + dl.small())
            else:
                yield env.process(dirs[step[1]].transfer(step[2]))

    env.run(until=env.process(conversation()))
    tb = ul.tb_total + dl.tb_total
    return dict(total=env.now, tb=tb, retx=ul.retx + dl.retx, rlc=ul.rlc + dl.rlc,
                losses=dirs[0].losses + dirs[1].losses, segs=dirs[0].segments + dirs[1].segments,
                ul_mbps=ul.rate / 1e3, dl_mbps=dl.rate / 1e3)


# =============================================================================
# 4. LINK SUMMARY AND SWEEPS
# =============================================================================


def link_summary(prof: Radio, sinr_db: float, samples: int = 300, seed: int = 1):
    """Average link properties over the per-transaction CQI error."""
    env = simpy.Environment()
    rng = random.Random(f"link|{seed}|{prof.name}|{sinr_db}")
    out = dict(dl=[], ul=[], p0=[], tx=[], fail=[])
    for _ in range(samples):
        blk = Blockage(rng, 0.0, 1.0)
        for up, key in ((False, "dl"), (True, "ul")):
            h = Hop(env, prof, sinr_db, up, rng, rng, blk)
            out[key].append(h.rate / 1e3)
            if not up:
                pr = h.pr
                out["p0"].append(pr[0])
                tx, run = 1.0, 1.0
                for r in range(prof.max_harq - 1):
                    run *= pr[r]
                    tx += run
                out["tx"].append(tx)
                out["fail"].append(math.prod(pr))
    m = lambda v: sum(v) / len(v)
    return dict(profile=prof.name, gen=prof.gen, sinr_db=sinr_db, dl_mbps=m(out["dl"]),
                ul_mbps=m(out["ul"]), bler_first_tx=m(out["p0"]), tx_per_tb=m(out["tx"]),
                harq_fail=m(out["fail"]), blockage=prof.p_block,
                ran_rtt_floor_ms=prof.dl_base_ms + prof.ul_base_ms)


ROW_COLS = ["profile", "gen", "sinr_db", "suite", "sig", "family", "protocol", "mode", "depth",
            "wired_rtt_ms", "mtu", "trials", "mean_ms", "std_ms", "p50_ms", "p95_ms", "p99_ms",
            "max_ms", "miss_200ms", "miss_500ms", "miss_1000ms", "retx_per_tb", "rlc_per_flow",
            "loss_per_flow", "dl_mbps", "ul_mbps", "cpu_ms", "l7_bytes", "segs"]
DEADLINES = (200.0, 500.0, 1000.0)


def sweep_task(args):
    prof_name, suite, proto, cfg = args
    prof = PROFILES[prof_name]
    su = S.SUITES[suite]
    rows = []
    modes = [("cold", d) for d in cfg["depths"]] + ([("warm", 0)] if cfg["warm"] else [])
    for sinr, (mode, depth), wrtt in itertools.product(cfg["sinrs"], modes, cfg["wired_rtts"]):
        flow = S.build_flow(suite, proto, depth, mode, False)
        cpu = sum(s[1] for s in flow.steps if s[0] == "cpu")
        lat, tb, retx, rlc, loss, dl, ul, segs = [], 0, 0, 0, 0, 0.0, 0.0, 0
        for t in range(cfg["trials"]):
            key = f"{cfg['seed']}|{prof_name}|{sinr}|{proto}|{mode}|{depth}|{wrtt}|{t}"
            r = run_radio_flow(flow, prof, sinr, wrtt, cfg["mtu"], "env|" + key,
                               f"pkt|{suite}|" + key, init_cwnd=cfg["init_cwnd"],
                               warm_cwnd=cfg["warm_cwnd"])
            lat.append(r["total"])
            tb += r["tb"]; retx += r["retx"]; rlc += r["rlc"]; loss += r["losses"]
            dl += r["dl_mbps"]; ul += r["ul_mbps"]; segs += r["segs"]
        lat.sort()
        n = len(lat)
        q = lambda p: lat[min(n - 1, int(p * n))]
        rows.append([prof_name, prof.gen, sinr, suite, su.sig, S.SIGS[su.sig].family, proto, mode,
                     depth, wrtt, cfg["mtu"], n, round(sum(lat) / n, 3),
                     round(st.pstdev(lat), 3), round(q(.5), 3), round(q(.95), 3), round(q(.99), 3),
                     round(lat[-1], 3)] + [round(sum(x > d for x in lat) / n, 4) for d in DEADLINES] +
                    [round(retx / max(1, tb), 4), round(rlc / n, 4), round(loss / n, 4),
                     round(dl / n, 2), round(ul / n, 2), round(cpu, 3), flow.sizes["total_l7"],
                     round(segs / n, 1)])
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="radio_results")
    ap.add_argument("--profiles", default="all", help="'all', one profile name, or names separated by ';'")
    ap.add_argument("--sinr", default="30,20,15,10,5,0,-5", help="mean DL SINR levels in dB")
    ap.add_argument("--suites", default="all")
    ap.add_argument("--protocols", default="all")
    ap.add_argument("--depths", default="2", help="chain depths for cold connections")
    ap.add_argument("--no-warm", action="store_true")
    ap.add_argument("--wired-rtts", default="20", help="RAN-to-server RTT(s) in ms")
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--init-cwnd", type=int, default=10)
    ap.add_argument("--warm-cwnd", type=int, default=10)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    a = ap.parse_args(argv)

    if a.profiles == "all":
        profs = list(PROFILES)
    elif a.profiles in PROFILES:                  # a single profile whose name contains a comma
        profs = [a.profiles]
    else:                                         # ';' separates several names (names may contain ',')
        profs = a.profiles.split(";") if ";" in a.profiles else a.profiles.split(",")
    suites = list(S.SUITES) if a.suites == "all" else a.suites.split(",")
    protos = list(S.PROTOCOLS) if a.protocols == "all" else a.protocols.split(",")
    sinrs = S.parse_list(a.sinr, float)
    cfg = dict(sinrs=sinrs, depths=S.parse_list(a.depths, int), warm=not a.no_warm,
               wired_rtts=S.parse_list(a.wired_rtts, float), mtu=a.mtu, trials=a.trials,
               seed=a.seed, init_cwnd=a.init_cwnd, warm_cwnd=a.warm_cwnd)
    os.makedirs(a.out, exist_ok=True)

    with open(os.path.join(a.out, "radio_links.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        cols = ["profile", "gen", "sinr_db", "dl_mbps", "ul_mbps", "bler_first_tx", "tx_per_tb",
                "harq_fail", "blockage", "ran_rtt_floor_ms"]
        w.writerow(cols)
        for pn in profs:
            for s in sinrs:
                d = link_summary(PROFILES[pn], s)
                w.writerow([d[c] if isinstance(d[c], str) else (f"{d[c]:.6g}") for c in cols])

    tasks = [(p, s, pr, cfg) for p in profs for s in suites for pr in protos]
    t0 = time.time()
    n = 0
    with open(os.path.join(a.out, "radio_results.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(ROW_COLS)
        if a.jobs > 1:
            with ProcessPoolExecutor(a.jobs) as ex:
                for rows in ex.map(sweep_task, tasks, chunksize=2):
                    w.writerows(rows)
                    n += len(rows)
        else:
            for t in tasks:
                rows = sweep_task(t)
                w.writerows(rows)
                n += len(rows)
    with open(os.path.join(a.out, "radio_assumptions.json"), "w") as fh:
        json.dump(dict(profiles={k: asdict(v) for k, v in PROFILES.items()}, config=cfg,
                       rows=n, seconds=round(time.time() - t0, 1)), fh, indent=1)
    print(f"[radio_sim] {n} rows ({n * a.trials:,} transactions) -> {a.out}/ in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
