#!/usr/bin/env python3
"""
capacity_latency.py - latency of a TLS 1.3 transaction UNDER LOAD at a fraction of the server's capacity (paper 2, WP6, scenario B4). No root.

    python3 capacity_latency.py --out results/latency_load_<machine>.csv [--suites ...] [--depths 2] [--mtls 1] [--resume 0,1]
                                [--fractions 0.5,0.8,0.95] [--time 10] [--warmup 3] [--server-cpus 18 --client-cpus 5,6,7,8,9,15]

For every configuration it first measures the saturation rate of one server core with the closed-loop generator (as capacity_test.py), then
offers Poisson arrivals at the given fractions of that rate with tls_load_open and reports the latency distribution (p50, p90, p99, p99.9) and
the server CPU use. Loopback: the numbers are the SERVICE plus QUEUEING time of the server, to be added to the transport time of the model.
Chains come from ../certs. Output columns: machine, suite, depth, mtls, resume, capacity_per_s, fraction, rate_target, ok, err, dropped, p50_ms ... util.
"""
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capacity_test as CT  # noqa: E402

RT, ALL_SUITES = CT.RT, CT.ALL_SUITES
COLS = ["machine", "suite", "depth", "mtls", "resume", "capacity_per_s", "fraction", "rate_target", "ok", "err", "dropped", "rate_ok",
        "p50_ms", "p90_ms", "p99_ms", "p999_ms", "max_ms", "util", "first_error"]


def open_loop(a, suite, depth, mtls, resume, rate, port, server_cpu, client_cpus):
    alg, group = ALL_SUITES[suite]
    ch = RT.ensure_chain(alg, depth, os.path.join(HERE, "work"))
    scmd = [os.path.join(HERE, "tls_serve"), "--addr", "127.0.0.1", "--port", str(port), "--cert", ch["server"][0], "--key", ch["server"][1],
            "--ca", ch["ca"], "--groups", group, "--req", str(a.req), "--resp", str(a.resp), "--reuseport"]
    scmd += (["--mtls"] if mtls else []) + (["--resume"] if resume else [])
    srv = CT.Server(scmd, server_cpu)
    ccmd = ["taskset", "-c", CT.cpu_list(client_cpus), os.path.join(HERE, "tls_load_open"), "--addr", "127.0.0.1", "--port", str(port), "--ca", ch["ca"],
            "--groups", group, "--req", str(a.req), "--resp", str(a.resp), "--rate", f"{rate:.2f}", "--time", str(a.time), "--warmup", str(a.warmup)]
    ccmd += (["--cert", ch["client"][0], "--key", ch["client"][1]] if mtls else []) + (["--resume", "--pool"] if resume else [])   # --pool: one single-use ticket per connection (the shared ticket failed in 4-14 % of the connections)
    cl = subprocess.Popen(ccmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(a.warmup + 0.3)
        s0 = srv.stats()
        w0 = time.time()
        time.sleep(a.time - 0.6)
        s1 = srv.stats()
        w1 = time.time()
        out, err = cl.communicate(timeout=a.time + a.warmup + 90)
    finally:
        srv.stop()
        if cl.poll() is None:
            cl.kill()
    rows = out.strip().splitlines()
    if len(rows) < 2:
        raise RuntimeError("tls_load_open failed: " + err[-300:])
    r = dict(zip(rows[0].split(","), rows[1].split(",")))
    cpu = (s1[1] + s1[2]) - (s0[1] + s0[2])
    r["util"] = round(cpu / (w1 - w0), 3)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "results", "latency_load.csv"))
    ap.add_argument("--machine", default=os.uname().nodename)
    ap.add_argument("--suites", default="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768")
    ap.add_argument("--depths", default="2")
    ap.add_argument("--mtls", default="1")
    ap.add_argument("--resume", default="0,1")
    ap.add_argument("--fractions", default="0.5,0.8,0.95")
    ap.add_argument("--req", type=int, default=302)
    ap.add_argument("--resp", type=int, default=222)
    ap.add_argument("--time", type=float, default=10.0)
    ap.add_argument("--warmup", type=float, default=3.0)
    ap.add_argument("--server-cpus", default="")
    ap.add_argument("--client-cpus", default="")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    topo = CT.topology()
    if a.server_cpus:
        server_cpu = int(a.server_cpus.split(",")[0])
        client_cpus = [int(x) for x in a.client_cpus.split(",")]
    else:
        server_cpu = topo[0][0]
        busy = set(topo[0])
        client_cpus = [c for t in topo for c in t if c not in busy] or [c for t in topo for c in t if c != server_cpu]
    fr = [float(x) for x in a.fractions.split(",")]
    cfgs = [(su, int(d), int(m), int(r)) for su in a.suites.split(",") for d in a.depths.split(",") for m in a.mtls.split(",") for r in a.resume.split(",")]
    est = len(cfgs) * (len(fr) + 1) * (a.time + a.warmup + 4) / 60
    print(f"{len(cfgs)} configurations x {len(fr)} loads, about {est:.0f} min; server cpu {server_cpu}, client cpus {client_cpus}")
    if a.list:
        return
    for b in ("tls_serve", "tls_load", "tls_load_open"):
        if not os.path.exists(os.path.join(HERE, b)):
            sys.exit(f"{b} not built: run ./setup_host.sh")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    done = set()
    new = not os.path.exists(a.out)
    if not new:
        done = {(r["suite"], int(r["depth"]), int(r["mtls"]), int(r["resume"]), float(r["fraction"])) for r in csv.DictReader(open(a.out))}
    fh = open(a.out, "a", newline="")
    w = csv.DictWriter(fh, fieldnames=COLS)
    if new:
        w.writeheader()
    # saturation runs reuse capacity_test.run_config with an attribute bag
    class Bag: pass
    b = Bag()
    b.server, b.server_cpus, b.client_cpus, b.procs_per_core = "tls_serve", [server_cpu], client_cpus, 1
    b.client_threads, b.req, b.resp, b.time, b.warmup = 0, a.req, a.resp, 6.0, 2.0
    port = 48000
    for cfg in cfgs:
        su, d, m, r = cfg
        if all((su, d, m, r, f) in done for f in fr):
            continue
        port += 1
        try:
            sat = CT.run_config(b, topo, a.machine, su, d, m, r, 1, port)
        except Exception as e:
            print(f"{cfg} saturation FAILED: {e}", flush=True)
            continue
        cap = float(sat["rate_per_s"])
        print(f"{su} d{d} mtls={m} resume={r}: capacity {cap:.0f}/s (util {sat['util']})", flush=True)
        for f in fr:
            if (su, d, m, r, f) in done:
                continue
            port += 1
            try:
                res = open_loop(a, su, d, m, r, f * cap, port, server_cpu, client_cpus)
            except Exception as e:
                print(f"   load {f}: FAILED {e}", flush=True)
                continue
            row = dict(machine=a.machine, suite=su, depth=d, mtls=m, resume=r, capacity_per_s=cap, fraction=f, rate_target=res["rate_target"], ok=res["ok"],
                       err=res["err"], dropped=res["dropped"], rate_ok=res["rate_ok"], p50_ms=res["p50_ms"], p90_ms=res["p90_ms"], p99_ms=res["p99_ms"],
                       p999_ms=res["p999_ms"], max_ms=res["max_ms"], util=res["util"], first_error=res["first_error"])
            w.writerow(row)
            fh.flush()
            print(f"   {f:.2f} of capacity: p50 {row['p50_ms']} p99 {row['p99_ms']} p99.9 {row['p999_ms']} ms, util {row['util']}, err {row['err']}, dropped {row['dropped']}", flush=True)
    fh.close()


if __name__ == "__main__":
    main()
