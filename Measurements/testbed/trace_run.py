#!/usr/bin/env python3
"""
trace_run.py - packet- and window-level traces of TLS transactions in the netns testbed (paper 2, WP6: scenarios B1, B5, B11). Needs root.

  sudo python3 trace_run.py window   --suites "ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768" --n 8   # B1: the server's window in resumed transactions
  sudo python3 trace_run.py fullticket --n 8                                                                          # B11: the half round trip of a full handshake that issues a ticket
  sudo python3 trace_run.py race --n 6                                                                                # B1b: SERVER-side timeline of ticket, its acknowledgment and the response, over networks and RTTs

Both run `tls_probe` (server and client, --resume: each measured transaction is a resumed one, preceded by a full one that obtains the
ticket) in the namespaces of tbnet.py, with the kernel tracepoint tcp:tcp_probe enabled (state of the socket that receives a segment: snd_cwnd,
snd_una, snd_nxt) and tcpdump on the client link. Output: results/trace_<scenario>/<tag>.{trace.txt,pcap} and the `tls_probe` CSV.
Analyse with analyze_trace.py (tcp_probe) and pcap_summary.py (packets).
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MEAS = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, MEAS)
import tbnet  # noqa: E402
import run_testbed as RT  # noqa: E402
from tls_trace import SUITES as ALL_SUITES  # noqa: E402

TRACEFS = "/sys/kernel/tracing"
PRESETS = {
    "window": dict(suites="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768", reqs=[19460], resps=[14 * 1440 - 700], rtt=100.0, rate=100.0, mtu=1500, depth=2, mtls=1),
    "fullticket": dict(suites="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768", reqs=[302], resps=[222], rtt=100.0, rate=100.0, mtu=1500, depth=3, mtls=1),
    # race: large request (the ticket is still in flight when the request completes), response of k segments (k * MSS - 700 bytes), several networks.
    # nets = rtt:rate:mtu; the RTT sweep at 100 Mbit/s locates where the window after the ticket changes (12/15 segments at 30 ms, 10 at 5 ms and at 10 Mbit/s)
    "race": dict(suites="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768", reqs=[19460], ks=[13], depth=2, mtls=1,
                 nets="5:100:1500,10:100:1500,15:100:1500,20:100:1500,30:100:1500,50:100:1500,100:100:1500,100:10:1500,100:100:1280,100:100:9000"),
}


def run_one(tb, probe, suite, req, resp, depth, mtls, n, outdir, tag, rtt, pcap, resume=True, srv_pcap=False):
    alg, group = ALL_SUITES[suite]
    ch = RT.ensure_chain(alg, depth, os.path.join(HERE, "work"))
    port = tbnet.PROBE_PORT
    srv_cmd = ["taskset", "-c", "1"] + tb.exec_prefix("s") + [probe, "server", "--addr", tb.server_bind, "--port", port, "--cert", ch["server"][0], "--key", ch["server"][1],
               "--ca", ch["ca"], "--groups", group, "--req", str(req), "--resp", str(resp)] + (["--resume"] if resume else []) + (["--mtls"] if mtls else [])
    cli_cmd = ["taskset", "-c", "0"] + tb.exec_prefix("c") + [probe, "client", "--addr", tb.client_target, "--port", port, "--ca", ch["ca"], "--groups", group, "--req", str(req),
               "--resp", str(resp), "--n", str(n), "--warmup", "2", "--gap-ms", f"{2 * rtt + 5:g}"] + (["--resume"] if resume else []) + (["--cert", ch["client"][0], "--key", ch["client"][1]] if mtls else [])
    srv = subprocess.Popen(srv_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if srv.stdout.readline().strip() != "READY":
        srv.kill()
        raise RuntimeError("server did not start: " + srv.stderr.read()[-300:])
    dump = tr = dump_s = None
    if srv_pcap:      # the server's own link: arrivals after the client's egress delay, departures at the moment the server sends
        dump_s = subprocess.Popen(tb.exec_prefix("s") + ["tcpdump", "-i", "vs0", "-U", "-s", "128", "-w", os.path.join(outdir, tag + "_srv.pcap")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if pcap:
        dump = subprocess.Popen(tb.exec_prefix("c") + ["tcpdump", "-i", "vc0", "-U", "-s", "128", "-w", os.path.join(outdir, tag + ".pcap")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(f"{TRACEFS}/trace", "w").write("")
    open(f"{TRACEFS}/events/tcp/tcp_probe/enable", "w").write("1")
    tr = subprocess.Popen(["cat", f"{TRACEFS}/trace_pipe"], stdout=open(os.path.join(outdir, tag + ".trace.txt"), "w"))
    time.sleep(0.5)
    try:
        r = subprocess.run(cli_cmd, capture_output=True, text=True, timeout=(n + 2) * (2 * rtt / 1000 * 12 + 2) + 60)
        open(os.path.join(outdir, tag + ".csv"), "w").write(r.stdout)
    finally:
        time.sleep(0.5)
        open(f"{TRACEFS}/events/tcp/tcp_probe/enable", "w").write("0")
        tr.terminate()
        if dump:
            dump.send_signal(signal.SIGINT)
            dump.wait(10)
        if dump_s:
            dump_s.send_signal(signal.SIGINT)
            dump_s.wait(10)
        srv.terminate()
        try:
            srv.wait(5)
        except subprocess.TimeoutExpired:
            srv.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=list(PRESETS))
    ap.add_argument("--suites", default="")
    ap.add_argument("--reqs", default="")
    ap.add_argument("--resps", default="")
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--rtt", type=float, default=0)
    ap.add_argument("--rate", type=float, default=0)
    ap.add_argument("--mtu", type=int, default=0)
    ap.add_argument("--no-pcap", action="store_true")
    ap.add_argument("--nets", default="", help="race: comma list rtt:rate:mtu")
    ap.add_argument("--ks", default="", help="race: comma list of response sizes in segments")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    pr = dict(PRESETS[a.scenario])
    suites = (a.suites or pr["suites"]).split(",")
    reqs = [int(x) for x in a.reqs.split(",")] if a.reqs else pr["reqs"]
    resps = [int(x) for x in a.resps.split(",")] if a.resps else pr.get("resps", [])
    rtt, rate, mtu = a.rtt or pr.get("rtt", 100.0), a.rate or pr.get("rate", 100.0), a.mtu or pr.get("mtu", 1500)
    probe = os.path.join(HERE, "tls_probe")
    outdir = os.path.join(HERE, "results", f"trace_{a.scenario}")
    os.makedirs(outdir, exist_ok=True)
    tb = tbnet.Testbed("direct")
    tb.up()
    try:
        if a.scenario == "race":
            nets = [tuple(float(x) for x in t.split(":")) for t in (a.nets or pr["nets"]).split(",")]
            ks = [int(x) for x in a.ks.split(",")] if a.ks else pr["ks"]
            for (r_, rt_, m_) in nets:
                m_ = int(m_)
                tb.shape(r_, rt_, 0.0, m_, 10, "reno", quickack=True)
                for su in suites:
                    for rq in reqs:
                        for k in ks:
                            rs = k * (m_ - 60) - 700
                            tag = f"{su.split('|')[0]}_req{rq}_k{k}_rtt{r_:g}_rate{rt_:g}_mtu{m_}"
                            print(f"[{time.strftime('%H:%M:%S')}] {tag}", flush=True)
                            run_one(tb, probe, su, rq, rs, pr["depth"], pr["mtls"], a.n, outdir, tag, r_, not a.no_pcap, True, True)
            suites = []
        else:
            tb.shape(rtt, rate, 0.0, mtu, 10, "reno", quickack=True)
        for su in suites:
            for rq in reqs:
                for rs in resps:
                    for resume in ((True, False) if a.scenario == "fullticket" else (True,)):    # fullticket: with tickets (--resume) and ticketless (as in Paper 1)
                        tag = f"{su.split('|')[0]}_req{rq}_resp{rs}_rtt{rtt:g}_mtu{mtu}" + ("" if resume else "_ticketless")
                        print(f"[{time.strftime('%H:%M:%S')}] {tag}", flush=True)
                        run_one(tb, probe, su, rq, rs, pr["depth"], pr["mtls"], a.n, outdir, tag, rtt, not a.no_pcap, resume)
    finally:
        tb.down()
        for f in os.listdir(outdir):
            os.chown(os.path.join(outdir, f), int(os.environ.get("SUDO_UID", 0)), -1)
    print("done ->", outdir)


if __name__ == "__main__":
    main()
