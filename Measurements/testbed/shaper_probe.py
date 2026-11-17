#!/usr/bin/env python3
"""
shaper_probe.py - does the netem rate shaper of the testbed behave the same on every machine?  (replication R2 / R5 follow-up)

Why.  The replication runs (226 configurations, OpenSSL 3.5.4) differ between machines almost only at 10 Mbit/s: i9-10900K and GX10 measure
1.3-1.5 ms MORE excess latency than the X250 (about the serialisation time of one 1500-byte frame at 10 Mbit/s = 1.2 ms), while 100 and
1000 Mbit/s agree.  The kernel is not the cause (the X250 gives the same numbers on 6.8, 6.14, 6.17, 7.0).  Candidates: the shaper (offload
state of the veth pair, per-packet accounting of netem `rate`, timer granularity) or the TCP stack.  This probe takes TCP out: it builds the
SAME veth pair with the SAME tbnet.py code and netem settings as the measurements, then sends plain UDP over it and measures
  (1) single packets: RTT as a function of the datagram size  -> slope = ms per byte; intercept = fixed delay
  (2) packet trains of K back-to-back datagrams: time from the first to the last arrival -> bytes the shaper charges per packet
      (expected IPv6 + UDP + payload: 1500 B for the largest datagram at MTU 1500)
and records ethtool -k, tc -s qdisc, tc and kernel versions, clock source, HZ.  If the three machines agree here, the cause is in the TCP stack;
if they differ at 10 Mbit/s, the cause is the shaper or the NIC offload state.

Run (needs root, nothing else running: it builds the namespaces pqcc/pqcs that the campaign uses, so it REFUSES to start while a measurement
or the namespaces exist; --force overrides the process check only):
    sudo python3 shaper_probe.py                       # all three rates, RTT 0 and 30 ms, ~3 minutes
    sudo python3 shaper_probe.py --rates 10 --rtts 0   # only the rate
    sudo python3 shaper_probe.py --server-cpu 6 --client-cpu 7   # pin like the measurements (i9: S=6 C=7)
    python3 shaper_probe.py --selftest                 # no root: protocol check on loopback, unshaped (does not touch any namespace)
    python3 shaper_probe.py --dry-run                  # print the plan only
Output: <out>/shaper_probe_<host>_<kernel>_<stamp>/ with probe.json, summary.txt, env_*.txt (default out: ~/pqc_shaper_probe).  No IP address of
the machine is written (the namespaces use the private fd99:: addresses of the testbed).  Send summary.txt and probe.json back; analyse with
    python3 shaper_probe.py --compare DIR1 DIR2 ...
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import socket
import statistics as st
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

PORT = 47331
HDR6, HDRU = 40, 8                        # IPv6 + UDP header bytes
SIZES = (64, 400, 800, 1200, 1452)        # datagram payloads for the single-packet probe; 1452 + 48 = 1500 = the MTU
TRAIN_K = 20
# under sudo "~" is /root: write to the invoking user's home instead (and give the files back to that user)
DEFAULT_OUT = os.path.join(os.path.expanduser("~" + os.environ["SUDO_USER"]) if os.environ.get("SUDO_USER") else os.path.expanduser("~"), "pqc_shaper_probe")


# ----------------------------------------------------------------------------- roles (run inside the namespaces)
def role_server(bind: str, port: int, stop_after: float):
    """Echo server. Packet types (first byte): 'S' single -> reply 'R' at once; 'T' train packet: remember arrival times; 'Q' query -> reply with
    (n, t_last - t_first) of the last train; 'X' end."""
    s = socket.socket(socket.AF_INET6 if ":" in bind else socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((bind, port))
    s.settimeout(stop_after)
    first = last = None
    n = 0
    seq_seen = set()
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            return
        t = time.perf_counter_ns()
        k = data[:1]
        if k == b"S":
            s.sendto(b"R" + data[1:9], addr)
        elif k == b"T":
            seq = struct.unpack("!I", data[1:5])[0]
            if seq == 0:
                first, last, n, seq_seen = t, t, 0, set()
            if seq not in seq_seen:
                seq_seen.add(seq)
                n += 1
                last = max(last or t, t)
        elif k == b"Q":
            s.sendto(b"A" + struct.pack("!IQ", n, (last - first) if first is not None else 0), addr)
        elif k == b"X":
            return


def role_client(target: str, port: int, reps: int, train_k: int, sizes, out_path: str):
    s = socket.socket(socket.AF_INET6 if ":" in target else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    s.connect((target, port))
    res = {"single": {}, "train": []}
    for size in sizes:                                       # (1) single packets
        pay = b"S" + struct.pack("!Q", 0) + b"\0" * (size - 9)
        v = []
        for _ in range(reps + 3):
            t0 = time.perf_counter_ns()
            s.send(pay)
            try:
                s.recv(64)
            except socket.timeout:
                continue
            v.append((time.perf_counter_ns() - t0) / 1e6)
        res["single"][str(size)] = v[3:]                     # three warm-up packets dropped
    big = max(sizes)                                         # (2) trains of the largest datagram
    for _ in range(reps):
        for seq in range(train_k):
            s.send(b"T" + struct.pack("!I", seq) + b"\0" * (big - 5))
        time.sleep(0.05 + 0.0)                               # let the train drain (the server sees it long after at low rates: wait for the answer below)
        got = None
        for _try in range(60):                               # query until all train_k arrived (low rates: 20 x 1.2 ms = 24 ms; with RTT: + RTT)
            s.send(b"Q")
            try:
                d = s.recv(64)
            except socket.timeout:
                continue
            if d[:1] == b"A":
                n, span = struct.unpack("!IQ", d[1:13])
                if n >= train_k:
                    got = span / 1e6
                    break
            time.sleep(0.02)
        res["train"].append(got)
        time.sleep(0.05)
    s.send(b"X")
    json.dump(res, open(out_path, "w"))


# ----------------------------------------------------------------------------- orchestration
def sh(cmd, check=False):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def pct(v, p):
    v = sorted(x for x in v if x is not None)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))] if v else float("nan")


def summarise(res, rate_mbps, rtt_ms, mtu=1500):
    out = {}
    single = {int(k): v for k, v in res["single"].items() if v}
    med = {k: st.median(v) for k, v in single.items()}
    ks = sorted(med)
    if len(ks) >= 2:
        xs, ys = ks, [med[k] for k in ks]
        mx, my = st.mean(xs), st.mean(ys)
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)        # ms per byte
        out["single_median_ms"] = {k: round(med[k], 3) for k in ks}
        out["slope_us_per_byte"] = round(slope * 1000, 4)
        out["expected_slope_us_per_byte"] = round(8 / rate_mbps, 4) if rate_mbps > 0 else 0.0
        out["intercept_ms"] = round(my - slope * mx, 3)
    tr = [t for t in res["train"] if t is not None]
    if tr:
        big = max(single) if single else 1452
        t = st.median(tr)
        out["train_span_ms_median"] = round(t, 3)
        out["train_span_ms_p10_p90"] = [round(pct(tr, 10), 3), round(pct(tr, 90), 3)]
        out["train_lost_runs"] = sum(1 for x in res["train"] if x is None)
        if rate_mbps > 0:
            out["charged_bytes_per_packet"] = round(t / 1000 * rate_mbps * 1e6 / 8 / (TRAIN_K - 1), 1)   # bytes the shaper accounted per datagram
            out["wire_bytes_per_packet"] = big + HDR6 + HDRU
    return out


def snapshot_env(d, tag):
    lines = []
    for ifc, ns in (("vc0", "pqcc"), ("vs0", "pqcs")):
        lines.append(f"## ethtool -k {ifc} ({ns})")
        lines.append(sh(["ip", "netns", "exec", ns, "ethtool", "-k", ifc]))
        lines.append(f"## ip -d link show {ifc}")
        lines.append(sh(["ip", "netns", "exec", ns, "ip", "-d", "link", "show", ifc]))
        lines.append(f"## tc -s qdisc show dev {ifc}")
        lines.append(sh(["ip", "netns", "exec", ns, "tc", "-s", "qdisc", "show", "dev", ifc]))
    open(os.path.join(d, f"env_{tag}.txt"), "w").write("\n".join(lines) + "\n")


def static_env(d):
    L = [f"date: {dt.datetime.now().astimezone().isoformat()}", f"host: {socket.gethostname().split('.')[0]}", f"kernel: {platform.release()}",
         f"machine: {platform.machine()}", f"python: {platform.python_version()}", "tc: " + sh(["tc", "-V"]), "ip: " + sh(["ip", "-V"]),
         "clocksource: " + sh("cat /sys/devices/system/clocksource/clocksource0/current_clocksource"),
         "governor: " + sh("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
         "CONFIG_HZ: " + sh("zgrep -E '^CONFIG_HZ=|^CONFIG_NO_HZ|^CONFIG_PREEMPT' /proc/config.gz 2>/dev/null || grep -E '^CONFIG_HZ=|^CONFIG_NO_HZ|^CONFIG_PREEMPT' /boot/config-$(uname -r) 2>/dev/null | tr '\\n' ' '"),
         "cmdline: " + re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", sh("cat /proc/cmdline")),
         "nproc: " + sh("nproc"), "veth module: " + sh("modinfo -F version veth 2>/dev/null; modinfo -F filename sch_netem 2>/dev/null | head -1")]
    open(os.path.join(d, "env_static.txt"), "w").write("\n".join(L) + "\n")
    return L


def check_idle(force: bool):
    busy = sh("pgrep -af 'pqcm.sh|campaign.sh|run_testbed.py|run_slack|tls_probe|tcp_flight|run_ossl_campaign|run_v5_cpu' | grep -v 'shaper_probe' | grep -v pgrep")
    ns = sh("ip netns list")
    if any(n in ns for n in ("pqcc", "pqcp", "pqcs")):
        sys.exit("namespaces pqcc/pqcp/pqcs already exist (a measurement is running or was interrupted); do not run the probe now:\n" + ns)
    if busy and not force:
        sys.exit("a measurement process is running (the probe would disturb it and delete its namespaces):\n" + busy + "\n(--force skips this check only)")


def run_one(tb, rate, rtt, args, outdir):
    from tbnet import NS_C, NS_S, A_C1, A_P1
    tb.shape(rtt, rate, 0, args.mtu, 10)
    time.sleep(0.5)
    tag = f"rate{rate:g}_rtt{rtt:g}"
    snapshot_env(outdir, tag)
    me = os.path.abspath(__file__)
    pin = lambda cpu: ["taskset", "-c", str(cpu)] if cpu is not None else []
    tmp = os.path.join(outdir, f"raw_{tag}.json")
    sizes = ",".join(str(s) for s in SIZES)
    srv = subprocess.Popen(["ip", "netns", "exec", NS_S] + pin(args.server_cpu) + [sys.executable, me, "--role", "server", "--addr", A_P1, "--stop-after", "20"])
    time.sleep(0.7)
    subprocess.run(["ip", "netns", "exec", NS_C] + pin(args.client_cpu) + [sys.executable, me, "--role", "client", "--addr", A_P1, "--reps", str(args.reps),
                    "--sizes", sizes, "--out", tmp], check=False)
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except Exception:
        srv.kill()
    res = json.load(open(tmp)) if os.path.exists(tmp) else {"single": {}, "train": []}
    return tag, summarise(res, rate, rtt, args.mtu)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rates", default="10,100,1000", help="Mbit/s, comma separated")
    ap.add_argument("--rtts", default="0,30", help="ms, comma separated")
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--reps", type=int, default=50)
    ap.add_argument("--server-cpu", type=int, default=None)
    ap.add_argument("--client-cpu", type=int, default=None)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--compare", nargs="+", metavar="DIR")
    ap.add_argument("--role", choices=["server", "client"], help=argparse.SUPPRESS)
    ap.add_argument("--addr", help=argparse.SUPPRESS)
    ap.add_argument("--stop-after", type=float, default=20, help=argparse.SUPPRESS)
    ap.add_argument("--sizes", default=",".join(map(str, SIZES)), help=argparse.SUPPRESS)
    ap.add_argument("--out-json", dest="out_json", help=argparse.SUPPRESS)
    a, rest = ap.parse_known_args()
    if a.role == "server":
        return role_server(a.addr, PORT, a.stop_after)
    if a.role == "client":
        o = a.out if a.out != DEFAULT_OUT else a.out_json
        return role_client(a.addr, PORT, a.reps, TRAIN_K, [int(x) for x in a.sizes.split(",")], o)
    if a.compare:
        return compare(a.compare)
    rates = [float(x) for x in a.rates.split(",")]
    rtts = [float(x) for x in a.rtts.split(",")]
    if a.dry_run:
        print("plan: build veth pair pqcc/pqcs (tbnet.py, offloads off), then for each rate", rates, "and RTT", rtts,
              f"send {a.reps} single datagrams of sizes {SIZES} and {a.reps} trains of {TRAIN_K} x {max(SIZES)} B; record ethtool -k / tc -s qdisc; tear down")
        return
    if a.selftest:
        return selftest(a)
    if os.geteuid() != 0:
        sys.exit("needs root: sudo python3 shaper_probe.py   (or --selftest / --dry-run without root)")
    check_idle(a.force)
    for tool in ("ip", "tc", "ethtool"):
        if not shutil.which(tool):
            sys.exit(f"{tool} not found")
    from tbnet import Testbed
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(a.out, f"shaper_probe_{socket.gethostname().split('.')[0]}_{platform.release()}_{stamp}")
    os.makedirs(outdir, exist_ok=True)
    static_env(outdir)
    tb = Testbed("direct")
    results = {"meta": {"host": socket.gethostname().split('.')[0], "kernel": platform.release(), "stamp": stamp, "mtu": a.mtu, "reps": a.reps,
                        "server_cpu": a.server_cpu, "client_cpu": a.client_cpu}, "cells": {}}
    try:
        tb.up()
        for rate in rates:
            for rtt in rtts:
                print(f"[{dt.datetime.now():%H:%M:%S}] rate {rate:g} Mbit/s, RTT {rtt:g} ms ...", flush=True)
                tag, s = run_one(tb, rate, rtt, a, outdir)
                results["cells"][tag] = s
                print("   ", json.dumps(s), flush=True)
    finally:
        tb.down()
    json.dump(results, open(os.path.join(outdir, "probe.json"), "w"), indent=1)
    write_summary(results, outdir)
    if os.environ.get("SUDO_UID"):                      # hand the output back to the user who ran sudo
        for root, dirs, files in os.walk(a.out):
            for n in dirs + files:
                try:
                    os.chown(os.path.join(root, n), int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"])))
                except OSError:
                    pass
        try:
            os.chown(a.out, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"])))
        except OSError:
            pass
    print("written:", outdir)


def write_summary(results, outdir):
    L = [f"shaper probe {results['meta']['host']} {results['meta']['kernel']} {results['meta']['stamp']}",
         "cell                 slope us/B (expected) | intercept ms | train span ms | charged B/pkt (wire B/pkt)"]
    for tag, s in results["cells"].items():
        L.append(f"{tag:20s} {s.get('slope_us_per_byte', float('nan')):9.4f} ({s.get('expected_slope_us_per_byte', float('nan')):.4f}) | "
                 f"{s.get('intercept_ms', float('nan')):9.3f} | {s.get('train_span_ms_median', float('nan')):9.3f} | "
                 f"{s.get('charged_bytes_per_packet', float('nan')):8.1f} ({s.get('wire_bytes_per_packet', '-')})")
    t = "\n".join(L) + "\n"
    open(os.path.join(outdir, "summary.txt"), "w").write(t)
    print(t)


def compare(dirs):
    data = []
    for d in dirs:
        p = os.path.join(d, "probe.json")
        data.append(json.load(open(p)))
    cells = sorted({c for x in data for c in x["cells"]})
    print("charged bytes per packet at the shaper (wire = 1500 for the largest datagram at MTU 1500) and slope (us/byte; expected 8/rate):")
    print("cell".ljust(22) + "".join(f"{x['meta']['host'][:10]}/{x['meta']['kernel'][:10]}".ljust(26) for x in data))
    for c in cells:
        row = c.ljust(22)
        for x in data:
            s = x["cells"].get(c, {})
            row += f"{s.get('charged_bytes_per_packet', float('nan')):7.1f} B  {s.get('slope_us_per_byte', float('nan')):7.4f} us/B   ".ljust(26)
        print(row)


def selftest(a):
    """Loopback, unshaped: checks that the server and client roles and the summary work (no root, no namespaces)."""
    me = os.path.abspath(__file__)
    srv = subprocess.Popen([sys.executable, me, "--role", "server", "--addr", "::1", "--stop-after", "10"])
    time.sleep(0.5)
    tmp = "/tmp/shaper_probe_selftest.json"
    subprocess.run([sys.executable, me, "--role", "client", "--addr", "::1", "--reps", "5", "--sizes", ",".join(map(str, SIZES)), "--out-json", tmp], check=True)
    srv.terminate()
    res = json.load(open(tmp))
    s = summarise(res, 0, 0)
    print(json.dumps(s, indent=1))
    assert s.get("single_median_ms") and s.get("train_span_ms_median") is not None, "selftest failed"
    print("selftest OK")


if __name__ == "__main__":
    main()
