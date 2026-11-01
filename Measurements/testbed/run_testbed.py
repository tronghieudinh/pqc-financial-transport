#!/usr/bin/env python3
"""
run_testbed.py - sweep real OpenSSL 3.5 TLS 1.3 transactions over an emulated network.

For every configuration (suite x chain depth x mutual-TLS x RTT x rate x MTU x loss x initial window) it
shapes a veth link with tc netem (tbnet.py), starts tls_probe server/client pinned to separate cores,
and records the timing of every transaction. Unshaped "base" runs measure the cost of computation and of
the local stack; analyze_testbed.py subtracts them and compares the remainder with the model.

    sudo python3 run_testbed.py --profile smoke                 # ~2 minutes, checks the whole chain
    sudo python3 run_testbed.py --profile core --n 30           # a few hours
    sudo python3 run_testbed.py --profile full  --n 30          # overnight
    sudo python3 run_testbed.py --profile loss  --n 200         # loss tails (slow)
    sudo python3 run_testbed.py --profile proxy --topology proxy-tcp      # real middlebox (HAProxy)
    sudo python3 run_testbed.py --topology loopback --profile smoke       # no root: pipeline self-test only

The run is resumable: finished configurations (>= n rows) are skipped when the output file exists.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
import platform
import random
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
MEAS = os.path.dirname(HERE)
sys.path.insert(0, MEAS)
from tls_trace import SUITES as ALL_SUITES  # noqa: E402  (simulator suite -> (certificate algorithm, TLS group))
import tbnet  # noqa: E402

TLS_SUITES = list(ALL_SUITES)               # SLH-DSA is covered too, but OpenSSL has no TLS code point for it
CORE_SUITES = ["RSA-2048|ECDHE-P256", "ECDSA-P256|X25519", "ECDSA-P256|X25519MLKEM768",
               "ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768", "ML-DSA-87|ML-KEM-1024"]

PROFILES = {
    "smoke": dict(suites=["ECDSA-P256|X25519", "ML-DSA-65|ML-KEM-768"], depths=[1, 3], mtls=[1], rtts=[30],
                  rates=[100], mtus=[1500], losses=[0], icws=[10], n=10),
    "core": dict(suites=CORE_SUITES, depths=[1, 2, 3, 4], mtls=[1], rtts=[5, 30, 100], rates=[10, 100, 1000],
                 mtus=[1280, 1500, 9000], losses=[0], icws=[10], n=30),
    "full": dict(suites=CORE_SUITES, depths=[1, 2, 3, 4], mtls=[1, 0], rtts=[5, 15, 30, 60, 100],
                 rates=[10, 100, 1000], mtus=[1280, 1500, 9000], losses=[0], icws=[10, 32], n=30),
    "loss": dict(suites=["ECDSA-P256|X25519", "ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768"], depths=[2, 3],
                 mtls=[1], rtts=[30], rates=[100], mtus=[1500], losses=[0, 0.1, 0.5, 1, 2], icws=[10], n=200),
    "proxy": dict(suites=["ECDSA-P256|X25519", "ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768",
                          "ML-DSA-87|ML-KEM-1024"], depths=[1, 2, 3, 4], mtls=[1], rtts=[30], rates=[100],
                  mtus=[1500], losses=[0], icws=[10], n=40),
}

COLS = ["cfg_id", "topology", "suite", "cert_alg", "group", "depth", "mtls", "req", "resp", "rtt_ms", "rate_mbps",
        "loss_pct", "mtu", "icw", "cc", "tcp_ts", "quickack", "resume", "net_id", "iter", "t_tcp_ms", "t_hs_ms", "t_total_ms", "bytes_w", "bytes_r",
        "snd_mss", "snd_cwnd0", "retrans", "rtt_us", "data_segs_out", "data_segs_in", "err", "reused", "prime_ms", "ts_utc"]


def cfg_id(c):
    cid = "|".join(str(c[k]) for k in ("topology", "suite", "depth", "mtls", "req", "resp", "rtt_ms", "rate_mbps",
                                      "loss_pct", "mtu", "icw", "cc"))
    return cid + ("|client=" + c["client_alg"] if c.get("client_alg") else "")       # unchanged for every earlier run


def detect_cpus():
    """Logical CPUs on distinct physical cores for client, server, proxy (e.g. i7-5600U: 2 cores, 4 threads)."""
    try:
        out = subprocess.run(["lscpu", "-p=CPU,CORE"], capture_output=True, text=True, check=True).stdout
        cores = {}
        for line in out.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            cpu, core = line.split(",")[:2]
            cores.setdefault(int(core), []).append(int(cpu))
        ids = sorted(cores)
        c = cores[ids[0]][0]
        s = cores[ids[1]][0] if len(ids) > 1 else c
        p = cores[ids[0]][1] if len(cores[ids[0]]) > 1 else s
        return c, s, p
    except Exception:
        return 0, 0, 0


def need(binary):
    if shutil.which(binary) is None:
        sys.exit(f"missing tool: {binary} (run setup_host.sh)")


def read_text(cmd):
    try:
        env = dict(os.environ)
        if cmd and os.sep in cmd[0] and os.path.basename(os.path.dirname(cmd[0])) == "bin":    # a self-built OpenSSL has no rpath
            env["LD_LIBRARY_PATH"] = os.path.join(os.path.dirname(os.path.dirname(cmd[0])), "lib")
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=env).stdout.strip()
    except Exception:
        return ""


def write_env(path, args, cpus, openssl):
    gov = read_text(["cat", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"])
    turbo = read_text(["cat", "/sys/devices/system/cpu/intel_pstate/no_turbo"])
    env = dict(utc=datetime.now(timezone.utc).isoformat(), platform=platform.platform(), machine=platform.machine(),
               cpu=read_text(["bash", "-c", "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2"]),
               nproc=os.cpu_count(), governor=gov, intel_no_turbo=turbo, cpus_client_server_proxy=cpus,
               openssl=read_text([openssl, "version"]), tc=read_text(["tc", "-V"]), ip=read_text(["ip", "-V"]),
               haproxy=read_text(["haproxy", "-v"]).splitlines()[:1], args=vars(args))
    json.dump(env, open(path, "w"), indent=2)


def ensure_chain(alg, depth, work):
    """Concatenate leaf + intermediates (what a server sends) for server and client."""
    d = os.path.join(MEAS, "certs", alg, f"d{depth}")
    for need_f in ("server.pem", "server.key", "client.key", "root.pem"):
        if not os.path.exists(os.path.join(d, need_f)):
            sys.exit(f"missing {need_f} in {d}: private keys are not in the repository, run ../certs.sh "
                     f"(needs OpenSSL 3.5 in ~/opt/openssl-3.5)")
    out = {}
    os.makedirs(work, exist_ok=True)
    for role in ("server", "client"):
        full = os.path.join(work, f"{alg}_d{depth}_{role}_full.pem")
        with open(full, "w") as fh:
            for f in (f"{role}.pem", "inter_chain.pem"):
                fh.write(open(os.path.join(d, f)).read())
        out[role] = (full, os.path.join(d, f"{role}.key"))
    out["ca"] = os.path.join(d, "root.pem")
    return out


HAPROXY_CFG = """global
    maxconn 1024
    nbthread 1
defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s
frontend f
    bind [{bind}]:{port}
{inspect}    default_backend b
backend b
    server s [{server}]:{port}
"""


def start_proxy(tb, work, inspect, cpu):
    cfg = os.path.join(work, "haproxy.cfg")
    ins = ("    tcp-request inspect-delay 5s\n    tcp-request content accept if { req.ssl_hello_type 1 }\n"
           if inspect else "")
    open(cfg, "w").write(HAPROXY_CFG.format(bind=tbnet.A_P1, port=tbnet.PROBE_PORT, server=tbnet.A_S2, inspect=ins))
    if tb.dry:
        return None
    p = subprocess.Popen(["taskset", "-c", str(cpu)] + tb.exec_prefix("p") + ["haproxy", "-db", "-f", cfg],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1.0)
    if p.poll() is not None:
        sys.exit("haproxy failed to start: " + p.stderr.read().decode(errors="replace")[-400:])
    return p


def run_config(c, tb, probe, cpus, work, loopback):
    alg, group = ALL_SUITES[c["suite"]]
    ch = ensure_chain(alg, c["depth"], work)
    ca_srv = ch["ca"]                      # the server's trust anchor for the CLIENT certificate
    if c.get("client_alg"):                # WP6: the client certificate comes from another algorithm's tree (mixed chains; a transition scenario)
        chc = ensure_chain(c["client_alg"], c["depth"], work)
        ca_srv = os.path.join(work, f"ca_{alg}_{c['client_alg']}_d{c['depth']}.pem")
        with open(ca_srv, "w") as fh:
            fh.write(open(ch["ca"]).read() + open(chc["ca"]).read())
        ch = dict(ch, client=chc["client"])
    cpu_c, cpu_s, _ = cpus
    port = tbnet.PROBE_PORT if not loopback else "45600"
    pre_s = [] if loopback else tb.exec_prefix("s")
    pre_c = [] if loopback else tb.exec_prefix("c")
    s_addr = "::1" if loopback else tb.server_bind
    c_addr = "::1" if loopback else tb.client_target
    mtls = ["--mtls"] if c["mtls"] else []
    srv_cmd = ["taskset", "-c", str(cpu_s)] + pre_s + [probe, "server", "--addr", s_addr, "--port", port,
              "--cert", ch["server"][0], "--key", ch["server"][1], "--ca", ca_srv, "--groups", group,
              "--req", str(c["req"]), "--resp", str(c["resp"])] + mtls + (["--resume"] if c["resume"] else [])
    gap = 2 * c["rtt_ms"] + 5
    cli_cmd = ["taskset", "-c", str(cpu_c)] + pre_c + [probe, "client", "--addr", c_addr, "--port", port,
              "--ca", ch["ca"], "--groups", group, "--req", str(c["req"]), "--resp", str(c["resp"]),
              "--n", str(c["n"]), "--warmup", str(c["warmup"]), "--gap-ms", f"{gap:g}"] + (["--resume"] if c["resume"] else [])
    if c["mtls"]:
        cli_cmd += ["--cert", ch["client"][0], "--key", ch["client"][1]]
    if tb is not None and tb.dry:
        print("  server:", " ".join(srv_cmd))
        print("  client:", " ".join(cli_cmd))
        return [], "", {}
    srv = subprocess.Popen(srv_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    rows, cerr, out_s, serr = [], "", "", ""
    try:
        if srv.stdout.readline().strip() != "READY":
            srv.kill()
            raise RuntimeError("server did not start: " + srv.stderr.read()[-400:])
        timeout = (c["n"] + c["warmup"]) * (10 + c["rtt_ms"] * 0.06) * (2 if c["resume"] else 1) + 60
        r = subprocess.run(cli_cmd, capture_output=True, text=True, timeout=timeout)
        rows = list(csv.DictReader(r.stdout.splitlines()))
        cerr = r.stderr.strip()
    finally:
        if srv.poll() is None:
            srv.send_signal(signal.SIGTERM)
        try:
            out_s, serr = srv.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
            out_s, serr = srv.communicate()
    srvinfo = next((l for l in (out_s or "").splitlines() if l.startswith("SRVINFO")), "")
    return rows, srvinfo, dict(client_stderr=cerr, server_stderr=(serr or "").strip())


def build_configs(a, p):
    suites = a.suites.split(",") if a.suites else p["suites"]
    ints = lambda s, d: [int(x) for x in s.split(",")] if s else d
    flts = lambda s, d: [float(x) for x in s.split(",")] if s else d
    depths, mtls = ints(a.depths, p["depths"]), ints(a.mtls, p["mtls"])
    rtts, rates, mtus = flts(a.rtts, p["rtts"]), flts(a.rates, p["rates"]), ints(a.mtus, p["mtus"])
    losses, icws = flts(a.losses, p["losses"]), ints(a.icws, p["icws"])
    n = a.n or p["n"]
    base = []
    shaped = []
    for su, d, m in itertools.product(suites, depths, mtls):
        common = dict(topology=a.topology, suite=su, depth=d, mtls=m, req=a.req, resp=a.resp, cc=a.cc, n=n,
                      tcp_ts=int(a.timestamps), quickack=int(not a.delack), resume=int(a.resume),
                      warmup=a.warmup)
        if a.client_alg:
            common["client_alg"] = a.client_alg
        base.append(dict(common, rtt_ms=0, rate_mbps=0, loss_pct=0, mtu=1500, icw=10, net_id="base"))
        for rtt, rate, mtu, loss, icw in itertools.product(rtts, rates, mtus, losses, icws):
            shaped.append(dict(common, rtt_ms=rtt, rate_mbps=rate, loss_pct=loss, mtu=mtu, icw=icw, net_id="shaped"))
    random.Random(a.seed).shuffle(shaped)
    return base + shaped


def estimate_s(c):
    return (c["n"] + c["warmup"]) * (8 * c["rtt_ms"] + 20 + 2 * c["rtt_ms"] + 5) * (2 if c["resume"] else 1) / 1000 + 1.5


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=list(PROFILES), default="smoke")
    ap.add_argument("--topology", choices=["direct", "proxy-tcp", "proxy-inspect", "loopback"], default="direct")
    ap.add_argument("--out", default=os.path.join(HERE, "results", "testbed_raw.csv"))
    ap.add_argument("--n", type=int, default=0, help="measured transactions per configuration")
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--req", type=int, default=302, help="request bytes (default = ISO 8583 0200)")
    ap.add_argument("--resp", type=int, default=222, help="response bytes (default = ISO 8583 0210)")
    ap.add_argument("--cc", default="reno")
    ap.add_argument("--resume", action="store_true", help="measure RESUMED transactions (a full transaction obtains a ticket first; prime_ms = its time)")
    ap.add_argument("--delack", action="store_true", help="no quickack on the routes: Linux delayed acknowledgements (default: quickack)")
    ap.add_argument("--timestamps", action="store_true", help="TCP timestamps on (12 option bytes, MSS = MTU - 72); default off")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--client-alg", default="", help="certificate algorithm of the CLIENT (e.g. ECDSA-P256) when it differs from the server's; adds a client_alg column")
    for k in ("suites", "depths", "mtls", "rtts", "rates", "mtus", "losses", "icws"):
        ap.add_argument(f"--{k}", default="", help="comma list overriding the profile")
    ap.add_argument("--dry-run", action="store_true", help="print the commands, run nothing")
    ap.add_argument("--list", action="store_true", help="print the number of configurations and time estimate")
    ap.add_argument("--debug", action="store_true", help="always print the stderr of client and server")
    ap.add_argument("--keep", action="store_true", help="do not remove the namespaces at the end")
    a = ap.parse_args()
    if a.client_alg:
        COLS.append("client_alg")      # only new files get the extra column; earlier outputs keep their header

    p = PROFILES[a.profile]
    cfgs = build_configs(a, p)
    est = sum(estimate_s(c) for c in cfgs)
    print(f"{len(cfgs)} configurations ({sum(c['net_id'] == 'base' for c in cfgs)} base), estimated "
          f"{est / 3600:.1f} h at n={cfgs[0]['n']}")
    if a.list:
        return

    loopback = a.topology == "loopback"
    topo = "direct" if loopback else ("direct" if a.topology == "direct" else "proxy")
    if not loopback and not a.dry_run and os.geteuid() != 0:
        sys.exit("run with sudo (network namespaces and tc need root), or use --topology loopback")
    for b in ("taskset",) + (() if loopback else ("ip", "tc", "ethtool")) + (("haproxy",) if topo == "proxy" else ()):
        if not a.dry_run:
            need(b)

    sudo_uid = int(os.environ.get("SUDO_UID", os.getuid()))
    home = os.path.expanduser("~" + os.environ["SUDO_USER"]) if os.environ.get("SUDO_USER") else os.path.expanduser("~")
    prefix = os.environ.get("PQC_OPENSSL", os.path.join(home, "opt", "openssl-3.5"))
    probe = os.path.join(HERE, "tls_probe")
    if not os.path.exists(probe) and not a.dry_run:
        sys.exit("tls_probe not built (run setup_host.sh)")
    openssl = os.path.join(prefix, "bin", "openssl")
    cpus = detect_cpus()
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    if os.geteuid() == 0 and not a.dry_run:
        os.chown(os.path.dirname(a.out), sudo_uid, -1)
    work = os.path.join(HERE, "work")
    if not a.dry_run:
        write_env(os.path.join(os.path.dirname(a.out), "env.json"), a, cpus, openssl)

    done = {}
    if os.path.exists(a.out) and not a.dry_run:
        for r in csv.DictReader(open(a.out)):
            if r["err"] == "":
                done[r["cfg_id"]] = done.get(r["cfg_id"], 0) + 1
    new_file = not os.path.exists(a.out)
    out = None if a.dry_run else open(a.out, "a", newline="")
    w = None if a.dry_run else csv.DictWriter(out, fieldnames=COLS)
    if new_file and w:
        w.writeheader()

    tb = tbnet.Testbed(topo, dry_run=a.dry_run, timestamps=a.timestamps) if not loopback else None
    proxy = None
    if tb:
        tb.up()
        if not a.dry_run and not tb.smoke_test() and topo == "direct":
            tb.down()
            sys.exit("ping through the veth link failed: check ip/ipv6 support in the kernel")
        if topo == "proxy":
            proxy = start_proxy(tb, work, a.topology == "proxy-inspect", cpus[2])
    if loopback:
        print("loopback: NO network shaping, every row measures the unshaped path (pipeline self-test only)")

    t_start = time.time()
    fails = 0
    try:
        for i, c in enumerate(cfgs, 1):
            cid = cfg_id(c)
            if done.get(cid, 0) >= c["n"]:
                continue
            print(f"[{i}/{len(cfgs)}] {c['net_id']} {c['suite']} d{c['depth']} mtls={c['mtls']} rtt={c['rtt_ms']:g} "
                  f"rate={c['rate_mbps']:g} mtu={c['mtu']} loss={c['loss_pct']:g} icw={c['icw']}", flush=True)
            try:
                if tb:
                    tb.shape(c["rtt_ms"], c["rate_mbps"], c["loss_pct"], c["mtu"], c["icw"], c["cc"], quickack=bool(c["quickack"]))
                rows, info, errs = run_config(c, tb, probe, cpus, work, loopback)
            except subprocess.CalledProcessError as e:
                sys.exit(f"command failed: {' '.join(map(str, e.cmd))} (exit {e.returncode}); "
                         f"fix the network setup first (python3 tbnet.py up --dry-run shows every command)")
            except Exception as e:           # keep the sweep going; the configuration stays unfinished
                print("   FAILED:", e, flush=True)
                fails += 1
                if fails >= 3:
                    sys.exit("3 configurations in a row failed: stopping (see messages above, or run ./diagnose.sh)")
                continue
            if a.dry_run:
                continue
            ok = [r for r in rows if not r["err"]]
            if a.debug or not ok:
                for k, v in errs.items():
                    if v:
                        print(f"   {k}: {v[-600:]}", flush=True)
            if not ok:
                from collections import Counter
                print("   no successful transaction; errors:", dict(Counter(r["err"] for r in rows)) or "no client output",
                      flush=True)
                ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
                for r in (rows or [dict(i="-1", t_tcp_ms="-1", t_hs_ms="-1", t_total_ms="-1", bytes_w="0", bytes_r="0",
                                        snd_mss="0", snd_cwnd0="0", retrans="0", rtt_us="0", data_segs_out="0", data_segs_in="0",
                                        err="no_client_output")]):
                    w.writerow(dict({k: c.get(k, "") for k in COLS if k in c}, cfg_id=cid, cert_alg=ALL_SUITES[c["suite"]][0],
                                    group=ALL_SUITES[c["suite"]][1], iter=r["i"], t_tcp_ms=r["t_tcp_ms"], t_hs_ms=r["t_hs_ms"],
                                    t_total_ms=r["t_total_ms"], bytes_w=r["bytes_w"], bytes_r=r["bytes_r"],
                                    snd_mss=r["snd_mss"], snd_cwnd0=r["snd_cwnd0"], retrans=r["retrans"],
                                    rtt_us=r["rtt_us"], data_segs_out=r["data_segs_out"], data_segs_in=r["data_segs_in"],
                                    err=r["err"], reused=r.get("reused", "0"), prime_ms=r.get("prime_ms", "-1"), ts_utc=ts))
                out.flush()
                fails += 1
                if fails >= 3:
                    sys.exit("3 configurations in a row without a successful transaction: stopping (run ./diagnose.sh)")
                continue
            fails = 0
            mss, cw0 = int(ok[0]["snd_mss"]), int(ok[0]["snd_cwnd0"])
            want_mss = c["mtu"] - 60 - (12 if c["tcp_ts"] else 0)
            if not loopback and (mss != want_mss or cw0 != c["icw"]) and c["net_id"] == "shaped":
                print(f"   WARNING: client mss={mss} (want {want_mss}), cwnd0={cw0} (want {c['icw']})", flush=True)
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            for r in rows:
                w.writerow(dict({k: c.get(k, "") for k in COLS if k in c}, cfg_id=cid, cert_alg=ALL_SUITES[c["suite"]][0],
                                group=ALL_SUITES[c["suite"]][1], iter=r["i"], t_tcp_ms=r["t_tcp_ms"], t_hs_ms=r["t_hs_ms"],
                                t_total_ms=r["t_total_ms"], bytes_w=r["bytes_w"], bytes_r=r["bytes_r"],
                                snd_mss=r["snd_mss"], snd_cwnd0=r["snd_cwnd0"], retrans=r["retrans"],
                                rtt_us=r["rtt_us"], data_segs_out=r["data_segs_out"], data_segs_in=r["data_segs_in"],
                                    err=r["err"], reused=r.get("reused", "0"), prime_ms=r.get("prime_ms", "-1"), ts_utc=ts))
            out.flush()
            tt = sorted(float(r["t_total_ms"]) for r in ok)
            print(f"   ok {len(ok)}/{len(rows)}  median {tt[len(tt) // 2]:.1f} ms  ({info})", flush=True)
        print(f"done in {(time.time() - t_start) / 60:.1f} min -> {a.out}")
    finally:
        if proxy:
            proxy.terminate()
        if tb and not a.keep:
            tb.down()
        if out:
            out.close()
            if os.geteuid() == 0:
                # everything created as root (the results directory, work/, the CSV, env.json) goes back to the user
                for f in (os.path.dirname(a.out), work, a.out, os.path.join(os.path.dirname(a.out), "env.json")):
                    if os.path.exists(f):
                        os.chown(f, sudo_uid, -1)
                for f in os.listdir(work) if os.path.isdir(work) else []:
                    os.chown(os.path.join(work, f), sudo_uid, -1)


if __name__ == "__main__":
    main()
