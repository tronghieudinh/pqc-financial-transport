#!/usr/bin/env python3
"""
run_slack.py - Paper 2, WP5: direct measurement of how the Linux kernel grows the congestion window after a first flight, to confirm or
refute the "slack" hypothesis of the transport model (Net.cwnd_slack; the rule cwnd < 2 x segments-in-flight is met exactly at the
boundary by a 5-segment ClientHello, and the resumed ML-DSA-44 flow behaves as if the window had grown).

Uses tcp_flight (plain TCP, no TLS) in the netns testbed of tbnet.py. One factor is changed at a time from the base configuration
(RTT 100 ms, 100 Mbit/s, MTU 1500, initcwnd 10, Reno, quickack on, no TCP timestamps, no offload), so that a dependence of the rule on
the stack shows. Resumable: configurations already in the output file are skipped.

  stage A  (cwnd rule)   n1 = 1..16, 20, 24, 31, 40 segments, tiny second flight: the window the kernel actually has after n1 segments
  stage B  (timing)      n1 = 1..12, n2 = 9..16 (3..12 for icw4, 17..24 for icw20; Finished write of 80 bytes first, like TLS)
  --trace                also record the kernel tcp_probe tracepoint (snd_cwnd at every incoming ACK) for stage A of the base configuration

  sudo ./host_tune.sh on; sudo python3 run_slack.py --stage A,B ; sudo ./host_tune.sh off
"""
import argparse, csv, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tbnet  # noqa: E402

BASE = dict(rtt=100.0, rate=100.0, mtu=1500, icw=10, cc="reno", quickack=1, ts=0, offload=0)
CONFIGS = {
    "base": {},
    "rtt30": dict(rtt=30.0), "rtt5": dict(rtt=5.0), "rate10": dict(rate=10.0), "rate1000": dict(rate=1000.0),
    "mtu1280": dict(mtu=1280), "mtu9000": dict(mtu=9000),
    "icw4": dict(icw=4), "icw20": dict(icw=20),
    "delack": dict(quickack=0), "cubic": dict(cc="cubic"), "ts": dict(ts=1), "offload": dict(offload=1),
}
N1_A = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,20,24,31,40"
N1_B = "1,2,3,4,5,6,7,8,9,10,11,12"           # the whole range around the thresholds of every window below
# stage B: n2 brackets the window each configuration can have (initcwnd and the growth after n1); the others use the base list
N2_B_DEFAULT = "9,10,11,12,13,14,15,16"
STAGE_B = {"base": N2_B_DEFAULT, "delack": N2_B_DEFAULT, "offload": N2_B_DEFAULT, "cubic": N2_B_DEFAULT,
           "icw4": "3,4,5,6,7,8,9,10,11,12", "icw20": "17,18,19,20,21,22,23,24"}
STAGE_B_CONFIGS = tuple(STAGE_B)
COLS = ["cfg", "stage", "rtt", "rate", "mtu", "icw", "cc", "quickack", "ts", "offload", "n1", "n2", "rep", "split", "snd_mss", "cwnd0",
        "cwnd_pre2", "ssthresh", "unacked_pre2", "t_b1_ms", "t_b2_ms", "cwnd_end", "retrans", "rtt_us", "err"]
TRACE = "/sys/kernel/tracing"


def set_offload(tb, on):
    for ns, ifc in ((tbnet.NS_C, "vc0"), (tbnet.NS_S, "vs0")):
        tb.run(["ethtool", "-K", ifc, "tso", "on" if on else "off", "gso", "on" if on else "off", "gro", "on" if on else "off"],
               ns=ns, check=False, capture=True)


def run_flight(tb, cfg, stage, n1, n2, reps, split, w, trace_file=None):
    srv = subprocess.Popen(tb.exec_prefix("s") + [os.path.join(HERE, "tcp_flight"), "server", "--bind", tbnet.A_P1, "--port", "4500"],
                           stdout=subprocess.PIPE, text=True)
    try:
        srv.stdout.readline()                                  # READY
        tr = None
        if trace_file:
            open(f"{TRACE}/events/tcp/tcp_probe/enable", "w").write("1")
            tr = subprocess.Popen(["cat", f"{TRACE}/trace_pipe"], stdout=open(trace_file, "w"))
        cmd = tb.exec_prefix("c") + [os.path.join(HERE, "tcp_flight"), "client", "--connect", tbnet.A_P1, "--port", "4500", "--n1", n1,
                                      "--n2", n2, "--reps", str(reps), "--delay-ms", "30"] + (["--split"] if split else [])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if tr:
            time.sleep(0.5)
            tr.terminate()
            open(f"{TRACE}/events/tcp/tcp_probe/enable", "w").write("0")
        for row in csv.DictReader(r.stdout.splitlines()):
            w.writerow({**{k: cfg[k] for k in ("rtt", "rate", "mtu", "icw", "cc", "quickack", "ts", "offload")}, "cfg": cfg["name"], "stage": stage, **row})
    finally:
        srv.terminate()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", default="A,B")
    ap.add_argument("--configs", default=",".join(CONFIGS))
    ap.add_argument("--reps-a", type=int, default=20)
    ap.add_argument("--reps-b", type=int, default=15)
    ap.add_argument("--out", default=os.path.join(HERE, "results", "slack_tcp.csv"))
    ap.add_argument("--trace", action="store_true", help="tcp_probe tracepoint for stage A of the configurations in --trace-configs (needs tracefs)")
    ap.add_argument("--trace-configs", default="base", help="comma list of configurations to trace with --trace (WP6 B5: mtu9000)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.geteuid() != 0 and not a.dry_run:
        sys.exit("run with sudo")
    if not os.path.exists(os.path.join(HERE, "tcp_flight")):
        sys.exit("tcp_flight not built: gcc -O2 -o tcp_flight tcp_flight.c (setup_host.sh does it)")
    stages = a.stage.split(",")
    if not a.dry_run:                                   # the kernel and the settings the rule depends on (WP6 B6: repeat on another kernel)
        import json, platform
        def sysctl(k):
            try:
                return open("/proc/sys/" + k.replace(".", "/")).read().strip()
            except OSError:
                return ""
        env = dict(kernel=platform.release(), machine=platform.machine(), cpu=subprocess.run("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2", shell=True, capture_output=True, text=True).stdout.strip(),
                   congestion_control=sysctl("net.ipv4.tcp_congestion_control"), slow_start_after_idle=sysctl("net.ipv4.tcp_slow_start_after_idle"),
                   initial_window_default=10, utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), args=vars(a))
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        json.dump(env, open(os.path.splitext(a.out)[0] + "_env.json", "w"), indent=2)
    names = a.configs.split(",")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    done = set()
    if os.path.exists(a.out):
        done = {(r["cfg"], r["stage"]) for r in csv.DictReader(open(a.out)) if r["err"] == ""}
    new = not os.path.exists(a.out)
    fh = open(a.out, "a", newline="")
    w = csv.DictWriter(fh, fieldnames=COLS)
    if new:
        w.writeheader()
    for ts in (0, 1):
        todo = [n for n in names if {**BASE, **CONFIGS[n]}["ts"] == ts]
        if not todo:
            continue
        tb = tbnet.Testbed("direct", dry_run=a.dry_run, timestamps=bool(ts))
        tb.up()
        try:
            for n in todo:
                cfg = {**BASE, **CONFIGS[n], "name": n}
                tb.shape(cfg["rtt"], cfg["rate"], 0.0, cfg["mtu"], cfg["icw"], cfg["cc"], quickack=bool(cfg["quickack"]))
                set_offload(tb, cfg["offload"])
                if not a.dry_run and not tb.smoke_test():
                    print(f"{n}: ping failed, skipped", file=sys.stderr)
                    continue
                for st in stages:
                    if (n, st) in done or (st == "B" and n not in STAGE_B):
                        continue
                    print(f"[{time.strftime('%H:%M:%S')}] {n} stage {st}", flush=True)
                    if a.dry_run:
                        continue
                    if st == "A":
                        tf = os.path.join(os.path.dirname(a.out), f"slack_trace_{n}.txt") if (a.trace and n in a.trace_configs.split(",")) else None
                        run_flight(tb, cfg, "A", N1_A, "1", a.reps_a, False, w, tf)
                    else:
                        run_flight(tb, cfg, "B", N1_B, STAGE_B[n], a.reps_b, True, w)
                    fh.flush()
                set_offload(tb, 0)
        finally:
            tb.down()
    fh.close()
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and os.path.exists(a.out):
        os.chown(a.out, int(sudo_uid), -1)


if __name__ == "__main__":
    main()
