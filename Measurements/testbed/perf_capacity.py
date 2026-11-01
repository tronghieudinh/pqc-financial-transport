#!/usr/bin/env python3
"""
perf_capacity.py - where does the CPU of a saturated TLS 1.3 server go? (paper 2, WP6 B8). Needs `perf` (linux-tools); root or perf_event_paranoid <= 1.

Runs tls_serve on one core, saturates it with tls_load, records `perf record -F 999 -g` of the server for --time seconds and writes the share of samples by
shared object (libcrypto, libssl, kernel, tls_serve, libc) for ML-DSA-65 and ECDSA-P256, full transactions, mutual TLS, depth 2. This is the white-box
view used by Sosnowski et al.; it explains the 0.08-0.33 ms (Arm) and 0.38-1.30 ms (x86) beyond the sum of the primitives reported in the paper.
"""
import argparse, os, shutil, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capacity_test as CT  # noqa: E402
RT, ALL = CT.RT, CT.ALL_SUITES


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "results", "wp6_perf.txt"))
    ap.add_argument("--server-cpu", type=int, default=-1)
    ap.add_argument("--client-cpus", default="")
    ap.add_argument("--time", type=float, default=15.0)
    a = ap.parse_args()
    if not shutil.which("perf"):
        sys.exit("perf not found (apt install linux-tools-$(uname -r))")
    topo = CT.topology()
    scpu = a.server_cpu if a.server_cpu >= 0 else topo[0][0]
    ccpus = [int(x) for x in a.client_cpus.split(",")] if a.client_cpus else [c for t in topo[1:] for c in t] or [c for t in topo for c in t if c != scpu]
    out = open(a.out, "w")
    port = 49500
    for suite in ("ECDSA-P256|X25519", "ML-DSA-65|ML-KEM-768"):
        port += 1
        alg, group = ALL[suite]
        ch = RT.ensure_chain(alg, 2, os.path.join(HERE, "work"))
        scmd = [os.path.join(HERE, "tls_serve"), "--addr", "127.0.0.1", "--port", str(port), "--cert", ch["server"][0], "--key", ch["server"][1], "--ca", ch["ca"],
                "--groups", group, "--req", "302", "--resp", "222", "--reuseport", "--mtls"]
        srv = CT.Server(scmd, scpu)
        ccmd = ["taskset", "-c", CT.cpu_list(ccpus), os.path.join(HERE, "tls_load"), "--addr", "127.0.0.1", "--port", str(port), "--ca", ch["ca"], "--groups", group,
                "--req", "302", "--resp", "222", "--threads", str(max(8, 4 * len(ccpus))), "--time", str(a.time + 2), "--warmup", "2", "--cert", ch["client"][0], "--key", ch["client"][1]]
        cl = subprocess.Popen(ccmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(2.5)
            data = os.path.join(HERE, "work", f"perf_{port}.data")
            subprocess.run(["perf", "record", "-F", "999", "-g", "-p", str(srv.p.pid), "-o", data, "--", "sleep", str(a.time)], capture_output=True, text=True)
            rep = subprocess.run(["perf", "report", "-i", data, "--no-children", "--sort", "dso", "--stdio"], capture_output=True, text=True).stdout
            out.write(f"== {suite}, mutual TLS, depth 2, full transactions, one core, {a.time:g} s of samples\n")
            out.write("\n".join(l for l in rep.splitlines() if l.strip() and not l.lstrip().startswith("#") and "%" in l and "--" not in l)[:3000] + "\n\n")
        finally:
            srv.stop()
            cl.kill()
    out.close()
    print(open(a.out).read())


if __name__ == "__main__":
    main()
