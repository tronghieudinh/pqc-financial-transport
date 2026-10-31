#!/usr/bin/env python3
"""
tls_trace.py - real TLS 1.3 handshakes (OpenSSL 3.5) through relay.py on loopback.

For every suite, chain depth 1-4 and authentication mode (mutual TLS or server-only) it runs N
handshakes and records the bytes of the three handshake flights - ClientHello (CH), server
flight (SF), client flight (CF) - and the loopback handshake time (first CH byte to last byte of
the client flight), which is dominated by real cryptographic computation.

    python3 tls_trace.py [N]   -> data/tls_trace.csv, data/tls_trace_raw.jsonl
"""
import csv
import json
import os
import statistics as st
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
O = os.path.expanduser("~/opt/openssl-3.5/bin/openssl")
ENV = dict(os.environ, LD_LIBRARY_PATH=os.path.expanduser("~/opt/openssl-3.5/lib"))
ALERT = 0           # s_client -quiet implies -ign_eof: it sends no close_notify; the server's 24-byte
                    # alert travels server->client and starts a fourth run, which is ignored

# simulator suite name -> (certificate algorithm, TLS group)
SUITES = {
    "RSA-2048|ECDHE-P256": ("RSA-2048", "secp256r1"),
    "RSA-3072|ECDHE-P256": ("RSA-3072", "secp256r1"),
    "ECDSA-P256|X25519": ("ECDSA-P256", "x25519"),
    "ECDSA-P256|X25519MLKEM768": ("ECDSA-P256", "X25519MLKEM768"),
    "ML-DSA-44|ML-KEM-768": ("ML-DSA-44", "MLKEM768"),
    "ML-DSA-65|ML-KEM-768": ("ML-DSA-65", "MLKEM768"),
    "ML-DSA-87|ML-KEM-1024": ("ML-DSA-87", "MLKEM1024"),
    "SLH-DSA-128s|ML-KEM-768": ("SLH-DSA-SHA2-128s", "MLKEM768"),
    "SLH-DSA-128f|ML-KEM-768": ("SLH-DSA-SHA2-128f", "MLKEM768"),
}


def flights(chunks):
    """Group relay chunks into direction runs: CH, SF, CF (a later server close_notify run is ignored)."""
    runs = []
    for t, d, n in chunks:
        if runs and runs[-1]["dir"] == d:
            runs[-1]["bytes"] += n
            runs[-1]["t_end"] = t
        else:
            runs.append({"dir": d, "bytes": n, "t_start": t, "t_end": t})
    if len(runs) < 3 or [r["dir"] for r in runs[:3]] != [0, 1, 0]:
        return None
    cf = runs[2]["bytes"] - ALERT
    return runs[0]["bytes"], runs[1]["bytes"], cf, runs[2]["t_end"] - runs[0]["t_start"]


def run(suite, alg, group, depth, mtls, n, port):
    d = os.path.join(HERE, "certs", alg, f"d{depth}")
    log = os.path.join(HERE, "data", f"relay_{port}.jsonl")
    if os.path.exists(log):
        os.remove(log)
    chain = ["-cert_chain", "inter_chain.pem"] if depth > 1 else []
    srv = subprocess.Popen(["taskset", "-c", "15", O, "s_server", "-accept", f"127.0.0.1:{port}", "-cert", "server.pem",
                            "-key", "server.key", *chain, "-verifyCAfile", "root.pem", "-num_tickets", "0",
                            "-groups", group, "-naccept", str(n), "-quiet"] + (["-Verify", "5"] if mtls else []),
                           cwd=d, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    rel = subprocess.Popen(["taskset", "-c", "17", sys.executable, os.path.join(HERE, "relay.py"), "--listen",
                            str(port + 1), "--upstream", str(port), "--log", log], stdout=subprocess.PIPE, text=True)
    rel.stdout.readline()                    # READY
    time.sleep(0.3)
    ok = 0
    for _ in range(n):
        cmd = ["taskset", "-c", "16", O, "s_client", "-connect", f"127.0.0.1:{port + 1}", "-verifyCAfile", "root.pem",
               "-groups", group, "-verify_return_error", "-quiet"]
        if mtls:
            cmd += ["-cert", "client.pem", "-key", "client.key", *chain]
        r = subprocess.run(cmd, cwd=d, env=ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        ok += r.returncode == 0
    time.sleep(0.3)
    rel.terminate()
    srv.terminate()
    err = srv.stderr.read().decode(errors="replace")[-300:] if ok == 0 else ""
    res = []
    if os.path.exists(log):
        for line in open(log):
            f = flights(json.loads(line)["chunks"])
            if f:
                res.append(f)
        os.remove(log)
    return ok, res, err


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 21
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
    out = open(os.path.join(HERE, "data", "tls_trace.csv"), "w", newline="")
    w = csv.writer(out)
    w.writerow(["suite", "cert_alg", "group", "depth", "mtls", "n_ok", "ch_bytes", "sf_bytes", "cf_bytes",
                "hs_ms_median", "hs_ms_p10", "hs_ms_p90", "note"])
    port = 45000
    for suite, (alg, group) in SUITES.items():
        for depth in (1, 2, 3, 4):
            for mtls in (True, False):
                port += 2
                ok, res, err = run(suite, alg, group, depth, mtls, n, port)
                if not res:
                    w.writerow([suite, alg, group, depth, int(mtls), ok, "", "", "", "", "", "", err.replace("\n", " ")[:200]])
                    print(f"{suite} d{depth} mtls={mtls}: FAILED {err[:120]!r}", flush=True)
                    continue
                ch, sf, cf = (st.median([r[i] for r in res]) for i in range(3))
                ts = sorted(r[3] for r in res)
                w.writerow([suite, alg, group, depth, int(mtls), ok, int(ch), int(sf), int(cf),
                            round(st.median(ts), 3), round(ts[len(ts) // 10], 3), round(ts[(9 * len(ts)) // 10], 3), ""])
                out.flush()
                print(f"{suite} d{depth} mtls={int(mtls)}: ok={ok} CH={int(ch)} SF={int(sf)} CF={int(cf)} hs={st.median(ts):.2f} ms", flush=True)
    out.close()


if __name__ == "__main__":
    main()
