#!/usr/bin/env python3
"""
resumption.py - real TLS 1.3 PSK session resumption (OpenSSL 3.5) through relay.py on loopback.

For each suite, chain depth and authentication mode: one full handshake stores a session ticket
(-sess_out), then N resumed handshakes reuse it (-sess_in). The relay records the bytes of the
resumed ClientHello (which carries the ticket), server flight and client flight.

    python3 resumption.py [N]  -> data/resumption.csv
"""
import csv
import json
import os
import re
import statistics as st
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.join(HERE, "certs")
O = os.path.expanduser("~/opt/openssl-3.5/bin/openssl")
ENV = dict(os.environ, LD_LIBRARY_PATH=os.path.expanduser("~/opt/openssl-3.5/lib"))
SUITES = {
    "RSA-2048|ECDHE-P256": ("RSA-2048", "secp256r1"),
    "ECDSA-P256|X25519": ("ECDSA-P256", "x25519"),
    "ECDSA-P256|X25519MLKEM768": ("ECDSA-P256", "X25519MLKEM768"),
    "ML-DSA-44|ML-KEM-768": ("ML-DSA-44", "MLKEM768"),
    "ML-DSA-65|ML-KEM-768": ("ML-DSA-65", "MLKEM768"),
    "ML-DSA-87|ML-KEM-1024": ("ML-DSA-87", "MLKEM1024"),
}


def runs(chunks):
    out = []
    for t, d, n in chunks:
        if out and out[-1][0] == d:
            out[-1][1] += n
        else:
            out.append([d, n])
    return out


def ticket_len(sess):
    txt = subprocess.run([O, "sess_id", "-in", sess, "-text", "-noout"], env=ENV, capture_output=True, text=True).stdout
    m = re.search(r"TLS session ticket:\s*\n((?:\s+[0-9a-f]{4} - .*\n)+)", txt)
    if not m:
        return None
    hexbytes = re.findall(r"\b[0-9a-f]{2}\b", re.sub(r"^\s+[0-9a-f]{4} - ", "", m.group(1), flags=re.M).split("   ")[0])
    lines = [l for l in m.group(1).splitlines() if l.strip()]
    last = lines[-1].strip()
    off = int(last.split(" - ")[0], 16)
    nb = len(re.findall(r"[0-9a-f]{2}(?=[ -]|$)", last.split(" - ")[1][:48]))
    return off + nb


def run(alg, group, depth, mtls, n, port):
    d = os.path.join(CERTS, alg, f"d{depth}")
    log = os.path.join(HERE, "data", f"relay_{port}.jsonl")
    sess = os.path.join(HERE, "data", f"sess_{port}.pem")
    for p in (log, sess):
        if os.path.exists(p):
            os.remove(p)
    chain = ["-cert_chain", "inter_chain.pem"] if depth > 1 else []
    srv = subprocess.Popen(["taskset", "-c", "15", O, "s_server", "-accept", f"127.0.0.1:{port}", "-cert", "server.pem",
                            "-key", "server.key", *chain, "-verifyCAfile", "root.pem", "-num_tickets", "1",
                            "-groups", group, "-naccept", str(n + 1), "-quiet"] + (["-Verify", "5"] if mtls else []),
                           cwd=d, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rel = subprocess.Popen(["taskset", "-c", "17", sys.executable, os.path.join(HERE, "relay.py"),
                            "--listen", str(port + 1), "--upstream", str(port), "--log", log],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    rel.stdout.readline()
    time.sleep(0.3)
    base = ["taskset", "-c", "16", O, "s_client", "-connect", f"127.0.0.1:{port + 1}", "-verifyCAfile", "root.pem",
            "-groups", group, "-verify_return_error"]
    auth = ["-cert", "client.pem", "-key", "client.key", *chain] if mtls else []
    subprocess.run(base + auth + ["-sess_out", sess, "-quiet"], cwd=d, env=ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    reused = 0
    for _ in range(n):
        r = subprocess.run(base + auth + ["-sess_in", sess, "-ign_eof"], cwd=d, env=ENV, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=60)
        reused += "Reused, TLSv1.3" in r.stdout
    time.sleep(0.3)
    rel.terminate()
    srv.terminate()
    conns = [runs(json.loads(l)["chunks"]) for l in open(log)] if os.path.exists(log) else []
    tl = ticket_len(sess) if os.path.exists(sess) else None
    for p in (log, sess):
        if os.path.exists(p):
            os.remove(p)
    return reused, conns, tl


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    out = open(os.path.join(HERE, "data", "resumption.csv"), "w", newline="")
    w = csv.writer(out)
    w.writerow(["suite", "depth", "mtls", "reused", "ticket_bytes", "full_ch", "full_sf", "full_cf",
                "res_ch", "res_sf", "res_cf", "res_new_ticket"])
    port = 52000
    for suite, (alg, group) in SUITES.items():
        for depth in (1, 2, 4):
            for mtls in (True, False):
                port += 2
                reused, conns, tl = run(alg, group, depth, mtls, n, port)
                if len(conns) < 2:
                    print(suite, depth, mtls, "FAILED")
                    continue
                full = conns[0]
                res = [c for c in conns[1:] if len(c) >= 3 and [x[0] for x in c[:3]] == [0, 1, 0]]
                med = lambda i: int(st.median(c[i][1] for c in res))
                nst = int(st.median(c[3][1] for c in res if len(c) > 3 and c[3][0] == 1)) if any(len(c) > 3 for c in res) else 0
                w.writerow([suite, depth, int(mtls), reused, tl, full[0][1], full[1][1], full[2][1], med(0), med(1), med(2), nst])
                out.flush()
                print(f"{suite} d{depth} mtls={int(mtls)} reused={reused}/{n} ticket={tl} full={full[0][1]}/{full[1][1]}/{full[2][1]} "
                      f"resumed={med(0)}/{med(1)}/{med(2)}", flush=True)
    out.close()


if __name__ == "__main__":
    main()
