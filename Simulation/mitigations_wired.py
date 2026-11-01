#!/usr/bin/env python3
"""
mitigations_wired.py - the wired-path mitigation study of paper 2 under the validated stack (Linux window validation, OpenSSL write
pattern) and under the idealised closed form of the earlier work, side by side.

    python3 mitigations_wired.py [--out mitigations_wired.csv]

For every protocol, suite and mitigation of mitigations.py on the two wired reference paths it writes the latency under both stack
models and the factor over the classical baseline without mitigation. QUIC is modelled by the simplified QUIC mode of pqc_sim.py
(no TCP handshake, 1250-byte datagrams, 3x anti-amplification limit); it has NOT been validated against a real QUIC stack, and its
window behaviour is that of the model, not of a measured implementation.
"""
import argparse
import csv
import itertools
import os

import pqc_sim as S
import mitigations as M

PATHS = {"wired": (100.0, 30.0, 1500), "wired_slow": (10.0, 100.0, 1500)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "mitigations_wired.csv"))
    a = ap.parse_args()
    rows = []
    for pr, mit, su in itertools.product(M.PROTOS, M.MITIG, M.SUITES):
        q = M.MITIG[mit][2]
        f = M.flow(su, pr, mit)
        for name, (bw, rtt, mtu) in PATHS.items():
            r = {"protocol": pr, "mitigation": mit, "path": name, "suite": su}
            for stk in ("linux-openssl", "v4"):
                net = S.Net(bw, rtt, mtu, 0.0, 4, quic=q, **S.STACKS[stk])
                r[f"ms_{stk}"] = round(S.run_flow(f, net)["total"], 3)
            rows.append(r)
    base = {(r["protocol"], r["path"], k): r[f"ms_{k}"] for r in rows if r["mitigation"] == "none" and r["suite"] == M.SUITES[0]
            for k in ("linux-openssl", "v4")}
    for r in rows:
        for k in ("linux-openssl", "v4"):
            r[f"factor_{k}"] = round(r[f"ms_{k}"] / base[(r["protocol"], r["path"], k)], 3)
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {a.out}")


if __name__ == "__main__":
    main()
