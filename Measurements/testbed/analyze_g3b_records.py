#!/usr/bin/env python3
"""analyze_g3b_records.py RUN_DIR... - POST HOC check (not pre-registered) of the G3b cells (full handshakes, MTU 9000) against the stack model with Model(app_records=True)
(one write per TLS record of at most 16 384 bytes, option defined earlier for resumed transactions; Paper 1 appendix SE) and with the default (one write per message).
Per run, buffer (default / large) and request size: cells within 2 ms, cells within 2 ms after removing the median offset, cells more than 50 ms off, for both models."""
import csv, collections, statistics as st, sys, os
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import analyze_testbed as A
S = A.S
ROWS = list(csv.DictReader(open(os.path.join(HERE, "results", "wp6_pred_mtu9000_full.csv"))))
def model(row, rec):
    fl = S.build_flow(row["suite"], A.probe_protocol(row["mtls"], row["req"], row["resp"], row["depth"]), int(row["depth"]), "cold", False, S.Model(app_records=rec))
    n = S.Net(float(row["rate_mbps"]), float(row["rtt_ms"]), int(row["mtu"]), penalty_ms=0.0, thr=4, init_cwnd=int(row["icw"]), cwnd_validation=True, segmentation="openssl", cwnd_slack=0, hdr=60)
    r = S.run_flow(fl, n); return r["total"] - r["cpu"]
M = {(r["suite"], r["depth"], r["mtls"], r["req"], r["resp"], rec): model(r, rec) for r in ROWS for rec in (False, True)}
for run in sys.argv[1:]:
    for tag in ("default", "large"):
        f = f"{run}/data/{tag}/tls_mtu9000_full.csv"
        if not os.path.exists(f): continue
        c = collections.defaultdict(list)
        for r in csv.DictReader(l for l in open(f) if not l.startswith("#")):
            if not r["err"]: c[(r["suite"], r["depth"], r["mtls"], r["req"], r["resp"], r["net_id"])].append(float(r["t_total_ms"]))
        meas = {k[:5]: st.median(v) - st.median(c[k[:5] + ("base",)]) for k, v in c.items() if k[5] == "shaped" and k[:5] + ("base",) in c}
        for req in ("302", "19460"):
            ks = [k for k in meas if k[3] == req and k + (False,) in M]
            if not ks: continue
            out = []
            for rec in (False, True):
                e = [meas[k] - M[k + (rec,)] for k in ks]; off = st.median(e)
                out.append(f"records={'on ' if rec else 'off'}: within 2 ms {sum(abs(x) <= 2 for x in e):2d}, after offset {off:+.1f} ms {sum(abs(x - off) <= 2 for x in e):2d}, >50 ms off {sum(abs(x) > 50 for x in e)}")
            print(f"{os.path.basename(os.path.normpath(run)):26s} {tag:7s} req {req:>5s} n={len(ks)}  " + " | ".join(out))
