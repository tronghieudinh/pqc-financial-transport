#!/usr/bin/env python3
"""analyze_mldsa_sweep.py --v6 FILE --v4 FILE : scores S1-S3 of results/mldsa_d1_sweep_predictions.md (transition = first response whose excess is > 15 ms above the cell 200 B below)."""
import argparse, csv, statistics as st
ap = argparse.ArgumentParser(); ap.add_argument("--v6", required=True); ap.add_argument("--v4", required=True); a = ap.parse_args()
def rd(f): return list(csv.DictReader(l for l in open(f) if not l.startswith("#")))
def exc(f):
    c = {}
    for r in rd(f):
        if r["err"] == "": c.setdefault((int(r["resp"]), r["net_id"]), []).append(float(r["t_total_ms"]))
    return {k[0]: st.median(v) - st.median(c[(k[0], "base")]) for k, v in c.items() if k[1] == "shaped" and (k[0], "base") in c}
def trans(e):
    ks = sorted(e); return [(k, e[k] - e[p]) for p, k in zip(ks, ks[1:]) if e[k] - e[p] > 15]
res = {}
for n, f in (("IPv6", a.v6), ("IPv4", a.v4)):
    e = exc(f); res[n] = trans(e)
    print(n, "excess by response:", " ".join(f"{k}:{e[k]:.0f}" for k in sorted(e))); print(n, "transitions (resp, jump ms):", [(k, round(j, 1)) for k, j in res[n]])
t6 = res["IPv6"][0][0] if res["IPv6"] else None; t4 = res["IPv4"][0][0] if res["IPv4"] else None
print("S1 transition below 22 500 B for IPv6:", "MET" if t6 else "NOT MET", t6)
if t6 and t4:
    print(f"S2 t4 - t6 = {t4 - t6} B (predicted 400 +-200):", "MET" if abs(t4 - t6 - 400) <= 200 else "NOT MET")
    print(f"S3 t6 {t6} within 400 B of 20 600:", "MET" if abs(t6 - 20600) <= 400 else f"NOT MET; undercount D about {23000 - t6} B")
