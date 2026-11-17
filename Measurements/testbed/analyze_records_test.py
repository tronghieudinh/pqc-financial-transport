#!/usr/bin/env python3
"""analyze_records_test.py FILE : scores R1-R3 of results/records_test_predictions.md on the run_testbed CSV of results/records_test_configs.csv."""
import csv, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
def rd(f): return list(csv.DictReader(l for l in open(f) if not l.startswith("#")))
c = {}
for r in rd(sys.argv[1]):
    if r["err"] == "": c.setdefault((r["suite"], r["depth"], r["resp"], r["net_id"]), []).append(float(r["t_total_ms"]))
P = rd(os.path.join(HERE, "results", "records_test_predictions.csv")); flip, ctrl, e_on = [], [], []
for p in P:
    k = (p["suite"], p["depth"], p["resp"])
    if k + ("shaped",) not in c or k + ("base",) not in c: print("missing", k); continue
    m = st.median(c[k + ("shaped",)]) - st.median(c[k + ("base",)]); on, off = float(p["model_on_ms"]), float(p["model_off_ms"]); e_on.append(m - on)
    (flip if p["kind"] == "flip" else ctrl).append((k, m, on, off))
    print(f"{p['suite'][:9]:9s} d{p['depth']} {p['resp']:>6s} {p['kind']:7s} measured {m:7.1f}  with records {on:7.1f}  without {off:7.1f}")
n1 = sum(abs(m - on) < abs(m - off) for _, m, on, off in flip)
print(f"R1 flip cells closer to the model with records: {n1} of {len(flip)} (need {len(flip) - 1}):", "MET" if n1 >= len(flip) - 1 else "NOT MET")
mae = st.mean(abs(x) for x in e_on); big = sum(abs(x) > 12 for x in e_on)
print(f"R2 model with records, MAE {mae:.2f} ms (need <= 2.5), cells above 0.4 RTT {big} (need 0):", "MET" if mae <= 2.5 and big == 0 else "NOT MET")
n3 = sum(min(abs(m - on), abs(m - off)) <= 12 for _, m, on, off in ctrl)
print(f"R3 controls within 12 ms: {n3} of {len(ctrl)} (need {len(ctrl) - 1}):", "MET" if n3 >= len(ctrl) - 1 else "NOT MET")
nr = sum(abs(m - off) < abs(m - on) for _, m, on, off in flip)
print(f"Rejection: without records closer in {nr} of {len(flip)} flip cells:", "REJECTED" if nr >= 5 else "not rejected")
