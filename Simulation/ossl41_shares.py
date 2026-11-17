#!/usr/bin/env python3
"""ossl41_shares.py - how the transport-bound shares of Table 5 (Paper 1) change if the ML-DSA primitive costs are those of OpenSSL 4.1.0 instead of 3.5.4.
    python3 ossl41_shares.py [--out DIR]       (runs pqc_sim.py three times in temporary copies; about 10 s; nothing in the repository is modified)
The costs of pqc_sim.py are OpenSSL 3.5.4 on the Cortex-X925. Ratios 4.1.0 / 3.5.4 are those measured by analyze_v5.py (results/gx10_7.0_v5_arm_20261115.txt and
results/ossl_versions_i9_rep_analysis.txt): Arm: sign 0.379 / 0.371 / 0.374 and verify 0.451 / 0.465 / 0.487 for ML-DSA-44 / 65 / 87;  x86 (i9): sign 0.30, verify 0.46.
ML-KEM (-0.7 to -2.1 %) and the other algorithms are not changed; composite suites follow because pqc_sim.py sums the constituents.
Prints, per suite, the share of cold rows with overhead > Tcpu for pi = 0 and for all pi (the two columns of Table 5) and the depth effect (depth 4 minus 1) of ML-DSA-65 in SWIFT MX."""
import argparse, csv, os, re, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("--out"); a = ap.parse_args()
SRC = open(os.path.join(HERE, "pqc_sim.py")).read()
BASE = {"ML-DSA-44": (0.3594, 0.06804), "ML-DSA-65": (0.586, 0.103), "ML-DSA-87": (0.6691, 0.1589)}
ARM = {"ML-DSA-44": (0.379, 0.451), "ML-DSA-65": (0.371, 0.465), "ML-DSA-87": (0.374, 0.487)}
X86 = {k: (0.30, 0.46) for k in BASE}
def run(tmp, name, ratio):
    d = os.path.join(tmp, name); os.makedirs(d)
    s = SRC
    if ratio:
        for alg, (sg, vf) in BASE.items():
            pat = re.compile(r'(Sig\("%s",\s+"lattice",\s+\d+,\s+\d+,\s+\d+,\s+)([0-9.]+), ([0-9.]+)\)' % re.escape(alg))
            assert pat.search(s), alg
            s = pat.sub(lambda m: m.group(1) + "%.5f, %.5f)" % (sg * ratio[alg][0], vf * ratio[alg][1]), s)
    open(os.path.join(d, "pqc_sim.py"), "w").write(s)
    subprocess.run([sys.executable, "pqc_sim.py", "--out", "out", "--jobs", "1"], cwd=d, check=True, capture_output=True)
    return list(csv.DictReader(open(os.path.join(d, "out", "results.csv"))))
def shares(rows):
    cold = [r for r in rows if r["mode"] == "cold"]; out = {}
    for s in sorted({r["suite"] for r in cold}):
        sub = [r for r in cold if r["suite"] == s]; z = [r for r in sub if float(r["penalty_ms"]) == 0]
        f = lambda L: 100 * sum(float(r["ser_ms"]) + float(r["ssw_ms"]) + float(r["pen_ms"]) > float(r["cpu_ms"]) for r in L) / len(L)
        out[s] = (f(z), f(sub))
    return out
def depth(rows):
    g = lambda d: [r for r in rows if r["suite"] == "ML-DSA-65|ML-KEM-768" and r["protocol"] == "SWIFT_MX" and r["mode"] == "cold" and r["depth"] == str(d)
                   and float(r["bw_mbps"]) == 100 and float(r["rtt_ms"]) == 30 and r["mtu"] == "1500" and float(r["penalty_ms"]) == 0][0]
    return float(g(4)["total_ms"]) - float(g(1)["total_ms"])
with tempfile.TemporaryDirectory() as tmp:
    R = {n: run(tmp, n, r) for n, r in (("3.5.4", None), ("4.1.0, Arm ratios", ARM), ("4.1.0, x86 ratios", X86))}
S = {n: shares(r) for n, r in R.items()}
lines = ["suite | " + " | ".join(f"{n} (pi=0, all pi) %" for n in R)]
for s in S["3.5.4"]: lines.append(f"{s:36s} | " + " | ".join(f"{S[n][s][0]:5.1f} {S[n][s][1]:5.1f}" for n in R))
lines.append("depth effect ML-DSA-65 SWIFT MX (ms): " + ", ".join(f"{n}: {depth(r):.2f}" for n, r in R.items()))
print("\n".join(lines))
if a.out: open(a.out, "w").write("\n".join(lines) + "\n")
