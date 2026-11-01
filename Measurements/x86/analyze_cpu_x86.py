#!/usr/bin/env python3
"""
analyze_cpu_x86.py - x86 CPU costs against the Arm measurements, and a CPU check against the testbed.

    python3 analyze_cpu_x86.py [--x86-dir data] [--latex ../../paper]

Inputs   data/cpu_openssl_x86.csv, data/cpu_liboqs_x86.csv   (run_bench_x86.sh on the x86 machine)
         ../data/cpu_*_core19.csv (Cortex-X925, the simulator's default) and ../data/cpu_*_core4.csv (Cortex-A725)
         ../testbed/results/*.csv                             (unshaped "base" transactions on the same x86 machine)
Outputs  data/cpu_x86_vs_arm.csv       every primitive: X925, A725, x86 cost (ms) and the ratios
         data/cpu_validation.csv       measured unshaped transaction time against the modelled CPU time
         <latex>/numbers_cpu.tex, <latex>/tables/tab_cpu_x86.tex

The validation compares the median time of an unshaped transaction (client and server on one machine, no network
delay) with the sum of the modelled CPU steps built from the x86 costs: the difference is the library, kernel and
scheduling overhead that the model does not contain.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MEAS = os.path.join(HERE, "..")
sys.path.insert(0, MEAS)
sys.path.insert(0, os.path.join(MEAS, "testbed"))
sys.path.insert(0, os.path.join(MEAS, "..", "Simulation"))
import make_inputs as MI  # noqa: E402
import pqc_sim as S  # noqa: E402
import analyze_testbed as A  # noqa: E402

OPS = [("RSA-2048", "sign"), ("RSA-2048", "verify"), ("ECDSA-P256", "sign"), ("ECDSA-P256", "verify"),
       ("ML-DSA-44", "sign"), ("ML-DSA-44", "verify"), ("ML-DSA-65", "sign"), ("ML-DSA-65", "verify"),
       ("ML-DSA-87", "sign"), ("ML-DSA-87", "verify"), ("oqs:Falcon-padded-512", "sign"), ("oqs:Falcon-padded-512", "verify"),
       ("SLH-DSA-SHA2-128s", "sign"), ("SLH-DSA-SHA2-128s", "verify"), ("SLH-DSA-SHA2-128f", "sign"),
       ("SLH-DSA-SHA2-128f", "verify"), ("X25519", "keygen"), ("X25519", "derive"), ("ML-KEM-768", "keygen"),
       ("ML-KEM-768", "encaps"), ("ML-KEM-768", "decaps")]
LABEL = {"oqs:Falcon-padded-512": "Falcon-512", "SLH-DSA-SHA2-128s": "SLH-DSA-128s", "SLH-DSA-SHA2-128f": "SLH-DSA-128f"}
OPNAME = {"keygen": "key generation", "derive": "derive", "encaps": "encapsulate", "decaps": "decapsulate"}


def load_x86(d):
    t, oqs = {}, {}
    for r in csv.DictReader(open(os.path.join(d, "cpu_openssl_x86.csv"))):
        t[(r["alg"], r["op"])] = float(r["median_us"]) / 1000.0
    p = os.path.join(d, "cpu_liboqs_x86.csv")
    if os.path.exists(p):
        for r in csv.DictReader(open(p)):
            oqs.setdefault((r["alg"], r["op"]), []).append(float(r["median_us"]) / 1000.0)
    for k, v in oqs.items():
        t[("oqs:" + k[0], k[1])] = st.median(v)
    return t


def fmt(x):
    return f"{x:.3g}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--x86-dir", default=os.path.join(HERE, "data"))
    ap.add_argument("--latex", default=os.path.join(HERE, "..", "..", "paper"))
    a = ap.parse_args()
    x925, a725, x86 = MI.load(19), MI.load(4), load_x86(a.x86_dir)

    rows, rat = [], {"sig": [], "kem": [], "a725": []}
    for k in OPS:
        if k not in x86 or k not in x925:
            continue
        r = dict(primitive=LABEL.get(k[0], k[0]), op=k[1], x925_ms=x925[k], a725_ms=a725.get(k, float("nan")), x86_ms=x86[k],
                 x86_over_x925=x86[k] / x925[k], x86_over_a725=x86[k] / a725[k] if k in a725 else float("nan"))
        rows.append(r)
        rat["kem" if k[0] in ("X25519", "ML-KEM-768") else "sig"].append(r["x86_over_x925"])
        if k in a725:
            rat["a725"].append(a725[k] / x925[k])
    with open(os.path.join(a.x86_dir, "cpu_x86_vs_arm.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.5g}" if isinstance(v, float) else v) for k, v in r.items()})

    nums = {}
    for tag, key in (("Sig", "sig"), ("Kem", "kem")):
        v = rat[key]
        if v:
            nums[f"cpuX{tag}Med"], nums[f"cpuX{tag}Min"], nums[f"cpuX{tag}Max"] = fmt(st.median(v)), fmt(min(v)), fmt(max(v))
    nums["cpuAArmMed"] = fmt(st.median(rat["a725"]))
    for k, name in ((("ML-DSA-65", "sign"), "MlSign"), (("ECDSA-P256", "sign"), "EcSign"), (("oqs:Falcon-padded-512", "sign"), "FalSign"),
                    (("SLH-DSA-SHA2-128s", "sign"), "SlhsSign")):
        if k in x86 and k in x925:
            nums[f"cpuX{name}"] = fmt(x86[k] / x925[k])
    # ------------------------------------------------------------------ validation against the testbed base runs
    xi = None
    try:
        xi = MI.inputs(x86)
    except KeyError as e:      # liboqs rows missing: Falcon cannot be modelled
        print("(no x86 Falcon costs:", e, ")")
        xi = None
    ai = MI.inputs(x925)

    def install(inp):
        for n, v in inp["sigs"].items():
            S.SIGS[n] = dataclasses.replace(S.SIGS[n], sign_ms=v["sign_ms"], verify_ms=v["verify_ms"])
        for n, v in inp["kex"].items():
            S.KEXS[n] = dataclasses.replace(S.KEXS[n], gen_ms=v["gen_ms"], derive_ms=v["derive_ms"], server_ms=v["server_ms"])
        S.build_flow.cache_clear()

    def cpu_ms(suite, depth):
        f = S.build_flow(suite, A.probe_protocol(1, 302, 222, depth), depth, "cold", False)
        return sum(s[1] for s in f.steps if s[0] == "cpu")

    raw = []
    rdir = os.path.join(MEAS, "testbed", "results")
    for n in sorted(os.listdir(rdir)) if os.path.isdir(rdir) else []:
        # raw runs of the reference stack only: not the analysis outputs, and not the variants with other TCP settings
        if n.endswith(".csv") and n not in ("model_vs_testbed.csv", "testbed_summary.csv", "residual_groups.csv", "residual_worst.csv",
                                            "variants_summary.csv", "delack.csv", "ts.csv", "delack_ts.csv", "bbr.csv", "resume.csv",
                                            "resume_swift.csv", "loss.csv") \
                and "topology" in open(os.path.join(rdir, n)).readline().split(","):          # raw testbed runs only (not analysis outputs)
            raw += [r for r in A.load(os.path.join(rdir, n), False) if r["net_id"] == "base" and r["topology"] == "direct"
                    and r["cc"] == "reno" and int(r["req"]) == 302 and r["mtls"] == "1"]
    base = {k: c for k, c in A.aggregate(raw).items()} if raw else {}
    val = []
    if base and xi:
        by = {}
        for c in base.values():
            by[(c["suite"], int(c["depth"]))] = c["med"]
        install(ai)
        c_arm = {k: cpu_ms(*k) for k in by}
        install(xi)
        c_x86 = {k: cpu_ms(*k) for k in by}
        for k, meas in sorted(by.items()):
            val.append(dict(suite=k[0], depth=k[1], measured_ms=meas, model_x86_ms=c_x86[k], model_x925_ms=c_arm[k],
                            residual_ms=meas - c_x86[k]))
        with open(os.path.join(a.x86_dir, "cpu_validation.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(val[0].keys()))
            w.writeheader()
            for r in val:
                w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in r.items()})
        res = [r["residual_ms"] for r in val]
        nums["cpuValN"] = str(len(val))
        nums["cpuValBias"] = f"{st.mean(res):+.2f}"
        nums["cpuValMae"] = fmt(st.mean(abs(x) for x in res))
        nums["cpuValRelMed"] = f"{100 * st.median(abs(r['residual_ms']) / r['measured_ms'] for r in val):.0f}"
        nums["cpuValResidMax"] = fmt(max(abs(x) for x in res))
        nums["cpuValRatioArm"] = fmt(st.median(r["measured_ms"] / r["model_x925_ms"] for r in val))
    # transport overhead against cryptographic time with the measured x86 costs (the sweep rows carry ser/ssw/pen; cpu depends only
    # on suite, protocol and depth)
    res_path = os.path.join(MEAS, "..", "Simulation", "results", "results.csv")
    if xi and os.path.exists(res_path):
        install(xi)
        cache = {}
        cnt = {}
        for r in csv.DictReader(open(res_path)):
            if r["mode"] != "cold":
                continue
            k = (r["suite"], r["protocol"], int(r["depth"]))
            if k not in cache:
                f = S.build_flow(r["suite"], r["protocol"], k[2], "cold", False)
                cache[k] = sum(s[1] for s in f.steps if s[0] == "cpu")
            c = cnt.setdefault(r["suite"], [0, 0])
            c[1] += 1
            c[0] += (float(r["ser_ms"]) + float(r["ssw_ms"]) + float(r["pen_ms"])) > cache[k]
        for suite, name in ((S.BASELINE, "Ec"), ("ML-DSA-65|ML-KEM-768", "Ml"), ("Falcon-512|ML-KEM-768", "Fal"),
                            ("SLH-DSA-128s|ML-KEM-768", "Slhs"), ("SLH-DSA-128f|ML-KEM-768", "Slhf"), ("RSA-2048|ECDHE-P256", "Rsa")):
            if suite in cnt:
                nums[f"cpuShare{name}"] = f"{100 * cnt[suite][0] / cnt[suite][1]:.0f}"
    install(ai)

    os.makedirs(os.path.join(a.latex, "tables"), exist_ok=True)
    with open(os.path.join(a.latex, "numbers_cpu.tex"), "w") as fh:
        fh.write("% Generated by Measurements/x86/analyze_cpu_x86.py - do not edit\n")
        for k, v in nums.items():
            fh.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    tex = ["\\begin{tabular}{@{}llrrrr@{}}", "\\toprule",
           "Primitive & Operation & X925 (ms) & A725 (ms) & x86 (ms) & x86/X925 \\\\", "\\midrule"]
    for r in rows:
        tex.append(f"{r['primitive']} & {OPNAME.get(r['op'], r['op'])} & {fmt(r['x925_ms'])} & {fmt(r['a725_ms'])} & {fmt(r['x86_ms'])} & "
                   f"{r['x86_over_x925']:.1f} \\\\")
    tex += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(a.latex, "tables", "tab_cpu_x86.tex"), "w").write("\n".join(tex) + "\n")
    print(f"{len(rows)} primitives; x86/X925 median: signatures {nums.get('cpuXSigMed')}, key establishment {nums.get('cpuXKemMed')}; "
          f"A725/X925 median {nums['cpuAArmMed']}")
    if val:
        print(f"validation on {len(val)} unshaped configurations: measured - modelled CPU: bias {nums['cpuValBias']} ms, "
              f"MAE {nums['cpuValMae']} ms (median {nums['cpuValRelMed']} % of the measured time)")


if __name__ == "__main__":
    main()
