#!/usr/bin/env python3
"""
make_assets.py - builds every table, figure and quoted number of the paper straight from the
simulation outputs, so that no number in the manuscript is typed by hand.

    python3 make_assets.py

Inputs : ../Simulation/{results,radio_results,results_thr,sens/*}
Outputs: tables/*.tex, figures/*.pdf, numbers.tex  (\\input by main.tex)
"""
from __future__ import annotations

import csv
import math
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SIM = os.path.join(HERE, "..", "Simulation")   # v4: self-contained (Simulation/run_all.sh)
sys.path.insert(0, SIM)
import pqc_sim as S          # noqa: E402
import radio_sim as RS       # noqa: E402

import matplotlib            # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt   # noqa: E402
from matplotlib.colors import TwoSlopeNorm, LinearSegmentedColormap   # noqa: E402

os.makedirs(os.path.join(HERE, "tables"), exist_ok=True)
os.makedirs(os.path.join(HERE, "figures"), exist_ok=True)

# ------------------------------------------------------------------ style (validated palette, fixed order)
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#dcdbd6"
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MARK = ["o", "s", "^", "D", "v", "P"]
LSTY = ["-", "--", "-.", ":", (0, (5, 1)), (0, (3, 1, 1, 1))]
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 8, "axes.titlesize": 8.5,
    "axes.labelsize": 8, "legend.fontsize": 7, "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "text.color": INK, "xtick.color": INK2,
    "ytick.color": INK2, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.spines.top": False,
    "axes.spines.right": False, "lines.linewidth": 1.4, "lines.markersize": 4, "pdf.fonttype": 42,
})

BASE = S.BASELINE
ml = "ML-DSA-65|ML-KEM-768"
SHOW = [BASE, "RSA-2048|ECDHE-P256", "ECDSA-P256|X25519MLKEM768", "ML-DSA-65|ML-KEM-768",
        "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]
ALL = list(S.SUITES)
PROTOS = list(S.PROTOCOLS)
PNAME = {"ISO_8583": "ISO 8583", "ISO_20022": "ISO 20022", "SWIFT_MX": "SWIFT MX",
         "OAUTH2_RFC6749": "OAuth 2.0", "OIDC": "OIDC", "FAPI2": "FAPI 2.0"}
PDEPTH = {p: S.PROTOCOLS[p].default_depth for p in PROTOS}


def short(s):                      # "ML-DSA-65|ML-KEM-768" -> "ML-DSA-65 / ML-KEM-768"
    return s.replace("|", " / ")


def sig_only(s):
    return {"ECDSA-P256|X25519": "ECDSA-P256 (baseline)", "ECDSA-P256|X25519MLKEM768": "ECDSA-P256 + hybrid KEM",
            "RSA-2048|ECDHE-P256": "RSA-2048", "RSA-3072|ECDHE-P256": "RSA-3072"}.get(s, s.split("|")[0])


NUMS = {}


import re   # noqa: E402
DIGW = dict(zip("0123456789", ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"]))


def num(name, val):
    NUMS[re.sub(r"\d", lambda m: DIGW[m.group()], name)] = val


def write(name, text):
    with open(os.path.join(HERE, "tables", name), "w") as fh:
        fh.write(text)


def load(path, floats=()):
    rows = list(csv.DictReader(open(path, newline="")))
    for r in rows:
        for k in floats:
            if k in r and r[k] != "":
                r[k] = float(r[k])
    return rows


# ------------------------------------------------------------------ load
WF = ["depth", "bw_mbps", "rtt_ms", "mtu", "penalty_ms", "thr", "total_ms", "cpu_ms", "ser_ms", "prop_ms",
      "ssw_ms", "pen_ms", "segs", "max_flight", "pen_flights", "l7_bytes", "tls_cert_bytes", "obj_alg_bytes",
      "cc_total_ms", "cc_saved_ms", "cc_cert_bytes", "decomp_kb_cli", "break_even_ms_per_kb"] + \
     [f"cc_net_{k}" for k in S.DECOMP_PROFILES]
R = load(os.path.join(SIM, "results", "results.csv"), WF)
SZ = load(os.path.join(SIM, "results", "sizes.csv"))
COLD = [r for r in R if r["mode"] == "cold"]
idx = {(r["suite"], r["protocol"], r["mode"], int(r["depth"]), r["bw_mbps"], r["rtt_ms"], int(r["mtu"]),
        r["penalty_ms"], int(r["thr"])): r for r in R}
szi = {(r["suite"], r["protocol"], int(r["depth"]), int(r["cc"])): r for r in SZ}
REF = dict(bw=100.0, rtt=30.0, mtu=1500, pen=0.0)    # no middlebox penalty: measured for an L4 proxy (testbed)


def at(s, p, d, bw=100.0, rtt=30.0, mtu=1500, pen=0.0, mode="cold", thr=4):
    return idx[(s, p, mode, 0 if mode == "warm" else d, float(bw), float(rtt), int(mtu), float(pen), thr)]


RF = ["sinr_db", "depth", "wired_rtt_ms", "mtu", "trials", "mean_ms", "std_ms", "p50_ms", "p95_ms", "p99_ms",
      "max_ms", "miss_200ms", "miss_500ms", "miss_1000ms", "retx_per_tb", "rlc_per_flow", "loss_per_flow",
      "dl_mbps", "ul_mbps", "cpu_ms", "l7_bytes", "segs"]
RR = load(os.path.join(SIM, "radio_results", "radio_results.csv"), RF)
RL = load(os.path.join(SIM, "radio_results", "radio_links.csv"),
          ["sinr_db", "dl_mbps", "ul_mbps", "bler_first_tx", "tx_per_tb", "harq_fail", "blockage", "ran_rtt_floor_ms"])
PROFS = list(dict.fromkeys(r["profile"] for r in RL))
SINRS = sorted({r["sinr_db"] for r in RL}, reverse=True)
ridx = {(r["profile"], r["sinr_db"], r["suite"], r["protocol"], r["mode"]): r for r in RR}
lidx = {(r["profile"], r["sinr_db"]): r for r in RL}
TRIALS = int(RR[0]["trials"])
PSH = {"5G-NR sub-6 (eMBB)": "5G sub-6", "5G-NR URLLC": "5G URLLC", "5G-NR mmWave (FR2)": "5G mmWave",
       "6G upper mid-band (FR3, assumed)": "6G mid-band$^\\ast$", "6G sub-THz (assumed)": "6G sub-THz$^\\ast$"}
PSH_PLAIN = {k: v.replace("$^\\ast$", "*") for k, v in PSH.items()}


def rat(p, s, su, pr="FAPI2", mode="cold"):
    return ridx[(p, s, su, pr, mode)]


# ================================================================== NUMBERS
num("nConfigs", f"{len(R):,}".replace(",", "{,}"))
num("nCold", f"{len(COLD):,}".replace(",", "{,}"))
num("nRadioRows", f"{len(RR):,}".replace(",", "{,}"))
num("nRadioTx", f"{len(RR) * TRIALS:,}".replace(",", "{,}"))
num("nTrials", f"{TRIALS:,}".replace(",", "{,}"))

# RQ1
def l7(s, p, d=None, cc=0):
    return int(szi[(s, p, d or PDEPTH[p], cc)]["total_l7"])


for key, su in (("MLDSAsixtyfive", "ML-DSA-65|ML-KEM-768"), ("MLDSAfortyfour", "ML-DSA-44|ML-KEM-768"),
                ("MLDSAeightyseven", "ML-DSA-87|ML-KEM-1024"), ("FalconFiveTwelve", "Falcon-512|ML-KEM-768"),
                ("FalconTenTwentyFour", "Falcon-1024|ML-KEM-1024"), ("SLHs", "SLH-DSA-128s|ML-KEM-768"),
                ("SLHf", "SLH-DSA-128f|ML-KEM-768"), ("Hybrid", "ECDSA-P256|X25519MLKEM768"),
                ("RSAtwo", "RSA-2048|ECDHE-P256")):
    b = l7(BASE, "SWIFT_MX")
    num(f"swiftKB{key}", f"{l7(su, 'SWIFT_MX') / 1024:.1f}")
    num(f"swiftX{key}", f"{l7(su, 'SWIFT_MX') / b:.1f}")
num("swiftKBbase", f"{l7(BASE, 'SWIFT_MX') / 1024:.1f}")
for p in PROTOS:
    for key, su in (("MLDSAsixtyfive", "ML-DSA-65|ML-KEM-768"), ("FalconFiveTwelve", "Falcon-512|ML-KEM-768")):
        num(f"x{p.replace('_', '')}{key}", f"{l7(su, p) / l7(BASE, p):.1f}")
sw = szi[("ML-DSA-65|ML-KEM-768", "SWIFT_MX", 3, 0)]
tot = int(sw["total_l7"])
num("swiftMLcertShare", f"{100 * int(sw['tls_cert']) / tot:.0f}")
num("swiftMLappShare", f"{100 * int(sw['obj_alg']) / tot:.0f}")
num("swiftMLcvShare", f"{100 * int(sw['tls_cv']) / tot:.0f}")
num("swiftMLfixedShare", f"{100 * int(sw['payload_fixed']) / tot:.0f}")
w65 = at("ML-DSA-65|ML-KEM-768", "ISO_8583", 0, mode="warm")
for tag, p in (("IsoTwoZeroTwoTwo", "ISO_20022"), ("FAPITwo", "FAPI2")):
    num(f"warmX{tag}", f"{at(ml, p, 0, mode='warm')['l7_bytes'] / at(BASE, p, 0, mode='warm')['l7_bytes']:.1f}")

num("hybridDeltaMs", f"{at('ECDSA-P256|X25519MLKEM768', 'SWIFT_MX', 3)['total_ms'] - at(BASE, 'SWIFT_MX', 3)['total_ms']:.1f}")
num("hybridDeltaKB", f"{(l7('ECDSA-P256|X25519MLKEM768', 'SWIFT_MX') - l7(BASE, 'SWIFT_MX')) / 1024:.1f}")
num("baseSwiftMs", f"{at(BASE, 'SWIFT_MX', 3)['total_ms']:.1f}")
num("mlSwiftMs", f"{at('ML-DSA-65|ML-KEM-768', 'SWIFT_MX', 3)['total_ms']:.1f}")
num("falSwiftMs", f"{at('Falcon-512|ML-KEM-768', 'SWIFT_MX', 3)['total_ms']:.1f}")
num("slhsSwiftMs", f"{at('SLH-DSA-128s|ML-KEM-768', 'SWIFT_MX', 3)['total_ms']:.0f}")
num("slhfSwiftMs", f"{at('SLH-DSA-128f|ML-KEM-768', 'SWIFT_MX', 3)['total_ms']:.0f}")

# RQ2
def dd(s, c, p="SWIFT_MX", **kw):
    return at(s, p, 4, **kw)[c] - at(s, p, 1, **kw)[c]


ml = "ML-DSA-65|ML-KEM-768"
num("mlDepthDelta", f"{dd(ml, 'total_ms'):.1f}")
num("mlDepthSsw", f"{dd(ml, 'ssw_ms'):.1f}")
num("mlDepthSer", f"{dd(ml, 'ser_ms'):.1f}")
num("mlDepthCpu", f"{dd(ml, 'cpu_ms'):.1f}")
num("ecDepthDelta", f"{dd(BASE, 'total_ms'):.1f}")
num("rsaDepthDelta", f"{dd('RSA-2048|ECDHE-P256', 'total_ms'):.1f}")
num("falDepthDelta", f"{dd('Falcon-512|ML-KEM-768', 'total_ms'):.1f}")
num("falDepthPen", f"{dd('Falcon-512|ML-KEM-768', 'pen_ms'):.0f}")
for mtu in (1280, 1500, 9000):
    num(f"perCert{mtu}p0", f"{dd(ml, 'total_ms', mtu=mtu, pen=0.0) / 3:.1f}")
    num(f"perCert{mtu}p24", f"{dd(ml, 'total_ms', mtu=mtu, pen=24.0) / 3:.1f}")
for rtt in (5.0, 100.0):
    num(f"perCertRtt{int(rtt)}", f"{dd(ml, 'total_ms', rtt=rtt) / 3:.1f}")
num("mlSswFirstDepth", "1")

# RQ3
def share(su, k, which=COLD):
    sub = [r for r in which if r["suite"] == su]
    return sum((r["ser_ms"] + r["ssw_ms"] + r["pen_ms"]) > k * r["cpu_ms"] for r in sub) / len(sub)


for key, su in (("ML", ml), ("Fal", "Falcon-512|ML-KEM-768"), ("SLHs", "SLH-DSA-128s|ML-KEM-768"),
                ("SLHf", "SLH-DSA-128f|ML-KEM-768"), ("EC", BASE), ("RSA", "RSA-2048|ECDHE-P256")):
    for k in (1, 4, 16):
        num(f"share{key}x{k}", f"{100 * share(su, k):.0f}")
def ratio(su, bw):
    r = at(su, "SWIFT_MX", 3, bw=bw)
    return (r["ser_ms"] + r["ssw_ms"] + r["pen_ms"]) / r["cpu_ms"]


num("ratioMLhundred", f"{ratio(ml, 100.0):.0f}")
num("ratioECHundred", f"{ratio(BASE, 100.0):.1f}")
num("ratioSLHsHundred", f"{ratio('SLH-DSA-128s|ML-KEM-768', 100.0):.1f}")
num("slhsCpuMs", f"{at('SLH-DSA-128s|ML-KEM-768', 'SWIFT_MX', 3)['cpu_ms']:.0f}")
num("mlCpuMs", f"{at(ml, 'SWIFT_MX', 3)['cpu_ms']:.1f}")
num("ecCpuMs", f"{at(BASE, 'SWIFT_MX', 3)['cpu_ms']:.1f}")

# RQ4
def red(su):
    sub = [r for r in COLD if r["suite"] == su and r["tls_cert_bytes"]]
    return 100 * st.mean(1 - r["cc_cert_bytes"] / r["tls_cert_bytes"] for r in sub)


num("ccRedEC", f"{red(BASE):.0f}")
num("ccRedRSA", f"{red('RSA-2048|ECDHE-P256'):.0f}")
num("ccRedML", f"{red(ml):.0f}")
num("ccRedSLHf", f"{red('SLH-DSA-128f|ML-KEM-768'):.0f}")
num("ccRedFal", f"{red('Falcon-512|ML-KEM-768'):.0f}")
def maxrtt(su):
    return max(r["cc_saved_ms"] / r["rtt_ms"] for r in COLD if r["suite"] == su)


num("ccMaxRttML", f"{maxrtt(ml):.2f}")
def harm(su, prof):
    sub = [r for r in COLD if r["suite"] == su]
    return 100 * sum(r[f"cc_net_{prof}"] <= -1 for r in sub) / len(sub)


for key, su in (("ML", ml), ("EC", BASE), ("RSA", "RSA-2048|ECDHE-P256"), ("SLHf", "SLH-DSA-128f|ML-KEM-768")):
    num(f"harmEmb{key}", f"{harm(su, 'embedded'):.0f}")
    num(f"harmSrv{key}", f"{harm(su, 'server-class'):.0f}")
def be(su):
    v = sorted(r["break_even_ms_per_kb"] for r in COLD if r["suite"] == su and r["cc_saved_ms"] >= 1.0
               and r["break_even_ms_per_kb"] is not None)
    return st.median(v)


num("beML", f"{be(ml):.2f}")
num("beRSA", f"{be('RSA-2048|ECDHE-P256'):.2f}")
num("beSLHf", f"{be('SLH-DSA-128f|ML-KEM-768'):.2f}")
lo = min(sum(r["cc_saved_ms"] >= 1 for r in COLD if r["suite"] == s) / sum(1 for r in COLD if r["suite"] == s) for s in ALL)
hi = max(sum(r["cc_saved_ms"] >= 1 for r in COLD if r["suite"] == s) / sum(1 for r in COLD if r["suite"] == s) for s in ALL)
num("ccMatLo", f"{100 * lo:.0f}")
num("ccMatHi", f"{100 * hi:.0f}")

# warm
num("warmMLiso20022", f"{at(ml, 'ISO_20022', 0, mode='warm')['total_ms'] - at(BASE, 'ISO_20022', 0, mode='warm')['total_ms']:.0f}")
num("warmMLiso8583", f"{at(ml, 'ISO_8583', 0, mode='warm')['total_ms'] - at(BASE, 'ISO_8583', 0, mode='warm')['total_ms']:.1f}")

# DES cross-check (full grid; cached in des_check.json - delete the file to re-measure)
import json   # noqa: E402
DES_CACHE = os.path.join(HERE, "des_check.json")
if os.path.exists(DES_CACHE):
    des = json.load(open(DES_CACHE))
else:
    import crosscheck_simpy as X
    cases = list(X.all_cases((10.0, 100.0, 200.0, 400.0, 800.0, 1600.0), (5.0, 12.0, 30.0, 50.0, 100.0),
                             (1280, 1500, 9000), (0.0, 24.0), (4,)))
    des = dict(flows=len(cases), max_diff=max(abs(X.compare(c, 1)["d_total"]) for c in cases))
    json.dump(des, open(DES_CACHE, "w"))
man, ex = f"{max(des['max_diff'], 1e-15):.1e}".split("e")
num("desFlows", f"{des['flows']:,}".replace(",", "{,}"))
num("desMaxDiff", f"{man}\\times10^{{{int(ex)}}}")

# Radio
def rf(p, s, su, pr="FAPI2"):
    return rat(p, s, su, pr)["mean_ms"] / rat(p, s, BASE, pr)["mean_ms"]


s6, u6 = "5G-NR sub-6 (eMBB)", "5G-NR URLLC"
f3, t6 = "6G upper mid-band (FR3, assumed)", "6G sub-THz (assumed)"
mm = "5G-NR mmWave (FR2)"
for tag, p in (("Six", s6), ("Urllc", u6), ("Mm", mm), ("Fr", f3), ("Thz", t6)):
    num(f"rf{tag}hi", f"{rf(p, 30.0, ml):.2f}")
    num(f"rf{tag}lo", f"{rf(p, -5.0, ml):.2f}")
    num(f"rf{tag}zero", f"{rf(p, 0.0, ml):.2f}")
num("rfSixFalLo", f"{rf(s6, -5.0, 'Falcon-512|ML-KEM-768'):.2f}")
num("rfSixHybLo", f"{rf(s6, -5.0, 'ECDSA-P256|X25519MLKEM768'):.2f}")
num("rfSixHybHi", f"{rf(s6, 30.0, 'ECDSA-P256|X25519MLKEM768'):.2f}")
num("rfSixSlhfLo", f"{rf(s6, -5.0, 'SLH-DSA-128f|ML-KEM-768'):.1f}")
num("rfSixSlhfHi", f"{rf(s6, 30.0, 'SLH-DSA-128f|ML-KEM-768'):.1f}")
num("baseSixHi", f"{rat(s6, 30.0, BASE)['mean_ms']:.0f}")
num("mlSixHi", f"{rat(s6, 30.0, ml)['mean_ms']:.0f}")
num("baseSixLo", f"{rat(s6, -5.0, BASE)['mean_ms']:.0f}")
num("mlSixLo", f"{rat(s6, -5.0, ml)['mean_ms']:.0f}")
num("dlSixHi", f"{lidx[(s6, 30.0)]['dl_mbps']:.0f}")
num("dlSixLo", f"{lidx[(s6, -5.0)]['dl_mbps']:.1f}")
num("dlThzHi", f"{lidx[(t6, 30.0)]['dl_mbps'] / 1000:.1f}")
num("dlFrHi", f"{lidx[(f3, 30.0)]['dl_mbps'] / 1000:.1f}")
num("dlUrHi", f"{lidx[(u6, 30.0)]['dl_mbps']:.0f}")
num("blerSixLo", f"{100 * lidx[(s6, -5.0)]['bler_first_tx']:.0f}")
num("blerSixHi", f"{100 * lidx[(s6, 20.0)]['bler_first_tx']:.0f}")
num("urllcBler", f"{100 * lidx[(u6, 10.0)]['bler_first_tx']:.2f}")
mlr = rat(s6, -5.0, ml)
num("rlcSixLo", f"{mlr['rlc_per_flow']:.1f}")
num("retxSixLo", f"{mlr['retx_per_tb']:.2f}")
num("rlcMmLo", f"{rat(mm, -5.0, ml)['rlc_per_flow']:.0f}")
num("lossThzLo", f"{rat(t6, -5.0, ml)['loss_per_flow']:.2f}")
num("p99MmBase", f"{rat(mm, 30.0, BASE)['p99_ms']:.0f}")
num("meanMmBase", f"{rat(mm, 30.0, BASE)['mean_ms']:.0f}")
se = sorted(r["std_ms"] / r["trials"] ** 0.5 for r in RR)
num("seMedian", f"{se[len(se) // 2]:.1f}")
num("seMax", f"{se[-1]:.0f}")
w6 = rat(s6, 30.0, ml, "FAPI2", "warm")["mean_ms"] / rat(s6, 30.0, BASE, "FAPI2", "warm")["mean_ms"]
num("warmSixHi", f"{w6:.2f}")
w6l = rat(s6, -5.0, ml, "FAPI2", "warm")["mean_ms"] / rat(s6, -5.0, BASE, "FAPI2", "warm")["mean_ms"]
num("warmSixLo", f"{w6l:.2f}")

# SLA (continuous from 30 dB downwards)
def sla(p, su, thr):
    ok = []
    for s in SINRS:
        if rat(p, s, su)["p99_ms"] > thr:
            break
        ok.append(s)
    return "--" if not ok else f"{min(ok):g}"


num("slaBaseSix", sla(s6, BASE, 500.0))
num("slaMLSix", sla(s6, ml, 500.0))
num("slaMLUrllc", sla(u6, ml, 500.0))
num("slaFalSix", sla("5G-NR sub-6 (eMBB)", "Falcon-512|ML-KEM-768", 500.0))
num("slaSlhfSix", sla(s6, "SLH-DSA-128f|ML-KEM-768", 500.0))
num("slaMLFr", sla(f3, ml, 500.0))

# ================================================================== SENSITIVITY (read other runs)
def sens_row(d, su):
    rows = load(os.path.join(SIM, "sens", d, "results.csv"), WF) if d != "base" else R
    def eq(x, y):
        try:
            return float(x) == float(y)
        except (TypeError, ValueError):
            return str(x) == str(y)

    k = lambda **kw: [r for r in rows if r["suite"] == su and all(eq(r[a], b) for a, b in kw.items())][0]
    ref = dict(bw_mbps=100.0, rtt_ms=30.0, mtu=1500, penalty_ms=0.0, thr=4)
    r3 = k(protocol="SWIFT_MX", mode="cold", depth=3, **ref)
    r1 = k(protocol="SWIFT_MX", mode="cold", depth=1, **ref)
    r4 = k(protocol="SWIFT_MX", mode="cold", depth=4, **ref)
    w = k(protocol="ISO_20022", mode="warm", depth=0, **ref)
    return r3["l7_bytes"] / 1024, r3["total_ms"], r4["total_ms"] - r1["total_ms"], w["total_ms"]


sens_cases = [("base", "Reference model"), ("nocert", "XMLDSig without embedded certificate"),
              ("meta_small", "Smaller certificates (leaf 600 B, CA 350 B)"),
              ("meta_large", "Larger certificates (leaf 1400 B, CA 800 B)"),
              ("cwnd_busy", "Busy reused connection ($cwnd=64$)")]
sens_suites = [BASE, ml, "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]
# simplified second layout: one row per variant, columns per metric for 4 suites
lines = [r"\begin{tabular}{@{}lrrrrrrrr@{}}", r"\toprule",
         r"Variant & \multicolumn{4}{c}{$\Delta_{d1\to d4}$ for SWIFT MX (ms)} & \multicolumn{4}{c}{Warm ISO 20022 latency (ms)} \\",
         r"\cmidrule(lr){2-5}\cmidrule(lr){6-9}",
         r" & ECDSA & ML-DSA-65 & Falcon-512 & SLH-f & ECDSA & ML-DSA-65 & Falcon-512 & SLH-f \\", r"\midrule"]
for d, label in sens_cases:
    vals = [sens_row(d, su) for su in sens_suites]
    lines.append(label + " & " + " & ".join(f"{v[2]:.1f}" for v in vals) + " & " + " & ".join(f"{v[3]:.1f}" for v in vals) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_sens.tex", "\n".join(lines) + "\n")
lines = [r"\begin{tabular}{@{}lrrrrrrrr@{}}", r"\toprule",
         r"Variant & \multicolumn{4}{c}{SWIFT MX $d{=}3$ size (KB)} & \multicolumn{4}{c}{SWIFT MX $d{=}3$ latency (ms)} \\",
         r"\cmidrule(lr){2-5}\cmidrule(lr){6-9}",
         r" & ECDSA & ML-DSA-65 & Falcon-512 & SLH-f & ECDSA & ML-DSA-65 & Falcon-512 & SLH-f \\", r"\midrule"]
for d, label in sens_cases[:4]:
    vals = [sens_row(d, su) for su in sens_suites]
    lines.append(label + " & " + " & ".join(f"{v[0]:.1f}" for v in vals) + " & " + " & ".join(f"{v[1]:.1f}" for v in vals) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_sens2.tex", "\n".join(lines) + "\n")
nc = sens_row("nocert", ml)
num("nocertMLKB", f"{nc[0]:.1f}")
num("nocertWarmML", f"{nc[3]:.0f}")
nb = sens_row("cwnd_busy", ml)
num("busyWarmML", f"{nb[3]:.0f}")
num("busyWarmBase", f"{sens_row('cwnd_busy', BASE)[3]:.0f}")
num("idleWarmML", f"{sens_row('base', ml)[3]:.0f}")
ml_lg = sens_row("meta_large", BASE)
num("metaLargeECDelta", f"{ml_lg[2]:.0f}")

# radio sensitivity: wired RTT
rw = load(os.path.join(SIM, "sens", "radio_wired", "radio_results.csv"), RF)
def rw_f(p, s, w, su):
    g = lambda x: [r["mean_ms"] for r in rw if r["profile"] == p and r["sinr_db"] == s and r["suite"] == x
                   and r["wired_rtt_ms"] == w][0]
    return g(su) / g(BASE), g(BASE)


lines = [r"\begin{tabular}{@{}llrrr@{}}", r"\toprule", r"Profile & SINR & RTT$_\text{wired}$ 5\,ms & 20\,ms & 60\,ms \\", r"\midrule"]
for p in (s6, f3):
    for s in (30.0, 0.0, -5.0):
        cells = []
        for w in (5.0, 20.0, 60.0):
            f, b = rw_f(p, s, w, ml)
            cells.append(f"{f:.2f}$\\times$ ({b:.0f})")
        lines.append(f"{PSH[p]} & ${s:g}$\\,dB & " + " & ".join(cells) + r" \\")
    lines.append(r"\midrule" if p == s6 else "")
lines = [l for l in lines if l] + [r"\bottomrule", r"\end{tabular}"]
write("tab_radio_wired.tex", "\n".join(lines) + "\n")
f5, b5 = rw_f(s6, 0.0, 5.0, ml)
f60, b60 = rw_f(s6, 0.0, 60.0, ml)
num("wiredFiveSix0", f"{f5:.2f}")
num("wiredSixtySix0", f"{f60:.2f}")


# radio: depth sensitivity (5G sub-6, FAPI 2.0)
rd = load(os.path.join(SIM, "sens", "radio_depth", "radio_results.csv"), RF)
def rd_f(pr, sinr, d, su=ml):
    g = lambda x: [r["mean_ms"] for r in rd if r["protocol"] == pr and r["sinr_db"] == sinr and r["suite"] == x and r["depth"] == d][0]
    return g(su) / g(BASE)


for sinr, tag in ((30.0, "Hi"), (0.0, "Zero")):
    num(f"radDepthOne{tag}", f"{rd_f('FAPI2', sinr, 1.0):.2f}")
    num(f"radDepthFour{tag}", f"{rd_f('FAPI2', sinr, 4.0):.2f}")


# initcwnd sensitivity and the hybrid-KEM knee
c32 = load(os.path.join(SIM, "sens", "cwnd32", "results.csv"), WF)
def c32_row(su, d, mtu=1500):
    return [r for r in c32 if r["suite"] == su and r["protocol"] == "SWIFT_MX" and r["mode"] == "cold" and int(r["depth"]) == d
            and r["bw_mbps"] == 100.0 and r["rtt_ms"] == 30.0 and int(r["mtu"]) == mtu and r["penalty_ms"] == 0.0 and int(r["thr"]) == 4][0]


num("icwThirtyTwoMLDelta", f"{c32_row(ml, 4)['total_ms'] - c32_row(ml, 1)['total_ms']:.1f}")
num("icwThirtyTwoMLd1", f"{c32_row(ml, 1)['total_ms']:.1f}")
num("icwThirtyTwoECd1", f"{c32_row(BASE, 1)['total_ms']:.1f}")
num("icwTenMLd1", f"{at(ml, 'SWIFT_MX', 1)['total_ms']:.1f}")
num("icwTenECd1", f"{at(BASE, 'SWIFT_MX', 1)['total_ms']:.1f}")
num("hybKneeBase", f"{at(BASE, 'SWIFT_MX', 1, mtu=1280)['total_ms']:.0f}")
num("hybKneeHyb", f"{at('ECDSA-P256|X25519MLKEM768', 'SWIFT_MX', 1, mtu=1280)['total_ms']:.0f}")

# ================================================================== TABLES
# Table 1: algorithms
lines = [r"\begin{tabular}{@{}llrrrrrr@{}}", r"\toprule",
         r"Signature & Family & PK & SPKI & Sig. & Sign & Verify & Pair \\",
         r" & & (B) & (B) & (B) & (ms) & (ms) & KEM \\", r"\midrule"]
pair = {"RSA-2048": "ECDHE-P256", "RSA-3072": "ECDHE-P256", "ECDSA-P256": "X25519 / hybrid", "ML-DSA-44": "ML-KEM-768",
        "ML-DSA-65": "ML-KEM-768", "ML-DSA-87": "ML-KEM-1024", "Falcon-512": "ML-KEM-768",
        "Falcon-1024": "ML-KEM-1024", "SLH-DSA-128s": "ML-KEM-768", "SLH-DSA-128f": "ML-KEM-768",
        "ML-DSA-44+ECDSA-P256": "X25519MLKEM768", "ML-DSA-65+ECDSA-P256": "X25519MLKEM768"}
for n, s in S.SIGS.items():
    lines.append(f"{n} & {s.family} & {s.pk:,} & {s.pk + s.spki_hdr:,} & {s.sig:,} & {s.sign_ms:g} & {s.verify_ms:g} & {pair[n]} \\\\"
                 .replace(",", "{,}"))
lines += [r"\midrule", r"\multicolumn{8}{l}{\textit{Key establishment: key-share bytes; last two columns = client / server computation (ms)}} \\"]
for n, k in S.KEXS.items():
    lines.append(f"\\quad {n} & {'post-quantum' if k.family == 'pqc' else k.family} & \\multicolumn{{2}}{{r}}{{client {k.client_share:,}}} & \\multicolumn{{2}}{{r}}{{server {k.server_share:,}}} & "
                 f"{k.gen_ms + k.derive_ms:.4g} & {k.server_ms:.4g} \\\\".replace(",", "{,}"))
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_algos.tex", "\n".join(lines) + "\n")

# Table 2: protocols
lines = [r"\begin{tabular}{@{}lllrrrr@{}}", r"\toprule",
         r"Profile & Message types & Security objects (signer) & Exch. & Req./resp. (B)$^{a}$ & mTLS & $d_\text{ref}$ \\", r"\midrule"]
objs = {"ISO_8583": "none (symmetric MAC)", "ISO_20022": "XMLDSig on BAH (client, server)",
        "SWIFT_MX": "XMLDSig / LAU (client, server)", "OAUTH2_RFC6749": "client assertion, access token, Bearer",
        "OIDC": "client assertion, ID/access token, JWK", "FAPI2": "JAR, DPoP$\\times$2, tokens, signed response"}
msgs = {"ISO_8583": "0200/0210", "ISO_20022": "pacs.008 / pacs.002", "SWIFT_MX": "cross-border pacs.008",
        "OAUTH2_RFC6749": "RFC 6749 token + RFC 6750 call", "OIDC": "token, JWKS, userinfo",
        "FAPI2": "PAR, token, resource"}
for p in PROTOS:
    pr = S.PROTOCOLS[p]
    rq = sum(e.req for e in pr.exchanges)
    rs = sum(e.resp for e in pr.exchanges)
    lines.append(f"{PNAME[p]} & {msgs[p]} & {objs[p]} & {len(pr.exchanges)} & {rq:,}/{rs:,} & {'yes' if pr.mtls else 'no'} & {pr.default_depth} \\\\".replace(",", "{,}"))
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_protocols.tex", "\n".join(lines) + "\n")

# Table RQ1 sizes
lines = [r"\begin{tabular}{@{}l" + "r" * len(PROTOS) + r"@{}}", r"\toprule",
         "Suite & " + " & ".join(f"{PNAME[p]} ($d{{=}}{PDEPTH[p]}$)" for p in PROTOS) + r" \\", r"\midrule"]
for su in ALL:
    cells = []
    for p in PROTOS:
        t = l7(su, p)
        cells.append(f"{t / 1024:.1f} ({t / l7(BASE, p):.1f}$\\times$)")
    lines.append(sig_only(su) + (" / " + su.split("|")[1] if su.split("|")[1] not in ("X25519", "ECDHE-P256") and "ECDSA" not in su else "") + " & " + " & ".join(cells) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_sizes.tex", "\n".join(lines) + "\n")

# Table depth
lines = [r"\begin{tabular}{@{}lrrrrrrrrr@{}}", r"\toprule",
         r"Suite & \multicolumn{4}{c}{Latency (ms) at depth} & \multicolumn{2}{c}{Largest flight (seg.)} & \multicolumn{3}{c}{$\Delta_{d1\to d4}$ components (ms)} \\",
         r"\cmidrule(lr){2-5}\cmidrule(lr){6-7}\cmidrule(lr){8-10}",
         r" & 1 & 2 & 3 & 4 & $d{=}1$ & $d{=}4$ & ser. & wait & pen. \\", r"\midrule"]
for su in ALL:
    la = [at(su, "SWIFT_MX", d) for d in (1, 2, 3, 4)]
    lines.append(f"{sig_only(su)} & " + " & ".join(f"{x['total_ms']:.1f}" for x in la) +
                 f" & {int(la[0]['max_flight'])} & {int(la[3]['max_flight'])} & {la[3]['ser_ms'] - la[0]['ser_ms']:.1f} & "
                 f"{la[3]['ssw_ms'] - la[0]['ssw_ms']:.1f} & {la[3]['pen_ms'] - la[0]['pen_ms']:.0f} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_depth.tex", "\n".join(lines) + "\n")

# Table interaction
pens = (0.0, 3.0, 6.0, 12.0, 24.0)
rtts = (5.0, 12.0, 30.0, 50.0, 100.0)
lines = [r"\begin{tabular}{@{}lrrrrr@{\hspace{14pt}}rrrrr@{}}", r"\toprule",
         r"& \multicolumn{5}{c}{(a) transport penalty (ms)} & \multicolumn{5}{c}{(b) RTT (ms)} \\",
         r"\cmidrule(r){2-6}\cmidrule(l){7-11}",
         r"MTU & " + " & ".join(f"{p:g}" for p in pens) + " & " + " & ".join(f"{r:g}" for r in rtts) + r" \\", r"\midrule"]
for mtu in (1280, 1500, 9000):
    a = [dd(ml, "total_ms", mtu=mtu, pen=p) / 3 for p in pens]
    b = [dd(ml, "total_ms", mtu=mtu, rtt=r) / 3 for r in rtts]
    lines.append(f"{mtu} & " + " & ".join(f"{x:.1f}" for x in a) + " & " + " & ".join(f"{x:.1f}" for x in b) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_interaction.tex", "\n".join(lines) + "\n")

# Table threshold
THR = load(os.path.join(SIM, "results_thr", "results.csv"), WF)
ti = {(int(r["depth"]), int(r["mtu"]), int(r["thr"])): r["total_ms"] for r in THR if r["mode"] == "cold"}
thrs = sorted({int(r["thr"]) for r in THR})
lines = [r"\begin{tabular}{@{}rr" + "r" * len(thrs) + r"@{}}", r"\toprule",
         r"MTU & $d$ & " + " & ".join(f"$\\theta{{=}}{t}$" for t in thrs) + r" \\", r"\midrule"]
for mtu in (1280, 1500, 9000):
    for d in (1, 2, 3, 4):
        lines.append(f"{mtu if d == 1 else ''} & {d} & " + " & ".join(f"{ti[(d, mtu, t)]:.1f}" for t in thrs) + r" \\")
    if mtu != 9000:
        lines.append(r"\addlinespace")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_threshold.tex", "\n".join(lines) + "\n")

# Table RQ3 shares
lines = [r"\begin{tabular}{@{}lrrrrr@{}}", r"\toprule",
         r"Suite & \multicolumn{3}{c}{Overhead $>$ crypto (\% of configs)} & Median overhead/crypto & Added overhead $>$ added crypto \\",
         r"\cmidrule(lr){2-4}", r" & CPU $\times1$ & $\times4$ & $\times16$ & ($\times1$) & vs.\ baseline, $\times1$ (\%) \\", r"\midrule"]
for su in ALL:
    sub = [r for r in COLD if r["suite"] == su]
    med = st.median((r["ser_ms"] + r["ssw_ms"] + r["pen_ms"]) / r["cpu_ms"] for r in sub)
    if su == BASE:
        inc = "--"
    else:
        n = w = 0
        for r in sub:
            b = idx[(BASE, r["protocol"], "cold", int(r["depth"]), r["bw_mbps"], r["rtt_ms"], int(r["mtu"]), r["penalty_ms"], int(r["thr"]))]
            n += 1
            w += ((r["ser_ms"] + r["ssw_ms"] + r["pen_ms"]) - (b["ser_ms"] + b["ssw_ms"] + b["pen_ms"])) > (r["cpu_ms"] - b["cpu_ms"])
        inc = f"{100 * w / n:.0f}"
    lines.append(f"{sig_only(su)} & " + " & ".join(f"{100 * share(su, k):.0f}" for k in (1, 4, 16)) + f" & {med:.1f} & {inc} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_rq3.tex", "\n".join(lines) + "\n")

# Table RQ4
lines = [r"\begin{tabular}{@{}lrrrrrrrr@{}}", r"\toprule",
         r"Suite & Cert.\ bytes & Material & Max saved & \multicolumn{4}{c}{Net-harmful configs (\%) by client inflate speed} & Break-even \\",
         r"\cmidrule(lr){5-8}",
         r" & saved (\%) & gain (\%) & (RTTs) & 330 MB/s & 33 MB/s & 3.3 MB/s & 0.33 MB/s & (ms/KB) \\", r"\midrule"]
for su in ALL:
    sub = [r for r in COLD if r["suite"] == su]
    mat = 100 * sum(r["cc_saved_ms"] >= 1 for r in sub) / len(sub)
    hv = [100 * sum(r[f"cc_net_{pr}"] <= -1 for r in sub) / len(sub) for pr in S.DECOMP_PROFILES]
    lines.append(f"{sig_only(su)} & {red(su):.0f} & {mat:.0f} & {maxrtt(su):.2f} & " + " & ".join(f"{h:.0f}" for h in hv) + f" & {be(su):.2f} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_rq4.tex", "\n".join(lines) + "\n")

# Table warm
lines = [r"\begin{tabular}{@{}l" + "r" * len(PROTOS) + r"@{}}", r"\toprule", "Suite & " + " & ".join(PNAME[p] for p in PROTOS) + r" \\", r"\midrule"]
for su in ALL:
    if su == BASE:
        continue
    lines.append(sig_only(su) + " & " + " & ".join(f"{at(su, p, 0, mode='warm')['total_ms'] - at(BASE, p, 0, mode='warm')['total_ms']:.1f}" for p in PROTOS) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_warm.tex", "\n".join(lines) + "\n")

# Radio tables
lines = [r"\begin{tabular}{@{}l" + "r" * len(SINRS) + r"@{}}", r"\toprule", "Profile & " + " & ".join(f"${s:g}$\\,dB" for s in SINRS) + r" \\", r"\midrule"]
for p in PROFS:
    lines.append(PSH[p] + " & " + " & ".join(f"{lidx[(p, s)]['dl_mbps']:.0f}/{lidx[(p, s)]['ul_mbps']:.0f}" if lidx[(p, s)]['dl_mbps'] >= 9.5
                                           else f"{lidx[(p, s)]['dl_mbps']:.1f}/{lidx[(p, s)]['ul_mbps']:.1f}" for s in SINRS) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_links.tex", "\n".join(lines) + "\n")

lines = [r"\begin{tabular}{@{}l" + "r" * len(SINRS) + r"@{}}", r"\toprule", "Profile & " + " & ".join(f"${s:g}$\\,dB" for s in SINRS) + r" \\", r"\midrule"]
for p in PROFS:
    lines.append(PSH[p] + " & " + " & ".join(f"{lidx[(p, s)]['tx_per_tb']:.2f}" for s in SINRS) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_tx.tex", "\n".join(lines) + "\n")

for pr, tag in (("FAPI2", "fapi"), ("ISO_8583", "iso8583")):
    lines = [r"\begin{tabular}{@{}l" + "r" * len(SINRS) + r"@{}}", r"\toprule", "Profile & " + " & ".join(f"${s:g}$\\,dB" for s in SINRS) + r" \\", r"\midrule"]
    for p in PROFS:
        lines.append(PSH[p] + " & " + " & ".join(f"{rat(p, s, BASE, pr)['mean_ms']:.0f}$\\to$" + f"{rat(p, s, ml, pr)['mean_ms']:.0f}" for s in SINRS) + r" \\")
    lines += [r"\midrule", r"\multicolumn{8}{l}{\textit{Factor (ML-DSA-65 / baseline)}} \\"]
    for p in PROFS:
        lines.append(PSH[p] + " & " + " & ".join(f"{rf(p, s, ml, pr):.2f}$\\times$" for s in SINRS) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    write(f"tab_radio_{tag}.tex", "\n".join(lines) + "\n")

# SLA table
slas = [BASE, "RSA-2048|ECDHE-P256", "ECDSA-P256|X25519MLKEM768", "ML-DSA-44|ML-KEM-768", ml, "ML-DSA-87|ML-KEM-1024",
        "Falcon-512|ML-KEM-768", "Falcon-1024|ML-KEM-1024", "SLH-DSA-128s|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]
lines = [r"\begin{tabular}{@{}l" + "rr" * len(PROFS) + r"@{}}", r"\toprule",
         "Suite & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{PSH[p]}}}" for p in PROFS) + r" \\",
         " ".join(f"\\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(len(PROFS))),
         " & " + " & ".join("500\\,ms & 1\\,s" for _ in PROFS) + r" \\", r"\midrule"]
for su in slas:
    cells = []
    for p in PROFS:
        cells += [sla(p, su, 500.0), sla(p, su, 1000.0)]
    lines.append(sig_only(su) + " & " + " & ".join(cells) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_sla.tex", "\n".join(lines) + "\n")

# Radio profile parameter table
lines = [r"\begin{tabular}{@{}lrrrrrrrrrr@{}}", r"\toprule",
         r"Profile & BW & Layers & Share & TTI & HARQ & Base DL/UL & BLER & RLC & $p_\text{block}$ & $\bar{T}_\text{block}$ \\",
         r" & (MHz) & DL/UL & (\%) & (ms) & RTT (ms) & (ms) & target & (ms) & (\%) & (ms) \\", r"\midrule"]
for n, p in RS.PROFILES.items():
    lines.append(f"{PSH[n]} & {p.bw_hz / 1e6:g} & {p.layers_dl}/{p.layers_ul} & {100 * p.user_share:g} & {p.tti_ms:g} & {p.harq_rtt_ms:g} & "
                 f"{p.dl_base_ms:g}/{p.ul_base_ms:g} & {p.bler_target:g} & {p.rlc_delay_ms:g} & {100 * p.p_block:g} & {p.block_ms:g} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_radio_profiles.tex", "\n".join(lines) + "\n")


# Master table (v2): one row per suite, one column group per research question
lines = [r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
         r"Suite & RQ2: size, KB & RQ3: $\Delta T_{d1\to d4}$ & RQ4: $O>T_\text{cpu}$ & RQ5: cert.\ bytes \\",
         r" & (factor) & (ms) & (\% of configs) & compressed (\%) \\", r"\midrule"]
for su in ALL:
    size = f"{l7(su, 'SWIFT_MX') / 1024:.1f} ({l7(su, 'SWIFT_MX') / l7(BASE, 'SWIFT_MX'):.1f}$\\times$)"
    lines.append(f"{sig_only(su)} & {size} & {dd(su, 'total_ms'):.1f} & {100 * share(su, 1):.0f} & {red(su):.0f} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_master.tex", "\n".join(lines) + "\n")

# ================================================================== FIGURES
def save(fig, name):
    fig.savefig(os.path.join(HERE, "figures", name), bbox_inches="tight")
    plt.close(fig)


# Fig: size breakdown
cats = [("payload_fixed", "Protocol payload"), ("obj_alg", "Signatures / keys / certs in messages"),
        ("tls_cert", "TLS certificate chains"), ("tls_cv", "TLS CertificateVerify"), ("tls_kex", "TLS key shares"),
        ("tls_other", "TLS other + record framing")]
fig, axs = plt.subplots(1, 2, figsize=(7.3, 3.1), sharey=True)
for ax, (pr, d) in zip(axs, (("SWIFT_MX", 3), ("FAPI2", 2))):
    left = [0.0] * len(ALL)
    for ci, (k, lab) in enumerate(cats):
        vals = [int(szi[(su, pr, d, 0)][k]) / 1024 for su in ALL]
        ax.barh(range(len(ALL)), vals, left=left, color=CAT[ci], edgecolor=SURFACE, linewidth=1.2, height=0.72,
                label=lab if pr == "SWIFT_MX" else None)
        left = [a + b for a, b in zip(left, vals)]
    for i, t in enumerate(left):
        ax.text(t + max(left) * 0.01, i, f"{t:.0f}", va="center", fontsize=6.5, color=INK2)
    ax.set_title(f"{PNAME[pr]}, chain depth {d}")
    ax.set_xlabel("serialised size of one cold transaction (KB)")
    ax.set_yticks(range(len(ALL)), [sig_only(s).replace(" (baseline)", "") for s in ALL])
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
fig.legend(loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.12))
save(fig, "fig_sizes.pdf")

# Fig: depth x MTU
fig, axs = plt.subplots(1, 3, figsize=(7.3, 2.7), sharey=True)
for ax, mtu in zip(axs, (1280, 1500, 9000)):
    for i, su in enumerate(SHOW):
        ax.plot((1, 2, 3, 4), [at(su, "SWIFT_MX", d, mtu=mtu)["total_ms"] for d in (1, 2, 3, 4)], marker=MARK[i],
                ls=LSTY[i], color=CAT[i], label=sig_only(su))
    ax.set_title(f"MTU {mtu} B")
    ax.set_xlabel("certificate chain depth $d$")
    ax.set_xticks((1, 2, 3, 4))
axs[0].set_ylabel("SWIFT MX latency (ms)")
axs[0].set_yscale("log")
axs[0].set_yticks([100, 200, 300], ["100", "200", "300"])
fig.legend(*axs[0].get_legend_handles_labels(), loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.2))
save(fig, "fig_depth.pdf")

# Fig: RQ3 heatmap (diverging around 1)
bws = sorted({r["bw_mbps"] for r in COLD})
data = [[math.log10(max(1e-3, ratio(su, b))) for b in bws] for su in ALL]
cmap = LinearSegmentedColormap.from_list("dv", ["#2a78d6", "#f0efec", "#eb6834"])
fig, ax = plt.subplots(figsize=(4.6, 3.3))
im = ax.imshow(data, cmap=cmap, norm=TwoSlopeNorm(vcenter=0.0, vmin=-1.0, vmax=2.2), aspect="auto")
ax.set_xticks(range(len(bws)), [f"{b:g}" for b in bws])
ax.set_yticks(range(len(ALL)), [sig_only(s).replace(" (baseline)", "") for s in ALL])
for i, row in enumerate(data):
    for j, v in enumerate(row):
        ax.text(j, i, f"{10 ** v:.1f}", ha="center", va="center", fontsize=6.3, color=INK)
ax.set_xlabel("bandwidth (Mbps)")
ax.grid(False)
cb = fig.colorbar(im, ax=ax, pad=0.02)
cb.set_label("transport overhead / cryptographic time", fontsize=7)
cb.set_ticks([-1, 0, 1, 2], labels=["0.1", "1", "10", "100"])
save(fig, "fig_ratio.pdf")

# Fig: RQ4
fig, axs = plt.subplots(1, 2, figsize=(7.3, 2.9))
subs = [s for s in ALL if s != "SLH-DSA-128s|ML-KEM-768"]
lab_s = [sig_only(s).replace(" (baseline)", "").replace("ECDSA-P256 + hybrid KEM", "ECDSA+hyb") for s in subs]
for k, (thr_fn, lab) in enumerate((
        (lambda r: r["cc_saved_ms"] >= 1.0, "saves $\\geq 1$ ms"),
        (lambda r: r["cc_saved_ms"] >= 0.5 * r["rtt_ms"], "saves $\\geq$ half an RTT"))):
    axs[0].bar([i + k * 0.38 for i in range(len(subs))],
               [100 * sum(thr_fn(r) for r in COLD if r["suite"] == s) / sum(1 for r in COLD if r["suite"] == s) for s in subs],
               0.36, color=CAT[k], edgecolor=SURFACE, linewidth=1.0, label=lab)
axs[0].set_xticks([i + 0.19 for i in range(len(subs))], lab_s, rotation=55, ha="right")
axs[0].set_ylabel("cold configurations (%)")
axs[0].set_title("(a) configurations where compression helps")
axs[0].legend(frameon=False, fontsize=6.5, loc="upper right")
w = 0.2
pnames = list(S.DECOMP_PROFILES)
labels = {"server-class": "330 MB/s", "phone/laptop": "33 MB/s", "embedded": "3.3 MB/s", "very-slow": "0.33 MB/s"}
for k, pnm in enumerate(pnames):
    axs[1].bar([i + k * w for i in range(len(subs))], [harm(s, pnm) for s in subs], w, color=CAT[k], edgecolor=SURFACE,
               linewidth=1.0, label=labels[pnm])
axs[1].set_xticks([i + 1.5 * w for i in range(len(subs))], [sig_only(s).replace(" (baseline)", "").replace("ECDSA-P256 + hybrid KEM", "ECDSA+hyb") for s in subs], rotation=55, ha="right")
axs[1].set_ylabel("configurations where net effect $\\leq -1$ ms (%)")
axs[1].set_title("(b) client inflate speed")
axs[1].legend(frameon=False, ncol=2, fontsize=6.5, loc="upper left")
axs[1].set_ylim(0, 118)
save(fig, "fig_cc.pdf")

# Fig: radio links
fig, ax = plt.subplots(figsize=(3.6, 2.8))
for i, p in enumerate(PROFS):
    ax.plot(SINRS, [lidx[(p, s)]["dl_mbps"] for s in SINRS], marker=MARK[i], ls=LSTY[i], color=CAT[i], label=PSH_PLAIN[p])
ax.set_yscale("log")
ax.set_xlabel("mean downlink SINR (dB)")
ax.set_ylabel("per-user DL rate (Mbps)")
ax.invert_xaxis()
ax.legend(frameon=False, fontsize=6.3)
save(fig, "fig_links.pdf")

# Fig: radio latency
show4 = [BASE, ml, "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]
fig, axs = plt.subplots(1, 5, figsize=(7.4, 2.5), sharey=True)
xs = sorted(SINRS)
for ax, p in zip(axs, PROFS):
    for i, su in enumerate(show4):
        ax.plot(xs, [rat(p, s, su)["mean_ms"] for s in xs], marker=MARK[i], ls="-", color=CAT[i], ms=3, label=sig_only(su).replace(" (baseline)", ""))
        ax.plot(xs, [rat(p, s, su)["p99_ms"] for s in xs], ls=":", color=CAT[i], lw=1.0)
    ax.set_yscale("log")
    ax.set_title(PSH_PLAIN[p], fontsize=7.5)
    ax.set_xlabel("SINR (dB)", fontsize=7)
    ax.set_xticks([-5, 10, 30])
axs[0].set_ylabel("FAPI 2.0 latency (ms)")
h, l = axs[0].get_legend_handles_labels()
from matplotlib.lines import Line2D   # noqa: E402
h += [Line2D([], [], color=INK2, ls="-"), Line2D([], [], color=INK2, ls=":")]
l += ["mean", "P99"]
fig.legend(h, l, loc="lower center", ncol=6, frameon=False, bbox_to_anchor=(0.5, -0.14))
save(fig, "fig_radio_latency.pdf")

# Fig: radio factor heatmaps
seq = LinearSegmentedColormap.from_list("sq", ["#f7fbff", "#9ec5f4", "#2a78d6", "#0d366b"])
fig, axs = plt.subplots(1, 3, figsize=(7.3, 2.5), sharey=True)
vmax = max(rf(p, s, "SLH-DSA-128f|ML-KEM-768") for p in PROFS for s in SINRS)
for ax, (su, ttl) in zip(axs, ((ml, "ML-DSA-65"), ("Falcon-512|ML-KEM-768", "Falcon-512"), ("SLH-DSA-128f|ML-KEM-768", "SLH-DSA-128f"))):
    d = [[rf(p, s, su) for s in SINRS] for p in PROFS]
    im = ax.imshow(d, cmap=seq, vmin=1.0, vmax=vmax if ttl == "SLH-DSA-128f" else 4.6, aspect="auto")
    ax.set_xticks(range(len(SINRS)), [f"{s:g}" for s in SINRS])
    ax.set_yticks(range(len(PROFS)), [PSH_PLAIN[p] for p in PROFS])
    for i, row in enumerate(d):
        for j, v in enumerate(row):
            ax.text(j, i, f"{v:.1f}", ha="center", va="center", fontsize=6, color="white" if v > (0.55 * (vmax if ttl == "SLH-DSA-128f" else 4.6)) else INK)
    ax.set_title(ttl, fontsize=8)
    ax.set_xlabel("SINR (dB)", fontsize=7)
    ax.grid(False)
save(fig, "fig_radio_factor.pdf")


# ================================================================== MEASUREMENTS (v2)
MEAS = os.path.join(HERE, "..", "Measurements", "data")
mi = json.load(open(os.path.join(MEAS, "measured_inputs.json")))
cpu = load(os.path.join(MEAS, "cpu_summary.csv"), ["v1_assumed_ms", "x925_ms", "a725_ms", "x925_over_v1", "a725_over_x925"])
num("mldsaSignOssl", f"{mi['X925']['sigs']['ML-DSA-65']['sign_ms']:.2f}")
num("mldsaSignOqs", f"{mi['X925']['sigs']['ML-DSA-65']['liboqs_cross_check']['sign_ms']:.2f}")
num("mldsaSignVone", "0.22")
num("effSlowdown", f"{st.median(r['a725_over_x925'] for r in cpu if r['op'] in ('sign', 'verify')):.1f}")
num("slhsSignMeas", f"{mi['X925']['sigs']['SLH-DSA-128s']['sign_ms']:.0f}")
num("falSignMeas", f"{mi['X925']['sigs']['Falcon-512']['sign_ms']:.2f}")
num("beMLmbs", f"{1 / be(ml):.0f}")
lines = [r"\begin{tabular}{@{}llrrrl@{}}", r"\toprule",
         r"Algorithm & Op. & X925 & A725 & A725/X925 & Implementation \\", r"\midrule"]
for r in cpu:
    if r["op"] not in ("sign", "verify"):
        continue
    lines.append(f"{r['alg']} & {r['op']} & {r['x925_ms']:.4g} & {r['a725_ms']:.4g} & {r['a725_over_x925']:.2f} & {r['source']} \\\\")
lines += [r"\midrule"]
for r in cpu:
    if r["op"] in ("sign", "verify"):
        continue
    lines.append(f"{r['alg']} & {r['op']} & {r['x925_ms']:.4g} & {r['a725_ms']:.4g} & {r['a725_over_x925']:.2f} & {r['source']} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_cpu.tex", "\n".join(lines) + "\n")

cs = load(os.path.join(MEAS, "cert_sizes.csv"), ["leaf_der", "ca_der", "leaf_meta", "ca_meta", "pred_leaf_from_ecdsa_meta",
                                                 "pred_ca_from_ecdsa_meta", "err_leaf_pct", "err_ca_pct"])
num("certErrMax", f"{max(max(abs(r['err_leaf_pct']), abs(r['err_ca_pct'])) for r in cs):.1f}")
lines = [r"\begin{tabular}{@{}lrrrrrr@{}}", r"\toprule",
         r"Algorithm & Leaf DER & CA DER & Metadata (leaf/CA) & Predicted leaf & Predicted CA & Max error (\%) \\", r"\midrule"]
for r in cs:
    lines.append(f"{r['alg']} & {r['leaf_der']:.0f} & {r['ca_der']:.0f} & {r['leaf_meta']:.0f}/{r['ca_meta']:.0f} & {r['pred_leaf_from_ecdsa_meta']:.0f} & "
                 f"{r['pred_ca_from_ecdsa_meta']:.0f} & {max(abs(r['err_leaf_pct']), abs(r['err_ca_pct'])):.2f} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_certs.tex", "\n".join(lines) + "\n")

cp = load(os.path.join(MEAS, "compression.csv"), ["depth", "uncompressed", "zlib9", "model", "ratio_real", "ratio_model"])
pq = [r for r in cp if r["alg"].startswith(("ML-DSA", "SLH"))]
num("compRealPQlo", f"{min(r['ratio_real'] for r in pq):.2f}")
num("compRealPQhi", f"{max(r['ratio_real'] for r in pq):.2f}")
num("compErrPQ", f"{100 * max(abs(r['model'] - r['zlib9']) / r['zlib9'] for r in pq):.0f}")
num("compRealECfour", f"{[r for r in cp if r['alg'] == 'ECDSA-P256' and r['depth'] == 4][0]['ratio_real']:.2f}")
lines = [r"\begin{tabular}{@{}l" + "rr" * 4 + r"@{}}", r"\toprule",
         "Algorithm & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{$d={d}$}}" for d in (1, 2, 3, 4)) + r" \\",
         " ".join(f"\\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(4)),
         " & " + " & ".join("zlib-9 & model" for _ in range(4)) + r" \\", r"\midrule"]
for a in dict.fromkeys(r["alg"] for r in cp):
    rr = {int(r["depth"]): r for r in cp if r["alg"] == a}
    lines.append(a + " & " + " & ".join(f"{rr[d]['ratio_real']:.2f} & {rr[d]['ratio_model']:.2f}" for d in (1, 2, 3, 4)) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_comp_real.tex", "\n".join(lines) + "\n")

tv = load(os.path.join(MEAS, "tls_vs_model.csv"), ["depth", "mtls", "ch_real", "sf_real", "cf_real", "ch_model", "sf_model",
                                                   "cf_model", "err_total_pct_realchain", "err_total_pct_bankmeta",
                                                   "hs_ms_median", "model_hs_cpu_ms"])
num("tlsErrMed", f"{st.median(abs(r['err_total_pct_realchain']) for r in tv):.2f}")
num("tlsErrMax", f"{max(abs(r['err_total_pct_realchain']) for r in tv):.2f}")
num("tlsConfigs", f"{len(tv)}")
res = [r["hs_ms_median"] - r["model_hs_cpu_ms"] for r in tv]
num("hsResidLo", f"{st.quantiles(res, n=10)[0]:.1f}")
num("hsResidHi", f"{st.quantiles(res, n=10)[-1]:.1f}")
lines = [r"\begin{tabular}{@{}lrrrrrrrr@{}}", r"\toprule",
         r"Suite (mutual TLS) & $d$ & CH & Server flight & Client flight & Model total & Error (\%) & Loopback (ms) & Model CPU (ms) \\", r"\midrule"]
for r in tv:
    if r["mtls"] != 1 or int(r["depth"]) not in (1, 4):
        continue
    lines.append(f"{sig_only(r['suite'])} & {r['depth']:.0f} & {r['ch_real']:.0f} & {r['sf_real']:.0f} & {r['cf_real']:.0f} & "
                 f"{r['ch_model'] + r['sf_model'] + r['cf_model']:.0f} & {r['err_total_pct_realchain']:.2f} & {r['hs_ms_median']:.2f} & {r['model_hs_cpu_ms']:.2f} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_tls.tex", "\n".join(lines) + "\n")

td = load(os.path.join(MEAS, "trace_driven_radio.csv"), ["sinr_db", "depth", "model_mean", "trace_mean", "model_p99", "trace_p99"])
dm = [100 * (r["trace_mean"] - r["model_mean"]) / r["model_mean"] for r in td]
dp = [100 * (r["trace_p99"] - r["model_p99"]) / r["model_p99"] for r in td]
num("tdCells", f"{len(td)}")
num("tdMeanMed", f"{st.median(map(abs, dm)):.2f}")
num("tdMeanMax", f"{max(map(abs, dm)):.1f}")
num("tdPNineNineMed", f"{st.median(map(abs, dp)):.1f}")
num("tdPNineNineMax", f"{max(map(abs, dp)):.0f}")
tw = load(os.path.join(MEAS, "trace_driven_wired.csv"), ["depth", "model_ms", "trace_ms", "model_bytes", "trace_bytes"])
num("tdWiredMed", f"{st.median(abs(100 * (r['trace_ms'] - r['model_ms']) / r['model_ms']) for r in tw):.2f}")
num("tdWiredMax", f"{max(abs(100 * (r['trace_ms'] - r['model_ms']) / r['model_ms']) for r in tw):.1f}")
tdi = {(r["profile"], r["sinr_db"], r["proto"], int(r["depth"]), r["suite"]): r for r in td}
td_profs = list(dict.fromkeys(r["profile"] for r in td))
td_sinr = sorted({r["sinr_db"] for r in td}, reverse=True)
lines = [r"\begin{tabular}{@{}l" + "r" * len(td_sinr) + r"@{}}", r"\toprule",
         "Profile & " + " & ".join(f"${s:g}$\\,dB" for s in td_sinr) + r" \\", r"\midrule"]
for p in td_profs:
    cells = []
    for s in td_sinr:
        a, b = tdi[(p, s, "FAPI2", 2, ml)], tdi[(p, s, "FAPI2", 2, BASE)]
        cells.append(f"{a['model_mean'] / b['model_mean']:.2f} / {a['trace_mean'] / b['trace_mean']:.2f}")
    lines.append(PSH[p] + " & " + " & ".join(cells) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_trace.tex", "\n".join(lines) + "\n")
a, b = tdi[(s6, -5.0, "FAPI2", 2, ml)], tdi[(s6, -5.0, "FAPI2", 2, BASE)]
num("tdFactorModel", f"{a['model_mean'] / b['model_mean']:.2f}")
num("tdFactorTrace", f"{a['trace_mean'] / b['trace_mean']:.2f}")

fig, ax = plt.subplots(figsize=(3.6, 3.2))
for i, p in enumerate(td_profs):
    xs = [r["model_mean"] for r in td if r["profile"] == p]
    ys = [r["trace_mean"] for r in td if r["profile"] == p]
    ax.scatter(xs, ys, s=7, color=CAT[i], marker=MARK[i], label=PSH_PLAIN[p], alpha=0.8, linewidths=0)
lo = min(r["model_mean"] for r in td) * 0.9
hi = max(r["model_mean"] for r in td) * 1.1
ax.plot([lo, hi], [lo, hi], color=INK2, lw=0.8, ls="--")
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xlabel("model flow, mean latency (ms)")
ax.set_ylabel("real-handshake trace, mean latency (ms)")
ax.legend(frameon=False, fontsize=6.5)
save(fig, "fig_trace.pdf")


# ================================================================== v4: MITIGATIONS, LOSS, CAPACITY, INTERNET, SENSITIVITY
mit = load(os.path.join(SIM, "mitigations.csv"), ["mean_ms", "p99_ms"])
def mg(pr, m_, net, su, s=""):
    return [r for r in mit if r["protocol"] == pr and r["mitigation"] == m_ and r["network"] == net
            and r["suite"] == su and r["sinr_db"] == s][0]["mean_ms"]


MITS = [("none", "None (full handshake, TCP)"), ("cached_info", "Cached server chain (RFC 7924)"),
        ("mtc", "Merkle Tree Certificate (draft)"), ("resumption", "PSK session resumption"),
        ("quic", "QUIC (HTTP/3)"), ("quic+resumption", "QUIC + resumption")]
NETS = [("wired", "", "100 Mbps / 30 ms"), ("wired_slow", "", "10 Mbps / 100 ms"),
        ("radio", "30.0", "5G sub-6, 30 dB"), ("radio", "-5.0", "5G sub-6, $-5$ dB")]
comp = "ML-DSA-65+ECDSA-P256|X25519MLKEM768"
lines = [r"\begin{tabular}{@{}l" + "r" * 8 + r"@{}}", r"\toprule",
         r" & \multicolumn{4}{c}{ML-DSA-65} & \multicolumn{4}{c}{Falcon-512} \\",
         r"\cmidrule(lr){2-5}\cmidrule(l){6-9}",
         "Mitigation & " + " & ".join(n[2] for n in NETS) * 1 + " & " + " & ".join(n[2] for n in NETS) + r" \\", r"\midrule"]
for key, label in MITS:
    cells = []
    for su in (ml, "Falcon-512|ML-KEM-768"):
        for net, s, _ in NETS:
            try:
                cells.append(f"{mg('FAPI2', key, net, su, s) / mg('FAPI2', 'none', net, BASE, s):.2f}")
            except IndexError:
                cells.append("--")
    lines.append(label + " & " + " & ".join(cells) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_mitig.tex", "\n".join(lines) + "\n")
for key, tag in (("none", "None"), ("cached_info", "Ci"), ("mtc", "Mtc"), ("resumption", "Res"), ("quic", "Quic"), ("quic+resumption", "QuicRes")):
    num(f"mit{tag}Wired", f"{mg('FAPI2', key, 'wired', ml) / mg('FAPI2', 'none', 'wired', BASE):.2f}")
    if "quic" not in key:
        num(f"mit{tag}RadioLo", f"{mg('FAPI2', key, 'radio', ml, '-5.0') / mg('FAPI2', 'none', 'radio', BASE, '-5.0'):.2f}")
        num(f"mit{tag}RadioHi", f"{mg('FAPI2', key, 'radio', ml, '30.0') / mg('FAPI2', 'none', 'radio', BASE, '30.0'):.2f}")
num("mitQuicSaveMs", f"{mg('FAPI2', 'none', 'wired', BASE) - mg('FAPI2', 'quic', 'wired', BASE):.0f}")
num("compositeExtraPct", f"{100 * (mg('FAPI2', 'none', 'wired', comp) / mg('FAPI2', 'none', 'wired', ml) - 1):.1f}")
warm = [r for r in RR if r["profile"] == s6 and r["sinr_db"] == -5.0 and r["protocol"] == "FAPI2" and r["mode"] == "warm"]
num("warmFapiLo", f"{[r for r in warm if r['suite'] == ml][0]['mean_ms'] / [r for r in warm if r['suite'] == BASE][0]['mean_ms']:.2f}")


# QUIC anti-amplification gate: cost with the default and a large initial window
_f = S.build_flow(ml, "FAPI2", 2, "cold", False)
def _gate(icw):
    net = S.Net(100.0, 30.0, 1500, 0.0, 99, init_cwnd=icw, quic=True)
    on = S.run_flow(_f, net)["total"]
    old, S.QUIC_CLIENT_INITIAL = S.QUIC_CLIENT_INITIAL, 10 ** 9
    try:
        return on - S.run_flow(_f, net)["total"]
    finally:
        S.QUIC_CLIENT_INITIAL = old


_cp = "ML-DSA-65+ECDSA-P256|X25519MLKEM768"
num("compositeDepthDelta", f"{dd(_cp, 'total_ms'):.1f}")

# ---- the same quantities under the v4 closed form (ideal segmentation, cwnd += every flight), for comparison
V4 = load(os.path.join(SIM, "sens", "v4stack", "results.csv"), WF)
v4idx = {(r["suite"], r["protocol"], r["mode"], int(r["depth"]), r["bw_mbps"], r["rtt_ms"], int(r["mtu"]),
          r["penalty_ms"], int(r["thr"])): r for r in V4}


def v4at(s, p, d, bw=100.0, rtt=30.0, mtu=1500, pen=0.0, mode="cold", thr=4):
    return v4idx[(s, p, mode, 0 if mode == "warm" else d, float(bw), float(rtt), int(mtu), float(pen), thr)]


def v4dd(s, c="total_ms", p="SWIFT_MX", **kw):
    return v4at(s, p, 4, **kw)[c] - v4at(s, p, 1, **kw)[c]


num("hybKneeBaseIdeal", f"{v4at(BASE, 'SWIFT_MX', 1, mtu=1280)['total_ms']:.0f}")
num("hybKneeHybIdeal", f"{v4at('ECDSA-P256|X25519MLKEM768', 'SWIFT_MX', 1, mtu=1280)['total_ms']:.0f}")
num("ecDepthDeltaIdeal", f"{v4dd(BASE):.1f}")
num("mlDepthDeltaIdeal", f"{v4dd(ml):.1f}")
num("compositeDepthDeltaIdeal", f"{v4dd(_cp):.1f}")
_cold4 = [r for r in V4 if r["mode"] == "cold"]
num("shareMLxOneIdeal", f"{100 * sum(r['ser_ms'] + r['ssw_ms'] + r['pen_ms'] > r['cpu_ms'] for r in _cold4 if r['suite'] == ml and int(r['depth']) in (1, 2, 3, 4)) / max(1, sum(1 for r in _cold4 if r['suite'] == ml)):.0f}")
num("mlDepthDelta87", f"{dd('ML-DSA-87|ML-KEM-1024', 'total_ms'):.1f}")
num("mlDepthDelta87Ideal", f"{v4dd('ML-DSA-87|ML-KEM-1024'):.1f}")
num("mlDepthNet", f"{dd(ml, 'total_ms') - dd(BASE, 'total_ms'):.1f}")
num("perCertNet", f"{(dd(ml, 'total_ms') - dd(BASE, 'total_ms')) / 3:.1f}")
num("hybDepthDelta", f"{dd('ECDSA-P256|X25519MLKEM768', 'total_ms'):.1f}")
_n = mg("FAPI2", "none", "wired", ml); _r = mg("FAPI2", "resumption", "wired", ml)
num("mitCiShare", f"{100 * (_n - mg('FAPI2', 'cached_info', 'wired', ml)) / (_n - _r):.0f}")
num("mitMtcShare", f"{100 * (_n - mg('FAPI2', 'mtc', 'wired', ml)) / (_n - _r):.0f}")
num("quicGateTen", f"{_gate(10):.1f}")
num("quicGateThirtyTwo", f"{_gate(32):.0f}")
_t = lambda q, su: S.run_flow(S.build_flow(su, "FAPI2", 2, "cold", False), S.Net(100.0, 30.0, 1500, 6.0, 4, quic=q))["total"]
num("absPenTcp", f"{_t(False, ml) - _t(False, BASE):.0f}")
num("absPenQuic", f"{_t(True, ml) - _t(True, BASE):.0f}")

# loss
lo = load(os.path.join(SIM, "loss_results.csv"), ["loss", "rtt_ms", "mean_ms", "se_ms", "p50_ms", "p95_ms", "p99_ms"])
def lg(pr, su, p, rtt=30.0, k="mean_ms"):
    return [r for r in lo if r["protocol"] == pr and r["suite"] == su and r["loss"] == p and r["rtt_ms"] == rtt][0][k]


num("lossGapZero", f"{lg('FAPI2', ml, 0.0) - lg('FAPI2', BASE, 0.0):.0f}")
num("lossGapTwo", f"{lg('FAPI2', ml, 0.02) - lg('FAPI2', BASE, 0.02):.0f}")
num("lossFactorZero", f"{lg('FAPI2', ml, 0.0) / lg('FAPI2', BASE, 0.0):.2f}")
num("lossFactorTwo", f"{lg('FAPI2', ml, 0.02) / lg('FAPI2', BASE, 0.02):.2f}")
num("lossSlhGapTwo", f"{lg('FAPI2', 'SLH-DSA-128f|ML-KEM-768', 0.02) - lg('FAPI2', BASE, 0.02):.0f}")
losses = sorted({r["loss"] for r in lo})
fig, axs = plt.subplots(1, 2, figsize=(7.3, 2.8), sharex=True)
show_l = [BASE, "ECDSA-P256|X25519MLKEM768", ml, "Falcon-512|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"]
for ax, key, ttl in ((axs[0], "mean_ms", "mean"), (axs[1], "p95_ms", "95th percentile")):
    for i, su in enumerate(show_l):
        ax.plot([100 * p for p in losses], [lg("FAPI2", su, p, 30.0, key) for p in losses], marker=MARK[i], ls=LSTY[i],
                color=CAT[i], label=sig_only(su).replace(" (baseline)", ""))
    ax.set_xlabel("segment loss rate (%)")
    ax.set_title(f"FAPI 2.0, 100 Mbps, 30 ms RTT: {ttl}")
axs[0].set_ylabel("latency (ms)")
axs[0].legend(frameon=False, fontsize=6.3)
save(fig, "fig_loss.pdf")

# server capacity
cap = load(os.path.join(MEAS, "capacity.csv"), ["mtls", "hs_per_s", "server_cpu_util", "server_cpu_ms_per_hs"])
def cg(su, mt):
    return [r for r in cap if r["suite"] == su and int(r["mtls"]) == mt][0]["server_cpu_ms_per_hs"]


lines = [r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
         r"Suite & \multicolumn{2}{c}{Server CPU per handshake (ms)} & \multicolumn{2}{c}{Handshakes/s per core} \\",
         r"\cmidrule(lr){2-3}\cmidrule(l){4-5}", r" & server auth & mutual TLS & server auth & mutual TLS \\", r"\midrule"]
for su in dict.fromkeys(r["suite"] for r in cap):
    a, b = cg(su, 0), cg(su, 1)
    lines.append(f"{sig_only(su)} & {a:.3f} & {b:.3f} & {1000 / a:,.0f} & {1000 / b:,.0f} \\\\".replace(",", "{,}"))
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_capacity.tex", "\n".join(lines) + "\n")
num("capEC", f"{1000 / cg(BASE, 0):,.0f}".replace(",", "{,}"))
num("capHyb", f"{1000 / cg('ECDSA-P256|X25519MLKEM768', 0):,.0f}".replace(",", "{,}"))
num("capML", f"{1000 / cg(ml, 0):,.0f}".replace(",", "{,}"))
num("capMLm", f"{1000 / cg(ml, 1):,.0f}".replace(",", "{,}"))
num("capMLratio", f"{cg(ml, 0) / cg(BASE, 0):.1f}")
num("capHybPct", f"{100 * (cg('ECDSA-P256|X25519MLKEM768', 0) / cg(BASE, 0) - 1):.0f}")

# real Internet
ik = load(os.path.join(MEAS, "internet_kem.csv"), ["round", "tcp_ms", "handshake_ms", "bytes_out", "bytes_in"])
import random as _rnd   # noqa: E402
lines = [r"\begin{tabular}{@{}lrrrrr@{}}", r"\toprule",
         r"Server & RTT (ms) & X25519 (ms) & X25519MLKEM768 (ms) & Paired difference (ms) & Extra bytes out/in \\", r"\midrule"]
for h in ("cloudflare.com", "www.google.com"):
    a = {r["round"]: r for r in ik if r["host"] == h and r["group"] == "x25519"}
    b = {r["round"]: r for r in ik if r["host"] == h and r["group"] == "X25519MLKEM768"}
    d = sorted(b[k]["handshake_ms"] - a[k]["handshake_ms"] for k in a if k in b)
    rng = _rnd.Random(1)
    boots = sorted(st.median(rng.choices(d, k=len(d))) for _ in range(2000))
    med, lo95, hi95 = st.median(d), boots[50], boots[1950]
    rtt = st.median([r["tcp_ms"] for r in ik if r["host"] == h])
    lines.append(f"{h} & {rtt:.0f} & {st.median(x['handshake_ms'] for x in a.values()):.1f} & "
                 f"{st.median(x['handshake_ms'] for x in b.values()):.1f} & {med:.1f} [{lo95:.1f}, {hi95:.1f}] & "
                 f"{st.median(x['bytes_out'] for x in b.values()) - st.median(x['bytes_out'] for x in a.values()):.0f}/"
                 f"{st.median(x['bytes_in'] for x in b.values()) - st.median(x['bytes_in'] for x in a.values()):.0f} \\\\")
    tag = "Cf" if h.startswith("cloud") else "Gg"
    num(f"inet{tag}", f"{med:.1f}"); num(f"inet{tag}Lo", f"{lo95:.1f}"); num(f"inet{tag}Hi", f"{hi95:.1f}")
    num(f"inet{tag}Rtt", f"{rtt:.0f}")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_internet.tex", "\n".join(lines) + "\n")
num("inetN", f"{len(ik)}")

# resumption
rs = load(os.path.join(MEAS, "resumption.csv"), ["depth", "mtls", "reused", "ticket_bytes", "full_ch", "full_sf", "full_cf",
                                                 "res_ch", "res_sf", "res_cf", "res_new_ticket"])
lines = [r"\begin{tabular}{@{}lrrrrrr@{}}", r"\toprule",
         r"Suite (depth 2) & Auth. & Ticket & Full handshake CH/SF/CF & Resumed CH/SF/CF & New ticket \\", r"\midrule"]
for r in rs:
    if int(r["depth"]) != 2:
        continue
    lines.append(f"{sig_only(r['suite'])} & {'mutual' if r['mtls'] else 'server'} & {r['ticket_bytes']:.0f} & "
                 f"{r['full_ch']:.0f}/{r['full_sf']:.0f}/{r['full_cf']:.0f} & {r['res_ch']:.0f}/{r['res_sf']:.0f}/{r['res_cf']:.0f} & {r['res_new_ticket']:.0f} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_resumption.tex", "\n".join(lines) + "\n")
rr_ = [r for r in rs if r["suite"] == ml and int(r["depth"]) == 2 and r["mtls"] == 1][0]
num("resTicketML", f"{rr_['ticket_bytes']:,.0f}".replace(",", "{,}"))
num("resChML", f"{rr_['res_ch']:,.0f}".replace(",", "{,}"))
num("resSfML", f"{rr_['res_sf']:,.0f}".replace(",", "{,}"))
num("fullSfML", f"{rr_['full_sf']:,.0f}".replace(",", "{,}"))
num("resTicketBase", f"{[r for r in rs if r['suite'] == BASE and int(r['depth']) == 2 and r['mtls'] == 0][0]['ticket_bytes']:.0f}")

# application objects
ao = load(os.path.join(MEAS, "app_objects.csv"), ["real_bytes", "model_bytes", "sig_bytes", "signer_cert_der"])
def ag(alg, obj, k):
    return [r for r in ao if r["alg"] == alg and r["object"] == obj][0][k]


xerr = max(abs(r["model_bytes"] - r["real_bytes"]) / r["real_bytes"] for r in ao if r["object"] == "xmldsig")
num("appXmlErr", f"{100 * xerr:.1f}")
derr = []
for a in dict.fromkeys(r["alg"] for r in ao):
    if a == "ECDSA-P256":
        continue
    for o in ("client_assertion", "access_token", "dpop", "xmldsig"):
        rd = ag(a, o, "real_bytes") - ag("ECDSA-P256", o, "real_bytes")
        md = ag(a, o, "model_bytes") - ag("ECDSA-P256", o, "model_bytes")
        derr.append(abs(md - rd) / rd)
num("appDeltaErr", f"{100 * max(derr):.1f}")
num("appDpopML", f"{ag('ML-DSA-65', 'dpop', 'real_bytes'):,.0f}".replace(",", "{,}"))
num("appDpopEC", f"{ag('ECDSA-P256', 'dpop', 'real_bytes'):,.0f}".replace(",", "{,}"))
lines = [r"\begin{tabular}{@{}l" + "rr" * 4 + r"@{}}", r"\toprule",
         r"Algorithm & \multicolumn{2}{c}{Client assertion} & \multicolumn{2}{c}{Access token} & \multicolumn{2}{c}{DPoP proof} & \multicolumn{2}{c}{XMLDSig} \\",
         r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}\cmidrule(lr){6-7}\cmidrule(l){8-9}",
         r" & real & model & real & model & real & model & real & model \\", r"\midrule"]
for a in dict.fromkeys(r["alg"] for r in ao):
    lines.append(a + " & " + " & ".join(f"{ag(a, o, 'real_bytes'):.0f} & {ag(a, o, 'model_bytes'):.0f}"
                                        for o in ("client_assertion", "access_token", "dpop", "xmldsig")) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_app.tex", "\n".join(lines) + "\n")

# global sensitivity
gs = load(os.path.join(SIM, "sensitivity_indices.csv"), ["index"])
NAMES = {"suite": "suite", "protocol": "protocol", "depth": "chain depth", "bw_mbps": "bandwidth", "rtt_ms": "RTT",
         "mtu": "MTU", "penalty_ms": "penalty", "profile": "radio profile", "sinr_db": "SINR", "mode": "connection reuse"}
def top(resp, k=5):
    t = sorted([r for r in gs if r["response"] == resp], key=lambda r: -r["index"])[:k]
    return ", ".join(f"{NAMES[r['factor']]}{' x ' + NAMES[r['factor2']] if r['factor2'] else ''} ({r['index']:.2f})" for r in t)


lines = [r"\begin{tabular}{@{}lp{0.68\textwidth}@{}}", r"\toprule", r"Response & Largest first- and second-order indices \\", r"\midrule"]
for resp, lab in (("wired_latency", "log latency, wired"), ("wired_factor", "log PQ factor, wired, all PQ suites"),
                  ("wired_factor_lattice", "log PQ factor, wired, ML-DSA and Falcon"),
                  ("radio_factor", "log PQ factor, radio, all PQ suites"),
                  ("radio_factor_lattice", "log PQ factor, radio, ML-DSA and Falcon")):
    lines.append(f"{lab} & {top(resp)} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
write("tab_sobol.tex", "\n".join(lines) + "\n")
gi = {(r["response"], r["factor"], r["factor2"]): r["index"] for r in gs}
num("sobolLatRtt", f"{gi[('wired_latency', 'rtt_ms', '')]:.2f}")
num("sobolLatSuite", f"{gi[('wired_latency', 'suite', '')]:.2f}")
num("sobolLatMtu", f"{gi[('wired_factor_lattice', 'mtu', '')]:.2f}")
num("sobolLatRttF", f"{gi[('wired_factor_lattice', 'rtt_ms', '')]:.2f}")
num("sobolLatSuiteF", f"{gi[('wired_factor_lattice', 'suite', '')]:.2f}")
num("sobolRadSuite", f"{gi[('radio_factor_lattice', 'suite', '')]:.2f}")
num("sobolRadProto", f"{gi[('radio_factor_lattice', 'protocol', '')]:.2f}")
num("sobolRadSinr", f"{gi[('radio_factor_lattice', 'sinr_db', '')]:.2f}")
num("sobolRadProf", f"{gi[('radio_factor_lattice', 'profile', '')]:.2f}")

# confidence intervals of the radio factors
ci = load(os.path.join(SIM, "radio_factor_ci.csv"), ["sinr_db", "factor", "ci_lo", "ci_hi"])
c_ = [r for r in ci if r["profile"] == s6 and r["sinr_db"] == -5.0 and r["protocol"] == "FAPI2" and r["mode"] == "cold" and r["suite"] == ml][0]
num("ciMLLo", f"{c_['ci_lo']:.2f}"); num("ciMLHi", f"{c_['ci_hi']:.2f}")
num("ciMaxHalf", f"{max((r['ci_hi'] - r['ci_lo']) / 2 / r['factor'] for r in ci if not r['suite'].startswith('SLH')) * 100:.1f}")

# ================================================================== numbers.tex
with open(os.path.join(HERE, "numbers.tex"), "w") as fh:
    fh.write("% Generated by make_assets.py - do not edit\n")
    for k, v in sorted(NUMS.items()):
        fh.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(f"[make_assets] {len(NUMS)} numbers, tables/ and figures/ written")
