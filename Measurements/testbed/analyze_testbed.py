#!/usr/bin/env python3
"""
analyze_testbed.py - compare the emulated-network measurements with the transport model.

    python3 analyze_testbed.py results/testbed_raw.csv [--outdir results]

Method. For every shaped configuration the *excess* latency is the median transaction time minus the median
of the unshaped "base" run of the same suite, depth and mutual-TLS mode. Computation, TLS library overhead
and loopback stack cost lie on the critical path in both runs and cancel, so the excess is what the model
calls T_ser + T_prop + T_ssw (+ T_pen). It is compared with
    model_excess = T - T_cpu   of pqc_sim.run_flow() for the same flow, link, MTU and initial window.
Outputs (outdir):
    testbed_summary.csv      one row per configuration (median / p10 / p90 of the measured times)
    model_vs_testbed.csv     measured excess vs model, per configuration, plus size check
    model_vs_testbed_stats.txt   errors per suite, rank correlation, size agreement
    pi_theta_fit.csv         least-squares fit of the middlebox penalty pi for every threshold theta
    proxy_delta.csv          (if proxy runs exist) latency added by a real middlebox over the direct path
    model_vs_testbed.png     scatter (if matplotlib is installed)
"""
from __future__ import annotations

import argparse
import csv
import math
import random
import os
import statistics as st
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "Simulation"))
import pqc_sim as S  # noqa: E402

KEY_BASE = ("topology", "suite", "depth", "mtls", "req", "resp", "resume")
KEY_NET = ("rtt_ms", "rate_mbps", "loss_pct", "mtu", "icw", "cc")


def f(x):
    return float(x) if x not in ("", None) else float("nan")


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def load(path, allow_loopback):
    rows = list(csv.DictReader(open(path)))
    for r in rows:
        if r.get("resume") in (None, ""):
            r["resume"] = "0"              # runs before the resumption extension: full handshakes
    if not allow_loopback:
        rows = [r for r in rows if r["topology"] != "loopback"]
    return rows


def aggregate(rows):
    by = defaultdict(list)
    for r in rows:
        key = tuple((f"{float(r[k]):g}" if k in ("rtt_ms", "rate_mbps", "loss_pct") else r[k])
                    for k in KEY_BASE + KEY_NET + ("net_id",))
        by[key].append(r)
    out = {}
    for cid, rs in by.items():
        r0 = rs[0]
        good = [r for r in rs if r["err"] == "" and f(r["t_total_ms"]) > 0]
        n_all = len(rs)
        loss = f(r0["loss_pct"])
        if loss == 0:                                   # a retransmission without loss = queue drop / artefact
            clean = [r for r in good if int(r["retrans"]) == 0]
            if len(clean) >= max(3, len(good) // 2):
                good = clean
        if len(good) < 3:
            continue
        tt = [f(r["t_total_ms"]) for r in good]
        hs = [f(r["t_hs_ms"]) for r in good]
        norm = {k: (f"{float(r0[k]):g}" if k in ("rtt_ms", "rate_mbps", "loss_pct") else r0[k])
                for k in KEY_BASE + KEY_NET + ("net_id",)}      # "100" and "100.0" are the same configuration
        out[cid] = dict(
            norm,
            times=tt, n=len(good), n_all=n_all, med=st.median(tt), p10=pct(tt, 0.1), p90=pct(tt, 0.9), mean=st.mean(tt),
            hs_med=st.median(hs), bytes=st.median(f(r["bytes_w"]) + f(r["bytes_r"]) for r in good),
            mss=st.mode(int(r["snd_mss"]) for r in good), cwnd0=st.mode(int(r["snd_cwnd0"]) for r in good),
            retrans=sum(int(r["retrans"]) for r in good) / len(good),
            segs_out=st.median([int(r["data_segs_out"]) for r in good if r.get("data_segs_out")] or [0]),   # older runs lack the counters
            segs_in=st.median([int(r["data_segs_in"]) for r in good if r.get("data_segs_in")] or [0]))
    return out


_PROTO = {}


def probe_protocol(mtls, req, resp, depth):
    name = f"PROBE_{mtls}_{req}_{resp}_{depth}"
    if name not in _PROTO:
        S.PROTOCOLS[name] = S.Protocol(name, "testbed probe", bool(int(mtls)), int(depth),
                                       (S.Exchange("x", int(req), int(resp)),))
        _PROTO[name] = name
    return name


def model_for(c, penalty=0.0, thr=4, cwnd_validation=False, segmentation="ideal"):
    flow = S.build_flow(c["suite"], probe_protocol(c["mtls"], c["req"], c["resp"], c["depth"]), int(c["depth"]),
                        "resumed" if c.get("resume") == "1" else "cold", False)
    net = S.Net(f(c["rate_mbps"]), f(c["rtt_ms"]), int(c["mtu"]), penalty_ms=penalty, thr=thr,
                init_cwnd=int(c["icw"]), cwnd_validation=cwnd_validation, segmentation=segmentation)
    return flow, S.run_flow(flow, net)


def spearman(a, b):
    def rank(x):
        order = sorted(range(len(x)), key=lambda i: x[i])
        r = [0.0] * len(x)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and x[order[j + 1]] == x[order[i]]:
                j += 1
            for k in range(i, j + 1):
                r[order[k]] = (i + j) / 2 + 1
            i = j + 1
        return r
    ra, rb = rank(a), rank(b)
    ma, mb = st.mean(ra), st.mean(rb)
    num = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    den = math.sqrt(sum((x - ma) ** 2 for x in ra) * sum((y - mb) ** 2 for y in rb))
    return num / den if den else float("nan")


def fit_pi(rs, ps):
    """argmin_pi sum (r - pi p)^2, pi >= 0; and the two-parameter fit r = a + pi p."""
    spp = sum(p * p for p in ps)
    pi = max(0.0, sum(r * p for r, p in zip(rs, ps)) / spp) if spp else 0.0
    sse = sum((r - pi * p) ** 2 for r, p in zip(rs, ps))
    n = len(rs)
    mr, mp = sum(rs) / n, sum(ps) / n
    vp = sum((p - mp) ** 2 for p in ps)
    pi2 = max(0.0, sum((r - mr) * (p - mp) for r, p in zip(rs, ps)) / vp) if vp else 0.0
    a = mr - pi2 * mp
    sse2 = sum((r - a - pi2 * p) ** 2 for r, p in zip(rs, ps))
    return pi, sse, a, pi2, sse2


def build_table(agg, boot=1000):
    """One row per shaped configuration: measured excess latency (with bootstrap CI) against three model variants."""
    base = {tuple(c[k] for k in KEY_BASE): c for c in agg.values() if c["net_id"] == "base"}
    shaped = [c for c in agg.values() if c["net_id"] == "shaped"]
    table = []
    for c in shaped:
        b = base.get(tuple(c[k] for k in KEY_BASE))
        if not b:
            continue
        flow, m = model_for(c)
        _, mcv = model_for(c, cwnd_validation=True)
        _, mos = model_for(c, cwnd_validation=True, segmentation="openssl")
        excess = c["med"] - b["med"]
        rng = random.Random(1)
        bs = sorted(st.median(rng.choices(c["times"], k=len(c["times"]))) - st.median(rng.choices(b["times"], k=len(b["times"])))
                    for _ in range(boot))
        lo, hi = bs[int(0.025 * boot)], bs[min(boot - 1, int(0.975 * boot))]
        noncpu = m["total"] - m["cpu"]
        table.append(dict(
            {k: v for k, v in c.items() if k != "times"}, base_ms=round(b["med"], 3), excess_lo=round(lo, 3), excess_hi=round(hi, 3), model_cv_ms=round(mcv["total"] - mcv["cpu"], 3),
            model_stack_ms=round(mos["total"] - mos["cpu"], 3),
            stack_in_ci=int(lo <= mos["total"] - mos["cpu"] <= hi), stack_within_1ms=int(abs(mos["total"] - mos["cpu"] - excess) <= 1.0), model_stack_segs=mos["segs"], excess_ms=round(excess, 3), model_ms=round(noncpu, 3),
            err_ms=round(noncpu - excess, 3), rel_err=round((noncpu - excess) / excess, 4) if excess > 1 else "",
            model_ser=round(m["ser"], 3), model_prop=round(m["prop"], 3), model_ssw=round(m["ssw"], 3),
            model_max_flight=m["max_flight"], model_segs=m["segs"],
            model_segs_c=sum(-(-s[2] // (int(c["mtu"]) - 60)) for s in flow.steps if s[0] == "x" and s[1] == 0),
            model_segs_s=sum(-(-s[2] // (int(c["mtu"]) - 60)) for s in flow.steps if s[0] == "x" and s[1] == 1), model_l7=flow.sizes["total_l7"],
            meas_l7=int(c["bytes"]), size_ratio=round(c["bytes"] / flow.sizes["total_l7"], 4),
            rtt_equiv=round(excess / f(c["rtt_ms"]), 2) if f(c["rtt_ms"]) else ""))
    return table


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("raw")
    ap.add_argument("--outdir", default=os.path.join(HERE, "results"))
    ap.add_argument("--allow-loopback", action="store_true", help="pipeline self-test on loopback data")
    ap.add_argument("--max-theta", type=int, default=24)
    ap.add_argument("--boot", type=int, default=1000, help="bootstrap resamples for the CI of the excess latency")
    ap.add_argument("--fit-model", choices=["v4", "linux", "stack"], default="stack",
                    help="model used for the pi/theta fit: v4 closed form, Linux cwnd rule, or Linux rule + OpenSSL writes")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    if not os.access(a.outdir, os.W_OK):
        sys.exit(f"cannot write to {a.outdir} (probably created by sudo): run  sudo chown -R $USER:$USER {a.outdir}")

    agg = aggregate(load(a.raw, a.allow_loopback))
    if not agg:
        sys.exit("no usable rows")
    with open(os.path.join(a.outdir, "testbed_summary.csv"), "w", newline="") as fh:
        cols = [k for k in next(iter(agg.values())).keys() if k != "times"]
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for c in agg.values():
            w.writerow({k: (round(v, 3) if isinstance(v, float) else v) for k, v in c.items() if k != "times"})

    table = build_table(agg, a.boot)
    lines = []
    if not table:
        sys.exit("no shaped configuration with a matching base run")
    with open(os.path.join(a.outdir, "model_vs_testbed.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(table[0].keys()))
        w.writeheader()
        w.writerows(table)

    # ------------------------------------------------------------ statistics
    direct = [t for t in table if t["topology"] == "direct" and f(t["loss_pct"]) == 0]
    lines.append(f"configurations compared: {len(table)} (direct, loss 0: {len(direct)})")
    for label, key in (("v4 rule: cwnd += every flight", "model_ms"), ("Linux cwnd rule (grow only if the flight used > half of it)", "model_cv_ms"),
                       ("Linux cwnd rule + OpenSSL write pattern (stack model)", "model_stack_ms")):
        if len(direct) >= 3:
            e = [t[key] - t["excess_ms"] for t in direct]
            big = sum(abs(v) > 0.4 * f(t["rtt_ms"]) for v, t in zip(e, direct))
            lines.append(f"[{label}] bias {st.mean(e):+.2f} ms, MAE {st.mean(abs(v) for v in e):.2f} ms, max |error| "
                         f"{max(abs(v) for v in e):.1f} ms, configurations off by more than 0.4 RTT: {big}")
    for label, rows in (("all", table), ("direct, loss 0", direct)):
        if len(rows) < 3:
            continue
        e = [t["err_ms"] for t in rows]
        x = [t["excess_ms"] for t in rows]
        y = [t["model_ms"] for t in rows]
        rel = [abs(t["rel_err"]) for t in rows if t["rel_err"] != ""]
        lines.append(f"[{label}] bias (model - measured) {st.mean(e):+.2f} ms, MAE {st.mean(abs(v) for v in e):.2f} ms, "
                     f"median |rel. error| {100 * st.median(rel):.1f} %, Spearman {spearman(x, y):.3f}, "
                     f"mean size ratio {st.mean(t['size_ratio'] for t in rows):.3f}")
    lines.append("\nper suite (direct, loss 0): n, bias ms, MAE ms, median |rel err| %")
    for su in sorted({t["suite"] for t in direct}):
        rows = [t for t in direct if t["suite"] == su]
        e = [t["err_ms"] for t in rows]
        rel = [abs(t["rel_err"]) for t in rows if t["rel_err"] != ""]
        lines.append(f"  {su:32s} {len(rows):4d}  {st.mean(e):+7.2f}  {st.mean(abs(v) for v in e):6.2f}  "
                     f"{100 * st.median(rel) if rel else float('nan'):6.1f}")
    worst = sorted(direct, key=lambda t: -abs(t["err_ms"]))[:8]
    lines.append("\nlargest deviations (direct, loss 0):")
    for t in worst:
        lines.append(f"  {t['suite']:28s} d{t['depth']} rtt={t['rtt_ms']} rate={t['rate_mbps']} mtu={t['mtu']} "
                     f"icw={t['icw']}: measured {t['excess_ms']:.1f}, model {t['model_ms']:.1f} ms, "
                     f"max flight {t['model_max_flight']} segments")
    seg = [t for t in table if t["segs_out"] > 0]
    if seg:
        more = [t for t in seg if t["segs_out"] > t["model_segs_c"] or t["segs_in"] > t["model_segs_s"]]
        lines.append(f"\ndata segments (kernel counters) vs model: {len(more)} of {len(seg)} configurations use more segments than "
                     f"the model; mean difference client {st.mean(t['segs_out'] - t['model_segs_c'] for t in seg):+.2f}, "
                     f"server {st.mean(t['segs_in'] - t['model_segs_s'] for t in seg):+.2f} segments")
        for t in sorted(seg, key=lambda t: -(abs(t["segs_out"] - t["model_segs_c"]) + abs(t["segs_in"] - t["model_segs_s"])))[:6]:
            lines.append(f"  {t['suite']:28s} d{t['depth']} client {t['segs_out']:.0f} vs model {t['model_segs_c']}, "
                         f"server {t['segs_in']:.0f} vs model {t['model_segs_s']}; error {t['err_ms']:+.1f} ms")
    lines.append(f"\nstack model inside the 95 % bootstrap CI of the measured excess: {sum(t['stack_in_ci'] for t in table)} of "
                 f"{len(table)} configurations; within 1 ms: {sum(t['stack_within_1ms'] for t in table)}; "
                 f"within 0.1 RTT: {sum(abs(t['model_stack_ms'] - t['excess_ms']) <= 0.1 * f(t['rtt_ms']) for t in table)}")
    bad = [t for t in table if int(t["mss"]) != int(t["mtu"]) - 60 or int(t["cwnd0"]) != int(t["icw"])]
    lines.append(f"\nconfigurations whose TCP MSS / initial cwnd differ from the request: {len(bad)}")

    # ------------------------------------------------------------ pi / theta fit (direct path, no loss)
    if len(direct) >= 10:
        key = {"v4": "model_ms", "linux": "model_cv_ms", "stack": "model_stack_ms"}[a.fit_model]
        kw = {"v4": {}, "linux": dict(cwnd_validation=True), "stack": dict(cwnd_validation=True, segmentation="openssl")}[a.fit_model]
        rs = [t["excess_ms"] - t[key] for t in direct]
        rows = []
        sse0 = sum(r * r for r in rs)
        for th in range(1, a.max_theta + 1):
            ps = []
            for t in direct:
                _, m = model_for(t, penalty=1.0, thr=th, **kw)
                ps.append(m["pen_flights"])
            pi, sse, a0, pi2, sse2 = fit_pi(rs, ps)
            rows.append(dict(theta=th, pi_ms=round(pi, 3), rmse_ms=round(math.sqrt(sse / len(rs)), 3),
                             pi_with_offset_ms=round(pi2, 3), offset_ms=round(a0, 3),
                             rmse_with_offset_ms=round(math.sqrt(sse2 / len(rs)), 3)))
        best = min(rows, key=lambda r: r["rmse_ms"])
        with open(os.path.join(a.outdir, "pi_theta_fit.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        lines.append(f"\nmiddlebox penalty fit ({a.fit_model} model) on the direct path (no middlebox present): RMSE with pi=0 is "
                     f"{math.sqrt(sse0 / len(rs)):.2f} ms; best theta={best['theta']} gives pi={best['pi_ms']} ms, "
                     f"RMSE {best['rmse_ms']} ms. A fitted pi near 0 means the lower bound pi=0 is supported "
                     f"by the kernel path.")

    # ------------------------------------------------------------ real middlebox vs direct path
    prox = [c for c in agg.values() if c["net_id"] == "shaped" and c["topology"].startswith("proxy")]
    dirs = {tuple(c[k] for k in KEY_BASE[1:] + KEY_NET): c for c in agg.values()
            if c["net_id"] == "shaped" and c["topology"] == "direct"}
    deltas = []
    for c in prox:
        d = dirs.get(tuple(c[k] for k in KEY_BASE[1:] + KEY_NET))
        if not d:
            continue
        _, m = model_for(c)
        deltas.append(dict(topology=c["topology"], suite=c["suite"], depth=c["depth"], mtls=c["mtls"],
                           rtt_ms=c["rtt_ms"], rate_mbps=c["rate_mbps"], mtu=c["mtu"], icw=c["icw"],
                           proxy_ms=round(c["med"], 3), direct_ms=round(d["med"], 3),
                           delta_ms=round(c["med"] - d["med"], 3), model_max_flight=m["max_flight"],
                           model_segs=m["segs"]))
    if deltas:
        with open(os.path.join(a.outdir, "proxy_delta.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(deltas[0].keys()))
            w.writeheader()
            w.writerows(deltas)
        for topo in sorted({d["topology"] for d in deltas}):
            ds = [d for d in deltas if d["topology"] == topo]
            best = None
            for th in range(1, a.max_theta + 1):
                ps = []
                for d in ds:
                    cfg = dict(suite=d["suite"], depth=d["depth"], mtls=d["mtls"], req=302, resp=222,
                               rtt_ms=d["rtt_ms"], rate_mbps=d["rate_mbps"], mtu=d["mtu"], icw=d["icw"])
                    _, m = model_for(cfg, penalty=1.0, thr=th)
                    ps.append(m["pen_flights"])
                pi, sse, a0, pi2, sse2 = fit_pi([d["delta_ms"] for d in ds], ps)
                if best is None or sse < best[0]:
                    best = (sse, th, pi, a0, pi2, sse2)
            lines.append(f"\n{topo}: {len(ds)} configurations; mean added latency over the direct path "
                         f"{st.mean(d['delta_ms'] for d in ds):.2f} ms; best fit theta={best[1]}, pi={best[2]:.2f} ms "
                         f"(RMSE {math.sqrt(best[0] / len(ds)):.2f} ms)")

    text = "\n".join(lines)
    print(text)
    open(os.path.join(a.outdir, "model_vs_testbed_stats.txt"), "w").write(text + "\n")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(5.2, 5))
        for su in sorted({t["suite"] for t in direct}):
            rs = [t for t in direct if t["suite"] == su]
            ax.scatter([t["excess_ms"] for t in rs], [t["model_ms"] for t in rs], s=10, label=su, alpha=0.7)
        lim = [1, max(max(t["excess_ms"], t["model_ms"]) for t in direct) * 1.2]
        ax.plot(lim, lim, "k--", lw=0.8)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("measured excess latency (ms)")
        ax.set_ylabel("model T - T_cpu (ms)")
        ax.legend(fontsize=6)
        fig.tight_layout()
        fig.savefig(os.path.join(a.outdir, "model_vs_testbed.png"), dpi=200)
    except Exception as e:                                # matplotlib is optional
        print("(no plot:", e, ")")


if __name__ == "__main__":
    main()
