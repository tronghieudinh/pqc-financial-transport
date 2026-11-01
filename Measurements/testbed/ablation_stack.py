#!/usr/bin/env python3
"""
ablation_stack.py - contribution of each stack mechanism to the accuracy of the model (Paper 1, reviewer comment on ablation).

    python3 ablation_stack.py [--csv ../../manuscript/data/testbed_configurations.csv] [--out results/ablation_stack.csv]

For the 226 validation configurations, predicts the excess latency with the four combinations of the two mechanisms:
  none        Linux window rule off, ideal segmentation (the closed form of the idealised model)
  window      Linux window validation only
  writes      OpenSSL write boundaries only
  both        window validation + OpenSSL write boundaries (the model of the paper)
and reports MAE, bias, maximum error and the number of configurations whose error exceeds 0.4 RTT. Nothing is fitted.
"""
import argparse, csv, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze_testbed as A  # noqa: E402

VARIANTS = [("none", dict(cwnd_validation=False, segmentation="ideal")), ("window", dict(cwnd_validation=True, segmentation="ideal")),
            ("writes", dict(cwnd_validation=False, segmentation="openssl")), ("both", dict(cwnd_validation=True, segmentation="openssl"))]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(HERE, "..", "..", "manuscript", "data", "testbed_configurations.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "results", "ablation_stack.csv"))
    a = ap.parse_args()
    rows = list(csv.DictReader(open(a.csv)))
    res = {n: [] for n, _ in VARIANTS}
    for c in rows:
        ex = float(c["excess_ms"]); rtt = float(c["rtt_ms"])
        for n, kw in VARIANTS:
            _, m = A.model_for(c, **kw)
            res[n].append((m["total"] - m["cpu"] - ex, rtt))
    out = [["variant", "n", "mae_ms", "bias_ms", "max_abs_ms", "over_0.4rtt"]]
    for n, _ in VARIANTS:
        e = [x for x, _ in res[n]]
        out.append([n, len(e), round(st.mean(abs(x) for x in e), 2), round(st.mean(e), 2), round(max(abs(x) for x in e), 1),
                    sum(abs(x) > 0.4 * r for x, r in res[n])])
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    csv.writer(open(a.out, "w", newline="")).writerows(out)
    for r in out: print(*r, sep="\t")

if __name__ == "__main__":
    main()
