#!/usr/bin/env python3
"""
write_pattern_sensitivity.py - how much do the results depend on the way the TLS library writes handshake data? (Paper 1, Supplementary Appendix SK)

    python3 write_pattern_sensitivity.py [--out results/write_pattern_sensitivity.csv] [--tex ../paper1/Latex/tables/tab_writes.tex]

The validated model writes handshake messages through a 4,096-byte buffer (OpenSSL 3.5.4, checked with strace). This script replaces that
write pattern by others and reports, with nothing fitted and no new measurement:
  (a) the stack-model error on the 226 validation configurations of the testbed (an alternative pattern is expected to fit worse, because the data follow 4,096 bytes),
  (b) the number of those configurations whose predicted excess latency changes by more than 0.4 RTT against the validated model (the exposure of the grid to the pattern),
  (c) the modelled SWIFT MX depth effect (ML-DSA-65 and ECDSA-P256 baseline, depth 1 to 4 at both endpoints, 100 Mbit/s, MTU 1,500).
Patterns: buffer of 4,096 (validated), 2,048, 8,192 and 16,384 bytes; one write per flight (a very large buffer); ideal segmentation (bytes / MSS, no write boundaries).
All rows keep Linux window validation.
"""
import argparse, csv, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "Measurements", "testbed"))
import pqc_sim as S           # noqa: E402
import analyze_testbed as A   # noqa: E402

PATTERNS = [("buffer 4096 (validated)", 4096, "openssl"), ("buffer 2048", 2048, "openssl"), ("buffer 8192", 8192, "openssl"),
            ("buffer 16384", 16384, "openssl"), ("one write per flight", 10 ** 9, "openssl"), ("ideal segmentation", 4096, "ideal")]


def swift(suite, depth, rtt, seg):
    fl = S.build_flow(suite, "SWIFT_MX", depth, "cold", False)
    return S.run_flow(fl, S.Net(100, rtt, 1500, segmentation=seg))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(HERE, "..", "paper1", "Latex", "data", "testbed_configurations.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "results", "write_pattern_sensitivity.csv"))
    ap.add_argument("--tex", default=os.path.join(HERE, "..", "paper1", "Latex", "tables", "tab_writes.tex"))
    a = ap.parse_args()
    cfg = list(csv.DictReader(open(a.csv)))
    base_pred = None
    rows = []
    for name, size, seg in PATTERNS:
        S.bio_buffer.__defaults__ = (size,); S.build_flow.cache_clear()
        pred, err = [], []
        for c in cfg:
            _, m = A.model_for(c, cwnd_validation=True, segmentation=seg)
            p = m["total"] - m["cpu"]; pred.append(p); err.append(p - float(c["excess_ms"]))
        if base_pred is None: base_pred = pred
        rtt = [float(c["rtt_ms"]) for c in cfg]
        changed = sum(abs(p - q) > 0.4 * r for p, q, r in zip(pred, base_pred, rtt))
        over = sum(abs(e) > 0.4 * r for e, r in zip(err, rtt))
        d = {}
        for suite, tag in (("ML-DSA-65|ML-KEM-768", "mldsa"), ("ECDSA-P256|X25519", "ecdsa")):
            for rt in (30, 100):
                d[f"{tag}_{rt}"] = swift(suite, 4, rt, seg)["total"] - swift(suite, 1, rt, seg)["total"]
        rows.append(dict(pattern=name, mae=st.mean(abs(e) for e in err), over04=over, changed=changed, **d))
    S.bio_buffer.__defaults__ = (4096,); S.build_flow.cache_clear()
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); [w.writerow({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()}) for r in rows]
    for r in rows: print({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()})
    L = [r"\begin{tabular}{@{}lrrrrrr@{}}", r"\toprule",
         r"Write pattern & \shortstack[r]{MAE\\(ms)} & \shortstack[r]{Errors\\$>0.4$ RTT} & \shortstack[r]{Changed\\$>0.4$ RTT} & \shortstack[r]{ML-DSA-65\\30\ms} & \shortstack[r]{ML-DSA-65\\100\ms} & \shortstack[r]{ECDSA-P256\\30\ms} \\", r"\midrule"]
    for r in rows:
        L.append(f'{r["pattern"]} & {r["mae"]:.2f} & {r["over04"]} & {r["changed"]} & {r["mldsa_30"]:.1f} & {r["mldsa_100"]:.1f} & {r["ecdsa_30"]:.1f} \\\\')
    L += [r"\bottomrule", r"\end{tabular}"]
    os.makedirs(os.path.dirname(a.tex), exist_ok=True); open(a.tex, "w").write("\n".join(L) + "\n")

if __name__ == "__main__":
    main()
