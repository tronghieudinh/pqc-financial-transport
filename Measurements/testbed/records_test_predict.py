#!/usr/bin/env python3
"""records_test_predict.py - pre-registration of an independent test of the one-write-per-TLS-record option (Model(app_records=True)) on full handshakes at MTU 1500
(results/records_test_configs.csv, results/records_test_predictions.csv/.md). COMMIT AND PUSH BEFORE THE MEASUREMENT.
Why: the option was found after the G3b and ML-DSA-65 sweep data were seen (post hoc). This test uses response sizes that were not used to find it. The model with and without the option
differs by about one round trip in narrow bands of the response size (found by scanning 8 000-80 000 B in steps of 250 B): ML-DSA-65 depth 1 at 68 150-69 000 B and depth 2 at 30 800-31 600 B (the band at 22 250-22 750 B
of depth 1 was seen in the sweep and is not used). ECDSA-P256 has no such band.
Configuration of every cell: 302-byte request, mTLS, 30 ms RTT, 100 Mbit/s, MTU 1500, initial window 10, Reno, quick ACK, IPv6, n = 30; excess latency against the unshaped base as everywhere.
Cells: 8 ML-DSA-65 depth 1 (4 flip cells inside the band, 2 controls below, 2 above), 8 ML-DSA-65 depth 2 (same layout), 4 ECDSA-P256 depth 2 controls."""
import csv, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import analyze_testbed as A
S = A.S
S6, SE = "ML-DSA-65|ML-KEM-768", "ECDSA-P256|X25519"
CELLS = [(S6, 1, r) for r in (67500, 67900, 68300, 68500, 68700, 68900, 69300, 69700)] + [(S6, 2, r) for r in (30400, 30700, 31000, 31200, 31400, 31500, 31900, 32300)] + [(SE, 2, r) for r in (22500, 31200, 40000, 68700)]
def ex(suite, depth, resp, rec):
    fl = S.build_flow(suite, A.probe_protocol("1", "302", str(resp), str(depth)), depth, "cold", False, S.Model(app_records=rec))
    n = S.Net(100.0, 30.0, 1500, penalty_ms=0.0, thr=4, init_cwnd=10, cwnd_validation=True, segmentation="openssl", cwnd_slack=0, hdr=60)
    r = S.run_flow(fl, n); return r["total"] - r["cpu"]
cfg = [dict(suite=s, depth=d, mtls=1, req=302, resp=r, rtt_ms=30, rate_mbps=100, mtu=1500, icw=10, loss_pct=0, cc="reno") for s, d, r in CELLS]
w = csv.DictWriter(open(os.path.join(HERE, "results", "records_test_configs.csv"), "w", newline=""), fieldnames=list(cfg[0])); w.writeheader(); w.writerows(cfg)
rows = []
for s, d, r in CELLS:
    off, on = ex(s, d, r, False), ex(s, d, r, True)
    rows.append(dict(suite=s, depth=d, req=302, resp=r, model_off_ms=round(off, 2), model_on_ms=round(on, 2), diff_ms=round(on - off, 2), kind="flip" if abs(on - off) > 15 else "control"))
w = csv.DictWriter(open(os.path.join(HERE, "results", "records_test_predictions.csv"), "w", newline=""), fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
L = ["# One write per TLS record: pre-registered test on full handshakes at MTU 1500 (records_test_predict.py, before the measurement)", "",
     "| suite | depth | response (B) | model, one write per message (ms) | model, one write per record (ms) | difference | kind |", "|---|---|---|---|---|---|---|"]
L += [f"| {r['suite'].split('|')[0]} | {r['depth']} | {r['resp']} | {r['model_off_ms']} | {r['model_on_ms']} | {r['diff_ms']:+.1f} | {r['kind']} |" for r in rows]
nf = sum(r["kind"] == "flip" for r in rows)
L += ["", f"Flip cells: {nf} (model with records one round trip above the model without). Controls: {len(rows) - nf} (the two models agree within 1 ms).", "",
      "Criteria (scored by analyze_records_test.py):",
      f"- R1 flip cells: the measured excess is closer to the model with records than to the model without it in at least {nf - 1} of {nf}.",
      "- R2 accuracy of the model with records over all 20 cells: MAE at most 2.5 ms and no cell more than 0.4 RTT (12 ms) from it.",
      f"- R3 controls: at least {len(rows) - nf - 1} of {len(rows) - nf} within 12 ms of the model (either).",
      f"- Rejection: if the model without records is closer in 5 or more of the {nf} flip cells, the record explanation is rejected for full handshakes at MTU 1500 and the sentence of Paper 1 that offers it is withdrawn.",
      "- Machine offsets of 1 to 3 ms do not matter for R1 (the two predictions differ by 26 to 28 ms)."]
open(os.path.join(HERE, "results", "records_test_predictions.md"), "w").write("\n".join(L) + "\n"); print("\n".join(L))
