#!/usr/bin/env bash
# Regenerate every simulation result, table, figure and number of the paper, and build the PDFs.
#   PY=python3 bash reproduce.sh
# The testbed and x86 measurements themselves need a Linux machine with root (see Measurements/testbed/README.md and
# Measurements/x86/README.md); their raw results are included, this script only analyses them.
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
(cd Simulation && PY=$PY ./run_paper1.sh)
(cd Measurements/testbed && $PY paper_assets.py && $PY residual_analysis.py && { [ -f results/delack.csv ] && $PY analyze_variants.py || true; })
(cd Measurements/testbed && { [ -f results/resume.csv ] && $PY analyze_resume.py results/resume.csv results/resume_swift.csv results/resume_9000.csv results/resume_swift_9000.csv results/resume_iso20022.csv >/dev/null || true; } && { [ -f results/capacity_gx10.csv ] && $PY analyze_capacity.py results/capacity_gx10.csv --costs x925 >/dev/null || true; } && $PY supp_paper1_extra.py >/dev/null)
(cd Measurements/x86 && $PY analyze_cpu_x86.py)
(cd Simulation && $PY asymmetric_depth.py >/dev/null && $PY uncertainty.py --pi0 >/dev/null && $PY app_records_effect.py >/dev/null)      # v1.3: asymmetric chain depth; uncertainty analysis with the middlebox delay at 0
(cd Measurements/testbed && $PY ablation_stack.py >/dev/null)                                       # v1.3: contribution of each stack mechanism (uses manuscript/data/testbed_configurations.csv)
(cd Simulation && $PY mixed_chain.py >/dev/null)                                                         # v1.4: model-only scenario of chains with different leaf and CA algorithms (Supplementary Table SB.5)
(cd Measurements/testbed && $PY error_profile.py > results/error_profile.txt && $PY analyze_fullticket.py >/dev/null)   # v1.4: error profile numbers; negative result on the full handshake with a ticket
# ---- v1.4 (15/11/2026): analyses of the new experiments of Paper 1, from the raw files in Measurements/testbed/results/p1_v14/ (no root, no network; the measurements themselves need the machines)
# Each result file that is pure script output is regenerated and compared with the committed one (OK / DIFF); files that carry hand-written notes are only regenerated into results/reproduced_v14/.
(cd Measurements/testbed && R=results/p1_v14 && REP=results/replication && O=results/reproduced_v14 && mkdir -p $O && chk() { if cmp -s "$1" "$2"; then echo "v1.4 check OK:   $3"; else echo "v1.4 check DIFF: $3 (compare $1 with $2)"; fi; }
  { $PY analyze_baselines.py; $PY analyze_baselines.py $REP/*/model_vs_testbed.csv; } > $O/baselines.txt 2>&1;                       chk $O/baselines.txt results/baselines_20261115.txt "simpler baselines (Table: tab:baselines)"
  $PY analyze_g3b_records.py $R/g3b/* > $O/g3b_app_records.txt 2>&1;                                                            chk $O/g3b_app_records.txt results/g3b_app_records_20261115.txt "G3b with one write per TLS record (post hoc)"
  $PY analyze_dubetskyy_segments.py > $O/dubetskyy_segments.txt 2>&1;                                                           chk $O/dubetskyy_segments.txt results/dubetskyy_segments_20261116.txt "segment counts of Dubetskyy and Cano against the write pattern (post hoc)"
  $PY analyze_mldsa_sweep.py --v6 $R/mldsa_sweep_v6_gx10.csv --v4 $R/mldsa_sweep_v4_gx10.csv > $O/mldsa_sweep.txt 2>&1;           chk $O/mldsa_sweep.txt results/mldsa_d1_sweep_gx10_analysis_20261115.txt "ML-DSA-65 depth-1 sweep (S1-S3)"
  $PY analyze_records_test.py $R/records_test_gx10.csv > $O/records_test.txt 2>&1;                                               chk $O/records_test.txt results/records_test_gx10_analysis_20261115.txt "independent test of the record option (R1-R3)"
  for m in gx10 i9 x250; do $PY analyze_ipv4_offload.py --v6 $R/ipv4flip_v6_$m.csv --v4 $R/ipv4flip_v4_$m.csv > $O/ipv4_$m.txt 2>&1; done   # F1-F3 of the pre-registered IPv4 test, per machine
  $PY analyze_ipv4_offload.py --v6 $R/ipv4flip_v6_x250.csv --v4 $R/ipv4flip_v4_x250.csv --offload $R/offload_x250.csv --standard $REP/x250_*/model_vs_testbed.csv > $O/offload_x250.txt 2>&1   # OFF-1, OFF-2 (X250)
  # the pre-registered predictions are regenerated and must equal the committed files (they were committed before the measurements)
  PRE="results/ipv4_offload_predictions.csv results/ipv4_offload_predictions.md results/mldsa_d1_sweep_predictions.md results/mldsa_d1_sweep_configs.csv results/records_test_predictions.csv results/records_test_predictions.md results/records_test_configs.csv results/ipv4_flip_configs.csv results/offload_configs.csv results/prod_like_configs.csv"
  for g in $PRE; do cp "$g" "$O/before_$(basename $g)"; done
  for f in ipv4_offload_predict ml_dsa_d1_sweep_predict records_test_predict; do $PY $f.py > /dev/null; done
  for g in $PRE; do chk "$g" "$O/before_$(basename $g)" "pre-registered file $(basename $g) unchanged"; done
  $PY analyze_rtt_calibration.py $REP/x250_*/model_vs_testbed.csv --cal results/p1_v14/netem_cal/netem_cal_x250_20261115.json > $O/rtt_calibration_x250.txt 2>&1 || true )
(cd Simulation && $PY ossl41_shares.py > ../Measurements/testbed/results/reproduced_v14/ossl41_shares.txt 2>&1; cmp -s ../Measurements/testbed/results/reproduced_v14/ossl41_shares.txt ../Measurements/testbed/results/ossl41_shares_20261115.txt && echo "v1.4 check OK:   OpenSSL 4.1.0 shares (Table 5)" || echo "v1.4 check DIFF: OpenSSL 4.1.0 shares (compare reproduced_v14/ossl41_shares.txt with ossl41_shares_20261115.txt)")
# ---- end v1.4
(cd paper && rm -f des_check.json && $PY make_assets.py)
if command -v latexmk >/dev/null 2>&1; then
  (cd paper && latexmk -pdf -interaction=nonstopmode main.tex supplementary.tex)
else
  echo "latexmk not found: tables, figures and numbers were generated in paper/, the PDFs were not built"
fi
echo "done"
