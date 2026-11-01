#!/usr/bin/env bash
# Paper 2, WP5, stage E: the server's window for the response after an acknowledged ticket. Predictions fixed in advance (nst_predict_e.py).
#   python3 nst_predict_e.py   (done once; commit results/nst_predictions_e.csv BEFORE measuring)
#   sudo ./host_tune.sh on; sudo bash run_nst_e.sh; sudo ./host_tune.sh off        (about 45 minutes; resumable)
#   python3 analyze_resume.py --out results/resume_summary_nst_e_tls.csv results/nst_e_tls.csv     # --out is REQUIRED (it overwrites results/resume_summary.csv otherwise)
#   python3 analyze_nst_e.py
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -s results/nst_predictions_e.csv ] || { echo "run 'python3 nst_predict_e.py' first and commit its output BEFORE measuring"; exit 1; }
SUITES="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768,ML-DSA-87|ML-KEM-1024"
for REQ in 302 19460; do
  for k in 10 11 12 13 14 15 16 17 18; do
    RESP=$(( k*1440 - 700 ))
    $PY run_testbed.py --profile core --resume --suites "$SUITES" --depths 2 --rtts 100 --rates 100 --mtus 1500 --icws 10 \
        --req $REQ --resp $RESP --n 30 --out results/nst_e_tls.csv
  done
done
echo "done."
