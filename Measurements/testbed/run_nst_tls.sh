#!/usr/bin/env bash
# Paper 2, WP5, stage D: is the session ticket an earlier, separate write? Predictions fixed in advance by nst_predict.py.
#   python3 nst_predict.py   (once; commit results/nst_predictions.csv BEFORE measuring)
#   sudo ./host_tune.sh on; sudo bash run_nst_tls.sh; sudo ./host_tune.sh off      (about 50 minutes; resumable)
#   python3 analyze_resume.py --out results/resume_summary_nst_tls.csv results/nst_tls.csv ; python3 analyze_nst.py
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -s results/nst_predictions.csv ] || { echo "run 'python3 nst_predict.py' first and commit its output BEFORE measuring"; exit 1; }
SUITES="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768,ML-DSA-87|ML-KEM-1024"
for REQ in 302 19460; do
  for k in 3 4 5 6 7 8 9 10 11 12; do
    RESP=$(( k*1440 - 700 ))
    $PY run_testbed.py --profile core --resume --suites "$SUITES" --depths 2 --rtts 100 --rates 100 --mtus 1500 --icws 10 \
        --req $REQ --resp $RESP --n 30 --out results/nst_tls.csv
  done
done
echo "done."
