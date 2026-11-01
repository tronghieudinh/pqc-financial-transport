#!/usr/bin/env bash
# Paper 2, WP5, stage C: TLS-level test of the cwnd-slack hypothesis with predictions fixed in advance (slack_predict.py).
# Resumed TLS 1.3 transactions with a small response (222 B), so that only the CLIENT's request flight can cost an extra round trip;
# the request is sized to give a Finished + request flight of 9..15 segments (MTU 1500, RTT 100 ms). Four suites have a ClientHello of
# 2, 5, 6 and 8 segments (the ticket embeds the client certificate), i.e. the window the client has when it sends the request differs.
#   sudo ./host_tune.sh on; sudo bash run_slack_tls.sh; sudo ./host_tune.sh off      (about 25 minutes; resumable)
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -s results/slack_predictions.csv ] || { echo "run 'python3 slack_predict.py' first, and commit its output BEFORE measuring"; exit 1; }
SUITES="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768,ML-DSA-87|ML-KEM-1024"
for k in 9 10 11 12 13 14 15; do
  REQ=$(( (k-1)*1440 - 700 ))
  $PY run_testbed.py --profile core --resume --suites "$SUITES" --depths 2 --rtts 100 --rates 100 --mtus 1500 --icws 10 \
      --req $REQ --resp 222 --n 30 --out results/slack_tls.csv
done
echo "done. python3 analyze_slack.py"
