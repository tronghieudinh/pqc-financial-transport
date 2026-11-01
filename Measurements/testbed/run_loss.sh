#!/usr/bin/env bash
# Packet loss on the testbed (paper 2, WP4): the `loss` profile of run_testbed.py (ECDSA-P256, ML-DSA-44, ML-DSA-65; chain depth 2 and 3;
# 30 ms RTT, 100 Mbit/s, MTU 1500; netem loss of 0, 0.1, 0.5, 1 and 2 %; 200 transactions per configuration), against the lossy stack model.
#   cd Paper/v5/Measurements/testbed
#   sudo ./host_tune.sh on
#   sudo bash run_loss.sh              # about 45 minutes; resumable
#   sudo ./host_tune.sh off
#   python3 analyze_loss.py results/loss.csv
# Each loss rate sees the same TCP settings as the earlier runs (Reno, quick ACKs, no timestamps). netem loses packets at random; the
# retransmission counters (TCP_INFO) give the number of retransmissions per transaction, compared with the model's.
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -x ./tls_probe ] || { echo "tls_probe not built: run ./setup_host.sh"; exit 1; }
$PY run_testbed.py --profile loss --n 200 --out results/loss.csv
echo "done. Commit results/loss.csv, then: python3 analyze_loss.py results/loss.csv"
