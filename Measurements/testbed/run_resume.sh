#!/usr/bin/env bash
# TLS 1.3 session resumption on the testbed (paper 2, WP1): resumed transactions measured against the stack model and against the full
# handshake. Same machine, governor and pinning as the earlier runs.
#   cd Paper/v5/Measurements/testbed
#   ./setup_host.sh                  # once, and again after pulling: rebuilds tls_probe, which now has --resume
#   sudo ./host_tune.sh on
#   sudo bash run_resume.sh          # about an hour; resumable (run it again if interrupted)
#   sudo ./host_tune.sh off
#   python3 analyze_resume.py results/resume.csv results/resume_swift.csv      # no root
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -x ./tls_probe ] || { echo "tls_probe not built: run ./setup_host.sh"; exit 1; }
./tls_probe client --help >/dev/null 2>&1 || true
grep -q resume tls_probe.c || { echo "tls_probe.c has no --resume: pull the latest version"; exit 1; }
# 1. ISO 8583-sized transaction (302 / 222 B), the six suites of paper 1, chain depth 1 and 3 (under mutual TLS the ticket carries the client leaf)
$PY run_testbed.py --profile core --resume --depths 1,3 --rtts 5,30,100 --rates 100 --mtus 1280,1500 --icws 10 --n 30 --out results/resume.csv
# 2. SWIFT-sized transaction (10.9 KB / 3.6 KB): large messages are where the earlier model changed most
$PY run_testbed.py --profile core --resume --suites "ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768" --depths 1,3 \
    --rtts 30,100 --rates 100 --mtus 1500 --icws 10 --req 10900 --resp 3600 --n 30 --out results/resume_swift.csv
echo "done. Commit results/resume*.csv, then:  python3 analyze_resume.py results/resume.csv results/resume_swift.csv"
