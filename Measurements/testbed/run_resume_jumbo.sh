#!/usr/bin/env bash
# Session resumption at MTU 9000 and a test of a specific prediction (paper 2, WP1; supplement to run_resume.sh, which covers MTU 1280 and
# 1500). Separate output files: the results of run_resume.sh are not touched.
# Pass 3 tests a prediction that can be refuted: for a 14.5-KB request and a 12.1-KB response (the sizes of the ISO 20022 flow) the model says
# that ML-DSA-44 resumed is SLOWER than a full handshake at MTU 1500 (+28 ms at 30 ms RTT, +98 ms at 100 ms), because the fresh session
# ticket (it embeds the client certificate, about 5 KB) joins the response and takes the server flight from 9 to 12 segments, beyond the
# initial window of 10; ML-DSA-65 at the same sizes is faster resumed, and at MTU 9000 the effect disappears.
#   cd Paper/v5/Measurements/testbed
#   sudo ./host_tune.sh on
#   sudo bash run_resume_jumbo.sh        # about 35 minutes; resumable
#   sudo ./host_tune.sh off
#   python3 analyze_resume.py results/resume.csv results/resume_swift.csv results/resume_9000.csv results/resume_swift_9000.csv results/resume_iso20022.csv
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -x ./tls_probe ] || { echo "tls_probe not built: run ./setup_host.sh"; exit 1; }
grep -q resume tls_probe.c || { echo "tls_probe.c has no --resume: pull the latest version"; exit 1; }
# 1. ISO 8583-sized transaction, six suites, chain depth 1 and 3, MTU 9000
$PY run_testbed.py --profile core --resume --depths 1,3 --rtts 5,30,100 --rates 100 --mtus 9000 --icws 10 --n 30 --out results/resume_9000.csv
# 2. SWIFT-sized transaction (10.9 KB / 3.6 KB), three suites, MTU 9000
$PY run_testbed.py --profile core --resume --suites "ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768" --depths 1,3 \
    --rtts 30,100 --rates 100 --mtus 9000 --icws 10 --req 10900 --resp 3600 --n 30 --out results/resume_swift_9000.csv
# 3. ISO 20022-sized transaction (14.5 KB request, 12.1 KB response), depth 2, MTU 1500 and 9000: the prediction above
$PY run_testbed.py --profile core --resume --suites "ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768" --depths 2 \
    --rtts 30,100 --rates 100 --mtus 1500,9000 --icws 10 --req 14500 --resp 12100 --n 40 --out results/resume_iso20022.csv
echo "done. Commit results/resume_*9000.csv and results/resume_iso20022.csv, then analyze_resume.py with all five files (see the header of this script)"
