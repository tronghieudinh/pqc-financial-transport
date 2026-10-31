#!/usr/bin/env bash
# Regenerate every wired simulation result used by the paper (about a minute on a laptop).
#   PY=python3 JOBS=8 ./run_paper1.sh
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
J=${JOBS:-8}
$PY -m unittest -q test_pqc_sim test_radio_sim test_v4_features test_v5_stack
mkdir -p results results_thr sens
echo "== main sweep (validated stack: Linux window validation + OpenSSL write pattern)"
$PY pqc_sim.py --out results --jobs "$J"
echo "== threshold sensitivity"
$PY pqc_sim.py --out results_thr --thresholds 2,4,8,16 --bandwidths 100 --rtts 30 --penalties 6 \
    --protocols SWIFT_MX --suites "ML-DSA-65|ML-KEM-768" --jobs 1
echo "== parameter sensitivity"
$PY pqc_sim.py --out sens/nocert --no-xmldsig-cert --jobs "$J"
$PY pqc_sim.py --out sens/meta_small --leaf-meta 600 --ca-meta 350 --jobs "$J"
$PY pqc_sim.py --out sens/meta_large --leaf-meta 1400 --ca-meta 800 --jobs "$J"
$PY pqc_sim.py --out sens/cwnd_busy --warm-cwnd 64 --jobs "$J"
$PY pqc_sim.py --out sens/cwnd32 --init-cwnd 32 --warm-cwnd 32 --jobs "$J"
echo "== idealised closed form (ideal segmentation, window += every flight) for comparison"
$PY pqc_sim.py --out sens/v4stack --stack v4 --jobs "$J"
echo "== independent event-driven cross-check"
$PY crosscheck_simpy.py --full --jobs "$J"
$PY crosscheck_simpy.py --samples 20000 --stack v4 --jobs "$J"
echo "== sensitivity indices and parameter uncertainty"
$PY global_sensitivity.py
$PY uncertainty.py
echo RUN_PAPER1_DONE
