#!/usr/bin/env bash
# Extra testbed runs for the revision of paper 1: other TCP settings than Reno + quick ACK + no timestamps.
#   cd Paper/v5/Measurements/testbed && sudo bash run_variants.sh        # about 2 hours; add BBR=1 to include the exploratory BBR runs
#   sudo bash run_variants.sh cubic2 delack ts delack_ts                 # only some of them (any of: cubic2 delack ts delack_ts bbr)
# Same machine, governor and pinning as before (sudo ./host_tune.sh on first, as for the earlier runs, and off afterwards). Results go to results/*.csv (resumable:
# run the same command again if it is interrupted). Afterwards (no root needed):  python3 analyze_variants.py
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
S3="ECDSA-P256|X25519,ML-DSA-65|ML-KEM-768,ML-DSA-87|ML-KEM-1024"
want=("$@"); [ ${#want[@]} -eq 0 ] && want=(cubic2 delack ts delack_ts); [ "${BBR:-0}" = 1 ] && want+=(bbr)
has() { for w in "${want[@]}"; do [ "$w" = "$1" ] && return 0; done; return 1; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -x ./tls_probe ] || { echo "tls_probe not built: run setup_host.sh first"; exit 1; }
# the variants share one configuration grid: the core grid (100 Mbit/s, initial window 10) at MTU 1280 and 1500, so that every
# configuration has a Reno measurement to be paired with
GRID=(--profile core --suites "$S3" --depths 1,2,3,4 --rtts 5,30,100 --rates 100 --mtus 1280,1500 --icws 10 --n 30)

if has cubic2; then   # CUBIC over a wider grid than before (5, 30, 100 ms; MTU 1280, 1500, 9000; initial window 10 and 32)
  $PY run_testbed.py --profile core --suites "$S3" --depths 1,2,3,4 --rtts 5,30,100 --rates 100 --mtus 1280,1500,9000 --icws 10,32 --n 20 \
      --cc cubic --out results/cubic2.csv
fi
has delack    && $PY run_testbed.py "${GRID[@]}" --delack --out results/delack.csv
has ts        && $PY run_testbed.py "${GRID[@]}" --timestamps --out results/ts.csv
has delack_ts && $PY run_testbed.py "${GRID[@]}" --delack --timestamps --out results/delack_ts.csv
if has bbr; then      # BBR paces and does not follow the slow-start clock of the model: reported as a limit of the model, not as validation
  modprobe tcp_bbr 2>/dev/null || true
  $PY run_testbed.py --profile core --suites "ECDSA-P256|X25519,ML-DSA-65|ML-KEM-768" --depths 1,3 --rtts 30,100 --rates 100 --mtus 1500 \
      --icws 10 --n 30 --cc bbr --out results/bbr.csv
fi
echo "done. Commit results/*.csv, then:  python3 analyze_variants.py"
