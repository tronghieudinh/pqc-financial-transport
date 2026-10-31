#!/usr/bin/env bash
# Measure per-operation CPU cost on a performance core (X925, cpu 19) and an efficiency core (A725, cpu 4).
set -euo pipefail
cd "$(dirname "$0")"
export LD_LIBRARY_PATH=$HOME/opt/openssl-3.5/lib
OQS=$HOME/opt/src/liboqs/build/tests/speed_sig
mkdir -p data
{
  echo "date: $(date -Is)"; echo "host: $(uname -srm)"; lscpu | grep -E "Model name|CPU max MHz"
  echo "openssl: $(LD_LIBRARY_PATH=$LD_LIBRARY_PATH $HOME/opt/openssl-3.5/bin/openssl version)"
  echo "liboqs: 0.14.0 (NEON)"; echo "load before: $(cut -d' ' -f1-3 /proc/loadavg)"
} > data/env.txt
for core in 19 4; do
  taskset -c $core ./bench_pqc 0.5 7 > data/cpu_openssl_core$core.csv
  echo "alg,op,median_us,min_us,max_us,iters" > data/cpu_liboqs_core$core.csv
  for alg in Falcon-padded-512 Falcon-padded-1024 ML-DSA-65; do
    for rep in 1 2 3; do
      taskset -c $core $OQS -d 2 $alg | awk -v a=$alg -F'|' '/^(keypair|sign|verify) /{gsub(/ /,"",$1); gsub(/ /,"",$4); gsub(/ /,"",$2); print a","$1","$4","$4","$4","$2}'
    done >> data/cpu_liboqs_core$core.csv
  done
done
echo "load after: $(cut -d' ' -f1-3 /proc/loadavg)" >> data/env.txt
echo BENCH_DONE
