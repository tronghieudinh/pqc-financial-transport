#!/usr/bin/env bash
# Per-operation CPU cost on the x86 testbed machine, same method as ../run_bench.sh (Arm):
#   OpenSSL 3.5 EVP (RSA-PSS, ECDSA, X25519, P-256, ML-KEM, ML-DSA, SLH-DSA) with ../bench_pqc, one pinned core,
#   median of 7 x 0.5 s; liboqs speed_sig for Falcon (and ML-DSA-65 as a cross-check), 3 repetitions.
#
#   sudo ../testbed/host_tune.sh on      # performance governor, no turbo (restore with "off" afterwards)
#   ./run_bench_x86.sh [cpu]             # default: the first logical CPU; nothing else may run meanwhile
set -euo pipefail
cd "$(dirname "$0")"
PREFIX=${PQC_OPENSSL:-$HOME/opt/openssl-3.5}
export LD_LIBRARY_PATH=$PREFIX/lib
OQS=${OQS:-$HOME/opt/src/liboqs/build/tests/speed_sig}
CPU=${1:-0}
mkdir -p data
gcc -O2 -o ../bench_pqc_x86 ../bench_pqc.c -I"$PREFIX/include" -L"$PREFIX/lib" -lcrypto -Wl,-rpath,"$PREFIX/lib"
gov=$(cat /sys/devices/system/cpu/cpu$CPU/cpufreq/scaling_governor 2>/dev/null || echo n/a)
turbo=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)
[ "$gov" = performance ] || echo "WARNING: governor is '$gov' (run ../testbed/host_tune.sh on as root first)"
[ "$turbo" = 1 ] || echo "WARNING: turbo is enabled (no_turbo=$turbo): timings will vary"
{
  echo "date: $(date -Is)"; echo "host: $(uname -srm)"; lscpu | grep -E "Model name|CPU max MHz|CPU min MHz|Thread|Core|Flags" | sed 's/Flags:.*\(avx[^ ]*\).*/Flags: (avx present)/'
  grep -o -w -E "avx2|avx512f|sha_ni|aes|bmi2|adx" /proc/cpuinfo | sort -u | tr '\n' ' ' | sed 's/^/isa: /'; echo
  echo "openssl: $("$PREFIX/bin/openssl" version)"
  echo "liboqs: ${OQS_VER:-0.14.0} (x86, runtime CPU dispatch)"; echo "pinned cpu: $CPU"
  echo "governor: $gov  no_turbo: $turbo"; echo "load before: $(cut -d' ' -f1-3 /proc/loadavg)"
} > data/env_x86.txt
taskset -c "$CPU" ../bench_pqc_x86 0.5 7 > data/cpu_openssl_x86.csv
echo "alg,op,median_us,min_us,max_us,iters" > data/cpu_liboqs_x86.csv
if [ -x "$OQS" ]; then
  for alg in Falcon-padded-512 Falcon-padded-1024 ML-DSA-65; do
    for rep in 1 2 3; do
      taskset -c "$CPU" "$OQS" -d 2 $alg | awk -v a=$alg -F'|' '/^(keypair|sign|verify) /{gsub(/ /,"",$1); gsub(/ /,"",$4); gsub(/ /,"",$2); print a","$1","$4","$4","$4","$2}'
    done >> data/cpu_liboqs_x86.csv
  done
else
  echo "WARNING: $OQS not found: Falcon rows missing (run ./build_liboqs.sh)"
fi
echo "load after: $(cut -d' ' -f1-3 /proc/loadavg)" >> data/env_x86.txt
echo X86_BENCH_DONE
