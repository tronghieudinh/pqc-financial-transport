#!/usr/bin/env bash
# Server capacity (paper 2, WP2): handshakes per second and CPU per handshake of an event-driven TLS 1.3 server (tls_serve), loopback,
# against the sum of the measured primitive costs. No root and no network namespaces needed (loopback; the clients run on other cores).
#   cd Paper/v5/Measurements/testbed
#   ./setup_host.sh                       # builds tls_probe, tls_serve, tls_load; generates certificates (../certs.sh)
#   sudo ./host_tune.sh on                # optional but recommended: performance governor, no turbo (as for the other runs)
#   bash run_capacity.sh                  # Linux Mint i7-5600U: about 15 minutes
#   python3 analyze_capacity.py results/capacity_$(hostname).csv --costs x86
# Arm test platform (NVIDIA GX10; X925 cores 16-19 for the server, the clients on the other X925 cores):
#   SERVER_CPUS=18 CLIENT_CPUS=5,6,7,8,9,15 bash run_capacity.sh                     # then, for the scaling runs:
#   SCALING=1 SERVER_CPUS=16,17,18,19 CLIENT_CPUS=5,6,7,8,9,10,11,12,13,14,15 bash run_capacity.sh
# Check the util column: below about 0.9 the load generator, not the server, limited the rate (the i7-5600U has two physical cores,
# so the server gets one and the clients the other: expect the clients to limit the post-quantum-free, fast suites).
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
M=${MACHINE:-$(hostname)}
args=(--machine "$M")
[ -n "${SERVER_CPUS:-}" ] && args+=(--server-cpus "$SERVER_CPUS" --client-cpus "$CLIENT_CPUS")
if [ -n "${SCALING:-}" ]; then   # multi-core scaling of the saturated server (needs enough cores for the clients)
  $PY capacity_test.py "${args[@]}" --out "results/capacity_${M}_scaling.csv" --suites "ECDSA-P256|X25519,ML-DSA-65|ML-KEM-768" \
      --depths 1 --mtls 1 --resume 0 --server-cores 1,2,4 --time 6 --warmup 2
else                             # one server core: every suite, chain depth 1-4, server authentication and mutual TLS, full and resumed
  $PY capacity_test.py "${args[@]}" --out "results/capacity_${M}.csv" --server-cores 1 --time 6 --warmup 2
fi
echo "done. Commit results/capacity_*.csv, then: python3 analyze_capacity.py results/capacity_${M}.csv --costs x86   (or x925 on the Arm platform)"
