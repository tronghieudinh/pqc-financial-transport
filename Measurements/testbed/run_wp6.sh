#!/usr/bin/env bash
# Paper 2, WP6: further measurement scenarios (one script, one scenario per call; all resumable). Needs sudo for the namespace scenarios.
#   python3 wp6_predict.py        # ONCE; commit and push results/wp6_pred_*.csv BEFORE measuring (it refuses to overwrite)
#   sudo ./host_tune.sh on
#   sudo bash run_wp6.sh <scenario>        scenario =
#     trace      B1 + B11 + B5   tcp_probe and pcap traces: server window in resumed transactions, full handshake with ticket, MTU 9000   (~45 min)
#     gen        B3   ticket rule and server window across RTT 5/30, 10 Mbit/s, MTU 1280/9000, with early-ticket predictions                  (~2 h)
#     clientalg  B9   client certificate of another algorithm than the server's (mixed chains)                                                (~40 min)
#     servonly   B10  server authentication only (no client certificate, small ticket)                                                         (~30 min)
#     loss       B2   packet loss with full AND resumed transactions, N transactions per configuration (default 300)                          (~2.7 h; N=500 about 4.5 h)
#     kernel     B6   plain-TCP stages A+B and TLS stage C again, output tagged with `uname -r` (run it on another kernel)                      (~1.2 h)
#     latency    B4   latency under load: Poisson arrivals at 50/80/95% of capacity (no sudo; loopback)                                        (~1 h)
#     capacity   B7+B8 capacity repeated 5 times, and a perf profile of the server per library (no sudo for the first, perf may need root)     (~1 h)
#   sudo ./host_tune.sh off
# Then: python3 analyze_wp6.py <scenario>      (it prints what each scenario answers; see README, section WP6)
# Not prepared (they need other servers or hardware): QUIC (B12), other TLS libraries (B13), two machines over a real NIC (B14).
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
S=${1:-}
[ -n "$S" ] || { sed -n 2,19p "$0"; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }; }
need_pred() { [ -s "results/$1" ] || { echo "run 'python3 wp6_predict.py' first and commit results/wp6_pred_*.csv BEFORE measuring"; exit 1; }; }
SU3="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768"
rb() { echo $(( $1 * ($2 - 60) - 700 )); }          # response bytes for k segments at an MTU
case "$S" in
trace)
  need_root
  $PY trace_run.py window --n 8
  $PY trace_run.py fullticket --n 8
  $PY run_slack.py --stage A --configs mtu9000 --trace --trace-configs mtu9000 --out results/slack_tcp_trace.csv
  echo "done: python3 analyze_trace.py results/trace_window/*.trace.txt ; python3 pcap_summary.py results/trace_fullticket/<tag>.pcap --conn 0 ; python3 analyze_trace.py results/slack_trace_mtu9000.txt --port 4500" ;;
gen)
  need_root; need_pred wp6_pred_gen.csv
  # net: rtt rate mtu
  for NET in "5 100 1500" "30 100 1500" "100 10 1500" "100 100 1280" "100 100 9000"; do
    set -- $NET; RTT=$1; RATE=$2; MTU=$3
    for REQ in 302 19460; do for K in 9 10 11 12 13 14 15 16; do
      $PY run_testbed.py --profile core --resume --suites "$SU3" --depths 2 --rtts $RTT --rates $RATE --mtus $MTU --icws 10 \
          --req $REQ --resp $(rb $K $MTU) --n 20 --out results/wp6_gen_tls.csv
    done; done
  done
  echo "done: $PY analyze_resume.py --out results/resume_summary_wp6_gen.csv results/wp6_gen_tls.csv ; python3 analyze_wp6.py gen" ;;
servonly)
  need_root; need_pred wp6_pred_servonly.csv
  for REQ in 302 19460; do for K in 9 10 11 12 13 14 15 16; do
    $PY run_testbed.py --profile core --resume --mtls 0 --suites "$SU3" --depths 2 --rtts 30 --rates 100 --mtus 1500 --icws 10 \
        --req $REQ --resp $(rb $K 1500) --n 20 --out results/wp6_servonly_tls.csv
  done; done
  echo "done: $PY analyze_resume.py --out results/resume_summary_wp6_servonly.csv results/wp6_servonly_tls.csv ; python3 analyze_wp6.py servonly" ;;
clientalg)
  need_root; need_pred wp6_pred_clientalg.csv
  for PAIR in "ML-DSA-65|ML-KEM-768 ECDSA-P256 srv65_cliECDSA" "ECDSA-P256|X25519 ML-DSA-65 srvECDSA_cli65" "ML-DSA-44|ML-KEM-768 ML-DSA-65 srv44_cli65" "ML-DSA-65|ML-KEM-768 ML-DSA-44 srv65_cli44"; do
    set -- $PAIR; SUITE=$1; CLI=$2; TAG=$3
    for K in 9 10 11 12 13 14 15 16 17 18; do
      $PY run_testbed.py --profile core --resume --suites "$SUITE" --client-alg "$CLI" --depths 2 --rtts 100 --rates 100 --mtus 1500 --icws 10 \
          --req 19460 --resp $(rb $K 1500) --n 20 --out results/wp6_clientalg_${TAG}.csv
    done
    $PY analyze_resume.py --out results/resume_summary_wp6_clientalg_${TAG}.csv results/wp6_clientalg_${TAG}.csv >/dev/null || true
  done
  echo "done: python3 analyze_wp6.py clientalg" ;;
loss)
  need_root; need_pred wp6_pred_loss.csv
  N=${N:-300}
  $PY run_testbed.py --profile loss --suites "ECDSA-P256|X25519,ML-DSA-65|ML-KEM-768" --depths 3 --rtts 30,100 --losses 0,0.5,1,2 --n $N --out results/wp6_loss_full.csv
  $PY run_testbed.py --profile loss --resume --suites "ECDSA-P256|X25519,ML-DSA-65|ML-KEM-768" --depths 3 --rtts 30,100 --losses 0,0.5,1,2 --n $N --out results/wp6_loss_resumed.csv
  echo "done: python3 analyze_loss.py results/wp6_loss_full.csv --out results/wp6_loss_full_summary.csv ; python3 analyze_loss.py results/wp6_loss_resumed.csv --resume --out results/wp6_loss_resumed_summary.csv" ;;
kernel)
  need_root
  K=$(uname -r)
  $PY run_slack.py --stage A,B --out results/slack_tcp_${K}.csv
  for K2 in 9 10 11 12 13 14 15; do
    REQ=$(( (K2-1)*1440 - 700 ))
    $PY run_testbed.py --profile core --resume --suites "ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768,ML-DSA-87|ML-KEM-1024" --depths 2 --rtts 100 --rates 100 --mtus 1500 --icws 10 \
        --req $REQ --resp 222 --n 30 --out results/slack_tls_${K}.csv
  done
  echo "done: python3 analyze_slack.py --tcp results/slack_tcp_${K}.csv ; compare with the run on kernel $(echo 7.0.0-42-generic)" ;;
latency)
  $PY capacity_latency.py --out results/wp6_latency_load_$(hostname).csv ${SERVER_CPUS:+--server-cpus $SERVER_CPUS --client-cpus $CLIENT_CPUS}
  echo "done: python3 analyze_wp6.py latency" ;;
capacity)
  M=$(hostname)
  for I in 1 2 3 4 5; do
    $PY capacity_test.py --machine "$M" --out results/wp6_capacity_repeat_${M}_${I}.csv --suites "ECDSA-P256|X25519,ML-DSA-65|ML-KEM-768" --depths 2 --mtls 0,1 --resume 0 --server-cores 1 --time 6 --warmup 2 \
        ${SERVER_CPUS:+--server-cpus $SERVER_CPUS --client-cpus $CLIENT_CPUS}
  done
  $PY perf_capacity.py --out results/wp6_perf_${M}.txt ${SERVER_CPUS:+--server-cpu ${SERVER_CPUS%%,*} --client-cpus $CLIENT_CPUS} || echo "perf profile skipped (see message)"
  echo "done: python3 analyze_wp6.py capacity" ;;
*) echo "unknown scenario $S"; exit 1 ;;
esac
