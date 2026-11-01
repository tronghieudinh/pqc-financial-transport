#!/usr/bin/env bash
# Paper 2, WP6 B4 repeat: latency of RESUMED transactions under load, now with one single-use ticket per connection (tls_load_open --pool).
# The first run (results/wp6_latency_load_X250.csv, resume=1 rows) failed in 13-45 % of the connections (not_resumed, then socket errors) and is not usable.
#   cd Paper/v5/Measurements/testbed && sudo --preserve-env=SSH_AUTH_SOCK bash run_latency_resumed.sh        # about 25 min; the machine must be idle
# What it does: rebuilds tls_load_open (it is NOT rebuilt by run_all_wp6.sh when the binary exists), widens the ephemeral port range and enables
# tcp_tw_reuse for the loopback (restored on exit: about 1,300 new connections per second exhaust the default range), sets host_tune on (stops if the clock is
# not fixed), runs capacity_latency.py for resume=1 only (mutual TLS, depth 2, the three suites, 50/80/95 % of capacity) into
# results/wp6_latency_load_resumed_<host>.csv, analyses it (results/wp6_analysis_latency_resumed.txt), commits and pushes as you. Resumable (rows already in the CSV are skipped).
set -uo pipefail
cd "$(dirname "$0")"
HERE=$PWD; PY=${PY:-python3}
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo --preserve-env=SSH_AUTH_SOCK bash run_latency_resumed.sh"; exit 1; }
U=${SUDO_USER:?run through sudo from your normal user}
if [ -z "${LR_INHIBITED:-}" ] && command -v systemd-inhibit >/dev/null; then exec env LR_INHIBITED=1 systemd-inhibit --what=sleep:idle:handle-lid-switch --who=latency --why="resumed latency under load" bash "$0" "$@"; fi
as_user() { sudo -u "$U" -H env ${SSH_AUTH_SOCK:+SSH_AUTH_SOCK="$SSH_AUTH_SOCK"} "$@"; }
ROOT=$(as_user git -C "$HERE" rev-parse --show-toplevel)
mkdir -p results; chown "$U" results
LOG=results/latency_resumed_run.log
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
log "load average: $(cut -d' ' -f1-3 /proc/loadavg)"
P=$(as_user bash -c 'echo ${PQC_OPENSSL:-$HOME/opt/openssl-3.5}')
as_user gcc -O2 -Wall -pthread -o tls_load_open tls_load_open.c -I"$P/include" -L"$P/lib" -lssl -lcrypto -lm -Wl,-rpath,"$P/lib" || { log "ERROR: tls_load_open did not build"; exit 1; }
log "tls_load_open rebuilt (with --pool)"
OLD_RANGE=$(cat /proc/sys/net/ipv4/ip_local_port_range); OLD_TW=$(cat /proc/sys/net/ipv4/tcp_tw_reuse)
sysctl -qw net.ipv4.ip_local_port_range="10240 65000"; sysctl -qw net.ipv4.tcp_tw_reuse=1
restore() { ./host_tune.sh off >>"$LOG" 2>&1; sysctl -qw net.ipv4.ip_local_port_range="$OLD_RANGE"; sysctl -qw net.ipv4.tcp_tw_reuse="$OLD_TW"; chown -R "$U" results; log "restored host tuning and sysctl"; }
trap restore EXIT
./host_tune.sh on >>"$LOG" 2>&1
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor); nt=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)
[ "$gov" = performance ] && [ "$nt" = 1 ] || { log "ERROR: clock not fixed (governor=$gov no_turbo=$nt)"; exit 1; }
OUT=results/wp6_latency_load_resumed_$(hostname).csv
as_user bash -c "$PY capacity_latency.py --out $OUT --resume 1 ${SERVER_CPUS:+--server-cpus $SERVER_CPUS --client-cpus $CLIENT_CPUS}" 2>&1 | tee -a "$LOG"
{ echo "\$ $PY analyze_wp6.py latency-resumed"; as_user $PY analyze_wp6.py latency 2>&1; } > results/wp6_analysis_latency_resumed.txt
errs=$(awk -F, 'NR>1{e+=$11} END{print e+0}' "$OUT" 2>/dev/null); log "errors in $OUT (sum of the err column): $errs"
chown -R "$U" results
as_user git -C "$ROOT" add -A -- "$HERE/results" "$HERE/run_latency_resumed.sh" "$HERE/tls_load_open.c" "$HERE/capacity_latency.py" 2>>"$LOG"
as_user git -C "$ROOT" commit -q -m "Resumed latency under load with one ticket per connection: results (automatic)" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>" >>"$LOG" 2>&1 && log committed || log "nothing to commit"
for i in 1 2 3; do as_user git -C "$ROOT" pull --rebase --autostash -q >>"$LOG" 2>&1; as_user git -C "$ROOT" push -q >>"$LOG" 2>&1 && { log pushed; break; } || sleep 20; done
log "DONE"
