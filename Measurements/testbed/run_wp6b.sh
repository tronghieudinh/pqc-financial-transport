#!/usr/bin/env bash
# Paper 2, WP6 part B: the two open questions, unattended, ONE command (about 1.5 h plus rests).
#
#   cd Paper/v5/Measurements/testbed && git pull
#   sudo --preserve-env=SSH_AUTH_SOCK bash run_wp6b.sh            # type the password once
#   sudo --preserve-env=SSH_AUTH_SOCK bash run_wp6b.sh --dry-run  # print the plan, run nothing
#
#   race   (~25 min)  What decides the window the server has for its response after the session ticket? Server-side packet captures (vs0, the server's own clock) and tcp_probe of
#                     resumed transactions with a large request and a response of 13 segments, ML-DSA/ECDSA, ten networks (RTT sweep 5-100 ms at 100 Mbit/s, 10 Mbit/s, MTU 1280, MTU 9000).
#                     Analysis: analyze_ticket_race.py -> results/wp6_analysis_race.txt, results/ticket_race.csv
#   rwnd   (~60 min)  Is the MTU 9000 anomaly a receive-window limit? Stage A of the plain-TCP test and the TLS cells at MTU 9000, with the default receive buffer and with
#                     tcp_rmem[1] raised from 131072 to 1048576 (restored on exit). Analysis: analyze_rwnd.py -> results/wp6_analysis_rwnd.txt
# Order: pre-registration (the predictions below are committed and PUSHED before any measurement), host_tune on (stops if the clock is not fixed), race, rest, rwnd.
# After each scenario: analysis, git add + commit + push as you. Options: --only race|rwnd  --rest SECONDS (default 300)  --no-rest  --no-push  --no-commit  --force  --dry-run
# Needs what run_all_wp6.sh needs (tracefs, tcpdump, netns/netem, tls_probe, tcp_flight; see preflight_wp6.sh).
set -uo pipefail
cd "$(dirname "$0")"
HERE=$PWD; PY=${PY:-python3}
ONLY=""; REST=300; PUSH=1; COMMIT=1; FORCE=0; DRY=0
while [ $# -gt 0 ]; do case "$1" in --only) ONLY=$2; shift;; --rest) REST=$2; shift;; --no-rest) REST=0;; --no-push) PUSH=0;; --no-commit) COMMIT=0; PUSH=0;; --force) FORCE=1;; --dry-run) DRY=1;; -h|--help) sed -n 2,17p "$0"; exit 0;; *) echo "unknown option $1"; exit 1;; esac; shift; done
PLAN=(race rwnd); [ -n "$ONLY" ] && PLAN=("$ONLY")
echo "plan: ${PLAN[*]}  (race ~25 min, rwnd ~60 min, rest ${REST}s between)"
[ $DRY = 1 ] && exit 0
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo --preserve-env=SSH_AUTH_SOCK bash run_wp6b.sh"; exit 1; }
U=${SUDO_USER:?run through sudo from your normal user}
if [ -z "${WB_INHIBITED:-}" ] && command -v systemd-inhibit >/dev/null; then exec env WB_INHIBITED=1 systemd-inhibit --what=sleep:idle:handle-lid-switch --who=wp6b --why="WP6 part B" bash "$0" "$@"; fi
as_user() { sudo -u "$U" -H env ${SSH_AUTH_SOCK:+SSH_AUTH_SOCK="$SSH_AUTH_SOCK"} "$@"; }
ROOT=$(as_user git -C "$HERE" rev-parse --show-toplevel)
mkdir -p results; chown "$U" results
LOG=results/wp6b_run.log
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
fix_owner() { chown -R "$U" results work 2>/dev/null || true; }
log "load average: $(cut -d' ' -f1-3 /proc/loadavg)"
for b in ip tc ethtool taskset tcpdump; do command -v $b >/dev/null || { log "ERROR: $b missing"; exit 1; }; done
[ -d /sys/kernel/tracing/events/tcp/tcp_probe ] || { log "ERROR: tracepoint tcp:tcp_probe not available (mount -t tracefs nodev /sys/kernel/tracing)"; exit 1; }
for b in tls_probe tcp_flight; do [ -x $b ] || { log "ERROR: $b not built: run ./setup_host.sh"; exit 1; }; done

git_commit_push() {
  local msg=$1; shift
  [ $COMMIT = 1 ] || return 0
  local paths=() p; for p in "$@"; do [ -e "$p" ] && paths+=("$p"); done
  [ ${#paths[@]} -gt 0 ] && as_user git -C "$ROOT" add -A -- "${paths[@]}" 2>>"$LOG"
  if as_user git -C "$ROOT" diff --cached --quiet; then log "nothing new to commit"; else
    as_user git -C "$ROOT" commit -q -m "$msg" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>" >>"$LOG" 2>&1 && log "committed: $msg" || log "commit FAILED"; fi
  [ $PUSH = 1 ] || return 0
  for i in 1 2 3; do as_user git -C "$ROOT" pull --rebase --autostash -q >>"$LOG" 2>&1; as_user git -C "$ROOT" push -q >>"$LOG" 2>&1 && { log pushed; return 0; }; log "push failed ($i), retry in 20 s"; sleep 20; done; return 1
}

# ---------- pre-registration: what each hypothesis predicts, written BEFORE the measurements
cat > results/wp6_pred_race.txt <<'EOT'
WP6 part B, scenario race (pre-registered). Resumed transactions, mutual TLS, request 19,460 B, response 13 segments, one server window of 10 segments after the ServerHello.
Observed before this test (stage E, 30 ms): largest response without an extra round trip = 10 (ECDSA-P256, ticket 1 segment), 12 (ML-DSA-44, ticket 4), 15 (ML-DSA-65, ticket 5);
gen (240 cells): 10 for every suite at 5 ms and at 100 ms/10 Mbit/s. Question: what makes the window after the ticket 12 or 15 at 30 ms and 10 at 5 ms?
H_race: the window is raised by the ticket ONLY IF the ticket's acknowledgment reaches the server before the response is written (t_ack_tkt <= t_w in analyze_ticket_race.py).
   Predicts: where the burst (response segments sent before the first response ACK) exceeds 10, the share of transactions with 'acked<w' is high, and where the burst is 10, it is low;
   and as the RTT grows from 5 to 100 ms at 100 Mbit/s the transition occurs where the ticket ACK passes the response write.
H_ack_clock: the ticket's ACK opens the window even if it arrives after the first response segments (extra > 0 in analyze_ticket_race.py); the burst is the size of the first window (10)
   and the response finishes without an extra round trip because the ticket's ACK clocks out further segments before the first response ACK.
H_const: the window after the ticket is a property of the stack: burst and 'acked<w' do not change with the network (refuted by gen already; reported for completeness).
Decision rule: for the ML-DSA-65 cells at RTT 30 ms (the stage-E network) and at RTT 5 ms, compare burst and the sign of (ack_tkt - w); H_race is supported if burst > 10 occurs only with acked<w >= 80%,
H_ack_clock if burst > 10 or 'extra' > 0 occurs with acked<w <= 20%. If neither pattern holds the mechanism stays open.
EOT
cat > results/wp6_pred_mtu9000_rwnd.txt <<'EOT'
WP6 part B, scenario rwnd (pre-registered). Observed before this test: at MTU 9000 the advertised window in the tcp_probe trace is 63,488 B (7.1 segments of 8,940 B; 45 segments at MTU 1500);
stage A at MTU 9000 gives windows below the closed form max(10, min(10 + n, 2n)) (n = 10: 16 instead of 20); in the TLS cells at MTU 9000 every response of 9 to 16 segments pays one extra round trip.
H_rwnd: the sender is limited by the receive window (about 7 segments at MTU 9000), so cwnd is not the limit and does not grow by the rule.
   Predicts: with tcp_rmem[1] raised from 131072 to 1048576, (1) the stage-A windows at MTU 9000 follow the closed form in at least 90 % of the flight sizes (default: below 70 %),
   (2) the advertised window in the trace is above 89,400 B, (3) the TLS cells at MTU 9000 follow the early-ticket model with window 10 (fewer than 4 of 48 cells wrong by a round trip);
   nothing changes at MTU 1500.
If (1) fails the cause is not the receive buffer (candidates: offload settings of the virtual links, MSS accounting, the netem queue).
EOT
fix_owner
git_commit_push "WP6 part B: scripts and pre-registered predictions (before the measurements)" "$HERE/run_wp6b.sh" "$HERE/analyze_ticket_race.py" "$HERE/analyze_rwnd.py" "$HERE/trace_run.py" results/wp6_pred_race.txt results/wp6_pred_mtu9000_rwnd.txt \
  || { [ "${ALLOW_UNPUSHED:-0}" = 1 ] || { log "ERROR: the pre-registration commit was not pushed: fix the network or ssh key, or run with ALLOW_UNPUSHED=1"; exit 1; }; }

# ---------- host tuning
OLD_RMEM=$(cat /proc/sys/net/ipv4/tcp_rmem)
restore() { sysctl -qw net.ipv4.tcp_rmem="$OLD_RMEM"; ./host_tune.sh off >>"$LOG" 2>&1; fix_owner; log "restored host tuning and tcp_rmem ($OLD_RMEM)"; }
trap restore EXIT
./host_tune.sh on >>"$LOG" 2>&1
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor); nt=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)
[ "$gov" = performance ] && [ "$nt" = 1 ] || { log "ERROR: clock not fixed (governor=$gov no_turbo=$nt)"; exit 1; }
wait_idle() { [ $REST -gt 0 ] || return 0; log "resting $REST s and waiting for an idle machine"; sleep "$REST"; for i in $(seq 1 60); do awk -v l="$(cut -d' ' -f1 /proc/loadavg)" 'BEGIN{exit !(l < 0.7)}' && return 0; sleep 10; done; }

run_race() {
  $PY trace_run.py race --n 6 --ks 13 >>"$LOG" 2>&1 || log "race: trace_run FAILED (see the log)"
  fix_owner
  { echo "\$ python3 analyze_ticket_race.py results/trace_race/*_srv.pcap"; as_user $PY analyze_ticket_race.py results/trace_race/*_srv.pcap --csv results/ticket_race.csv 2>&1; } > results/wp6_analysis_race.txt
  { echo; echo "\$ python3 analyze_trace.py results/trace_race/*.trace.txt (server side)"; as_user $PY analyze_trace.py results/trace_race/*.trace.txt 2>&1 | head -80; } >> results/wp6_analysis_race.txt
  fix_owner; touch results/.wp6b_done_race; chown "$U" results/.wp6b_done_race
  git_commit_push "WP6 race: server-side ticket timeline, results and analysis (automatic)" "$HERE/results"
}
rb() { echo $(( $1 * ($2 - 60) - 700 )); }
run_rwnd() {
  SU3="ECDSA-P256|X25519,ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768"
  for TAG in default large; do
    if [ "$TAG" = large ]; then export PQC_RMEM="4096 1048576 6291456"; sysctl -qw net.ipv4.tcp_rmem="$PQC_RMEM"; else unset PQC_RMEM; sysctl -qw net.ipv4.tcp_rmem="$OLD_RMEM"; fi
    log "rwnd: tcp_rmem = $(cat /proc/sys/net/ipv4/tcp_rmem)"
    mkdir -p results/rwnd_$TAG
    $PY run_slack.py --stage A --configs base,mtu9000 --trace --trace-configs base,mtu9000 --reps-a 20 --out results/rwnd_$TAG/slack.csv >>"$LOG" 2>&1 || log "rwnd $TAG: run_slack FAILED"
    for REQ in 302 19460; do for K in 9 10 11 12 13 14 15 16; do
      $PY run_testbed.py --profile core --resume --suites "$SU3" --depths 2 --rtts 100 --rates 100 --mtus 9000 --icws 10 --req $REQ --resp $(rb $K 9000) --n 20 --out results/wp6_mtu9000_${TAG}_tls.csv >>"$LOG" 2>&1 || log "rwnd $TAG: run_testbed FAILED (req $REQ k $K)"
    done; done
    fix_owner
    as_user $PY analyze_resume.py --out results/resume_summary_wp6_mtu9000_$TAG.csv results/wp6_mtu9000_${TAG}_tls.csv >>"$LOG" 2>&1 || log "rwnd $TAG: analyze_resume failed"
  done
  unset PQC_RMEM; sysctl -qw net.ipv4.tcp_rmem="$OLD_RMEM"
  { echo "\$ python3 analyze_rwnd.py"; as_user $PY analyze_rwnd.py 2>&1; } > results/wp6_analysis_rwnd.txt
  fix_owner; touch results/.wp6b_done_rwnd; chown "$U" results/.wp6b_done_rwnd
  git_commit_push "WP6 rwnd: MTU 9000 with default and raised receive buffer, results and analysis (automatic)" "$HERE/results"
}
n=0
for s in "${PLAN[@]}"; do
  n=$((n + 1))
  if [ $FORCE = 0 ] && [ -e "results/.wp6b_done_$s" ]; then log "$s: already done (use --force)"; continue; fi
  log "[$n/${#PLAN[@]}] $s: start"
  "run_$s"
  log "$s: finished"
  [ "$n" -lt "${#PLAN[@]}" ] && wait_idle
done
log "ALL DONE: results/wp6_analysis_race.txt and results/wp6_analysis_rwnd.txt"
