#!/usr/bin/env bash
# Paper 2, WP6 part C: confirmatory test of the ticket-timing rule, unattended, ONE command (about 20 minutes).
#
#   cd Paper/v5/Measurements/testbed && git pull
#   sudo --preserve-env=SSH_AUTH_SOCK bash run_wp6c.sh            # after run_wp6b.sh has finished (both use the testbed)
#   sudo --preserve-env=SSH_AUTH_SOCK bash run_wp6c.sh --dry-run
#
# Rule found (exploratory) in the race run: the server's window for its response exceeds 10 segments iff the last ACK of the ticket arrives more than 0.049 ms AFTER the last request
# segment. Test: request of 19,460 + 1,440 j bytes (j = -3 .. +6), ML-DSA-44 and ML-DSA-65, 30 ms and 100 ms at 100 Mbit/s, MTU 1500, response of 16 segments, 8 resumed transactions per
# cell, server-side captures. The predictions (race2_predict.py -> results/wp6_pred_race2.csv) are committed and PUSHED before the measurement. Analysis: analyze_race2.py
# -> results/wp6_analysis_race2.txt, committed and pushed as you. Options: --no-push --no-commit --dry-run.
set -uo pipefail
cd "$(dirname "$0")"
HERE=$PWD; PY=${PY:-python3}
PUSH=1; COMMIT=1; DRY=0
for o in "$@"; do case "$o" in --no-push) PUSH=0;; --no-commit) COMMIT=0; PUSH=0;; --dry-run) DRY=1;; *) echo "unknown option $o"; exit 1;; esac; done
REQS="15140,16580,18020,19460,20900,22340,23780,25220,26660,28100"
SUITES="ML-DSA-44|ML-KEM-768,ML-DSA-65|ML-KEM-768"
NETS="30:100:1500,100:100:1500"
echo "plan: $SUITES; nets $NETS; request sizes $REQS; k=16; 8 resumed transactions per cell (40 runs, about 20 min)"
[ $DRY = 1 ] && exit 0
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo --preserve-env=SSH_AUTH_SOCK bash run_wp6c.sh"; exit 1; }
U=${SUDO_USER:?run through sudo from your normal user}
if [ -z "${WC_INHIBITED:-}" ] && command -v systemd-inhibit >/dev/null; then exec env WC_INHIBITED=1 systemd-inhibit --what=sleep:idle:handle-lid-switch --who=wp6c --why="WP6 part C" bash "$0" "$@"; fi
as_user() { sudo -u "$U" -H env ${SSH_AUTH_SOCK:+SSH_AUTH_SOCK="$SSH_AUTH_SOCK"} "$@"; }
ROOT=$(as_user git -C "$HERE" rev-parse --show-toplevel)
mkdir -p results; chown "$U" results
LOG=results/wp6c_run.log
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
[ -x tls_probe ] || { log "ERROR: tls_probe not built: ./setup_host.sh"; exit 1; }
[ -d /sys/kernel/tracing/events/tcp/tcp_probe ] || { log "ERROR: tcp:tcp_probe tracepoint not available"; exit 1; }
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
# ---------- pre-registration
as_user $PY race2_predict.py >>"$LOG" 2>&1 || { log "ERROR: race2_predict.py failed (needs results/ticket_race.csv from the race run)"; exit 1; }
git_commit_push "WP6 part C: predictions of the ticket-timing rule (before the measurement)" "$HERE/race2_predict.py" "$HERE/analyze_race2.py" "$HERE/run_wp6c.sh" results/wp6_pred_race2.csv \
  || { [ "${ALLOW_UNPUSHED:-0}" = 1 ] || { log "ERROR: the pre-registration commit was not pushed (fix the network or ssh key, or ALLOW_UNPUSHED=1)"; exit 1; }; }
# ---------- host tuning
restore() { ./host_tune.sh off >>"$LOG" 2>&1; chown -R "$U" results work 2>/dev/null; log "host tuning restored"; }
trap restore EXIT
./host_tune.sh on >>"$LOG" 2>&1
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor); nt=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)
[ "$gov" = performance ] && [ "$nt" = 1 ] || { log "ERROR: clock not fixed (governor=$gov no_turbo=$nt)"; exit 1; }
log "load average: $(cut -d' ' -f1-3 /proc/loadavg)"
$PY trace_run.py race --suites "$SUITES" --reqs "$REQS" --nets "$NETS" --ks 16 --n 8 >>"$LOG" 2>&1 || log "trace_run FAILED (see the log)"
chown -R "$U" results
{ echo "\$ python3 analyze_race2.py"; as_user $PY analyze_race2.py 2>&1; } > results/wp6_analysis_race2.txt
chown -R "$U" results
git_commit_push "WP6 part C: ticket-timing rule, confirmatory test: results and analysis (automatic)" "$HERE/results"
log "DONE: results/wp6_analysis_race2.txt"
