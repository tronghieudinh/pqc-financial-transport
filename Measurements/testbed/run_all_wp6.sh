#!/usr/bin/env bash
# Paper 2, WP6: run EVERY prepared measurement scenario unattended, analyse after each one, commit and push the results, rest, and go on.
#
#   sudo --preserve-env=SSH_AUTH_SOCK bash run_all_wp6.sh            # type the password once; everything else is automatic (about 12 h plus rests)
#   sudo --preserve-env=SSH_AUTH_SOCK bash run_all_wp6.sh --dry-run  # print the plan and the time, run nothing
#
# What it does, in order:
#   0. checks the tools, builds tls_load_open / tcp_flight if missing, creates results/wp6_pred_*.csv if missing (python3 wp6_predict.py);
#   1. PRE-REGISTRATION: commits and PUSHES the code and the predictions before any measurement (the timestamp on GitHub is the evidence);
#      if the push fails it stops, unless ALLOW_UNPUSHED=1;
#   2. host_tune on (performance governor, no turbo), restored at the end or on any exit;
#   3. for each scenario: run it (run_wp6.sh), analyse it (results/wp6_analysis_<scenario>.txt), chown the results to you, git add + commit + push
#      (as you, not as root), wait REST seconds (default 300) and until the machine is idle (load average < 0.7), then the next one.
# A scenario that fails is logged and skipped; the others go on. A finished scenario leaves results/.wp6_done_<scenario>: run the script again
# after an interruption and it continues where it stopped (each scenario is itself resumable). Full log: results/wp6_run.log.
#
# Options: --skip-preflight (do not run preflight_wp6.sh first)   --only trace,gen   --skip loss   --with-kernel (run the kernel scenario: only meaningful on a kernel different from the first runs)
#          --rest SECONDS (default 300)   --no-rest   --no-push (commit only)   --no-commit   --force (ignore the done markers)   --dry-run
# Scenarios in this order: trace clientalg servonly gen loss latency capacity [kernel]. Not covered: QUIC, other TLS libraries, two machines.
# git pushes need your ssh key: run with  sudo --preserve-env=SSH_AUTH_SOCK  (agent) or use a key without passphrase.
set -uo pipefail
cd "$(dirname "$0")"
HERE=$PWD
PY=${PY:-python3}
ORDER=(trace clientalg servonly gen loss latency capacity)
ONLY=""; SKIP=""; REST=300; PUSH=1; COMMIT=1; FORCE=0; DRY=0; KERNEL=0; PREFLIGHT=1
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY=$2; shift;; --skip) SKIP=$2; shift;; --rest) REST=$2; shift;; --no-rest) REST=0;; --no-push) PUSH=0;; --no-commit) COMMIT=0; PUSH=0;;
    --force) FORCE=1;; --skip-preflight) PREFLIGHT=0;; --dry-run) DRY=1;; --with-kernel) KERNEL=1;; -h|--help) sed -n 2,26p "$0"; exit 0;; *) echo "unknown option $1"; exit 1;;
  esac; shift
done
[ $KERNEL = 1 ] && ORDER+=(kernel)
EST=(trace:45 clientalg:40 servonly:30 gen:120 loss:165 latency:60 capacity:60 kernel:75)
est() { for e in "${EST[@]}"; do [ "${e%%:*}" = "$1" ] && echo "${e##*:}"; done; }
in_list() { case ",$2," in *",$1,"*) return 0;; esac; return 1; }
PLAN=()
for s in "${ORDER[@]}"; do
  [ -n "$ONLY" ] && ! in_list "$s" "$ONLY" && continue
  [ -n "$SKIP" ] && in_list "$s" "$SKIP" && continue
  PLAN+=("$s")
done
total=0; for s in "${PLAN[@]}"; do total=$((total + $(est "$s"))); done
total=$((total + (${#PLAN[@]} - 1) * REST / 60))
echo "plan: ${PLAN[*]}  (about $((total / 60)) h $((total % 60)) min including ${REST}s rests)"
[ $DRY = 1 ] && { for s in "${PLAN[@]}"; do echo "  $s: ~$(est $s) min"; done; exit 0; }
FAKE=${WP6_FAKE:-0}     # test mode (no root, no measurement): WP6_FAKE=1 bash run_all_wp6.sh --only latency --no-commit
[ "$(id -u)" = 0 ] || [ "$FAKE" = 1 ] || { echo "run with sudo: sudo --preserve-env=SSH_AUTH_SOCK bash run_all_wp6.sh"; exit 1; }
U=${SUDO_USER:-}; [ "$FAKE" = 1 ] && U=${U:-$(id -un)}
[ -n "$U" ] || { echo "run it through sudo from your normal user (SUDO_USER is empty)"; exit 1; }
if [ "$(id -u)" = 0 ]; then as_user() { sudo -u "$U" -H env ${SSH_AUTH_SOCK:+SSH_AUTH_SOCK="$SSH_AUTH_SOCK"} "$@"; }; else as_user() { "$@"; }; fi
ROOT=$(as_user git -C "$HERE" rev-parse --show-toplevel) || { echo "not in a git repository"; exit 1; }
RELT=$(realpath --relative-to="$ROOT" "$HERE")
mkdir -p results; chown "$U" results
# keep the machine awake for the whole run (re-executes itself once under systemd-inhibit)
if [ -z "${WP6_INHIBITED:-}" ] && [ "$FAKE" != 1 ] && command -v systemd-inhibit >/dev/null; then
  exec env WP6_INHIBITED=1 systemd-inhibit --what=sleep:idle:handle-lid-switch --who=wp6 --why="WP6 measurements (about 9 h)" bash "$0" "$@"
fi
LOG=results/wp6_run.log
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
fix_owner() { chown -R "$U" results work 2>/dev/null || true; chown -R "$U" "$HERE"/work 2>/dev/null || true; }

# ---------- 0. preflight (every condition the scenarios need) and builds
if [ $PREFLIGHT = 1 ] && [ "$FAKE" != 1 ]; then
  bash ./preflight_wp6.sh 2>&1 | tee -a "$LOG" || { log "ERROR: preflight failed: fix the FAIL lines above, or run with --skip-preflight at your own risk"; exit 1; }
fi
for b in ip tc ethtool taskset tcpdump; do command -v $b >/dev/null || log "WARNING: $b not found (some scenarios need it)"; done
command -v perf >/dev/null || log "WARNING: perf not found: the CPU profile of the capacity scenario will be skipped (apt install linux-tools-\$(uname -r))"
[ -d /sys/kernel/tracing/events/tcp/tcp_probe ] || log "WARNING: tracepoint tcp:tcp_probe not available (mount -t tracefs nodev /sys/kernel/tracing): the trace scenario will fail"
for b in tls_probe tls_serve tls_load; do [ -x $b ] || { log "ERROR: $b not built: run ./setup_host.sh first"; exit 1; }; done
P=$(as_user bash -c 'echo ${PQC_OPENSSL:-$HOME/opt/openssl-3.5}')
[ -x tls_load_open ] || as_user gcc -O2 -Wall -pthread -o tls_load_open tls_load_open.c -I"$P/include" -L"$P/lib" -lssl -lcrypto -lm -Wl,-rpath,"$P/lib" || log "ERROR: tls_load_open did not build"
[ -x tcp_flight ] || as_user gcc -O2 -Wall -o tcp_flight tcp_flight.c || log "ERROR: tcp_flight did not build"
if ! ls results/wp6_pred_*.csv >/dev/null 2>&1; then as_user $PY wp6_predict.py | tee -a "$LOG"; fi

# ---------- 1. pre-registration: commit and push code and predictions first
git_commit_push() {   # message, paths...
  local msg=$1; shift
  [ $COMMIT = 1 ] || return 0
  local paths=() p
  for p in "$@"; do [ -e "$p" ] && paths+=("$p"); done
  [ ${#paths[@]} -gt 0 ] && as_user git -C "$ROOT" add -- "${paths[@]}" 2>>"$LOG"
  if as_user git -C "$ROOT" diff --cached --quiet; then log "nothing new to commit"; else
    as_user git -C "$ROOT" commit -q -m "$msg" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>" >>"$LOG" 2>&1 && log "committed: $msg" || log "commit FAILED"
  fi
  [ $PUSH = 1 ] || return 0
  for i in 1 2 3; do
    as_user git -C "$ROOT" pull --rebase --autostash -q >>"$LOG" 2>&1
    if as_user git -C "$ROOT" push -q >>"$LOG" 2>&1; then log "pushed"; return 0; fi
    log "push failed (attempt $i), retrying in 20 s"; sleep 20
  done
  return 1
}
CODE=("$HERE"/*.py "$HERE"/*.sh "$HERE"/*.c "$HERE"/README.md "$HERE"/.gitignore "$HERE"/results/wp6_pred_*.csv)
if [ $COMMIT = 1 ]; then
  if ! git_commit_push "WP6: scenarios, analysis scripts and pre-registered predictions (before the measurements)" "${CODE[@]}"; then
    [ "${ALLOW_UNPUSHED:-0}" = 1 ] || { log "ERROR: the pre-registration commit could not be pushed; fix the network or the ssh key, or run with ALLOW_UNPUSHED=1"; exit 1; }
    log "WARNING: continuing with an unpushed pre-registration commit (ALLOW_UNPUSHED=1)"
  fi
fi

# ---------- 2. host tuning, restored on exit
[ "$FAKE" = 1 ] || ./host_tune.sh on 2>&1 | tee -a "$LOG" >/dev/null
trap '[ "$FAKE" = 1 ] || ./host_tune.sh off >>"$LOG" 2>&1; fix_owner; log "host tuning restored"' EXIT

wait_idle() {
  [ $REST -gt 0 ] || return 0
  log "resting $REST s, then waiting for an idle machine"
  sleep "$REST"
  for i in $(seq 1 60); do
    l=$(cut -d' ' -f1 /proc/loadavg)
    awk -v l="$l" 'BEGIN{exit !(l < 0.7)}' && return 0
    sleep 10
  done
  log "machine still busy after 10 min: going on"
}

analyse() {   # scenario -> results/wp6_analysis_<scenario>.txt
  local s=$1 out=results/wp6_analysis_$1.txt
  : > "$out"
  run() { echo "\$ $*" >>"$out"; "$@" >>"$out" 2>&1 || echo "(exit code $?)" >>"$out"; echo >>"$out"; }
  case "$s" in
    trace)
      run $PY analyze_trace.py results/trace_window/*.trace.txt
      for f in results/trace_fullticket/*.pcap; do [ -e "$f" ] && { echo "### $f" >>"$out"; $PY pcap_summary.py "$f" --conn 0 >>"$out" 2>&1; $PY pcap_summary.py "$f" --conn 1 >>"$out" 2>&1; }; done
      [ -e results/slack_trace_mtu9000.txt ] && run $PY analyze_trace.py results/slack_trace_mtu9000.txt --port 4500
      [ -e results/slack_trace_base.txt ] && run $PY analyze_trace.py results/slack_trace_base.txt --port 4500 ;;
    gen)       run $PY analyze_resume.py --out results/resume_summary_wp6_gen.csv results/wp6_gen_tls.csv; run $PY analyze_wp6.py gen ;;
    servonly)  run $PY analyze_resume.py --out results/resume_summary_wp6_servonly.csv results/wp6_servonly_tls.csv; run $PY analyze_wp6.py servonly ;;
    clientalg) run $PY analyze_wp6.py clientalg ;;
    loss)      run $PY analyze_loss.py results/wp6_loss_full.csv --out results/wp6_loss_full_summary.csv
               run $PY analyze_loss.py results/wp6_loss_resumed.csv --resume --out results/wp6_loss_resumed_summary.csv ;;
    latency)   run $PY analyze_wp6.py latency ;;
    capacity)  run $PY analyze_wp6.py capacity ;;
    kernel)    K=$(uname -r); run $PY analyze_slack.py --tcp results/slack_tcp_${K}.csv ;;
  esac
}

# ---------- 3. the scenarios
n=0; failed=()
for s in "${PLAN[@]}"; do
  n=$((n + 1))
  if [ $FORCE = 0 ] && [ -e "results/.wp6_done_$s" ]; then log "[$n/${#PLAN[@]}] $s: already done, skipping (use --force)"; continue; fi
  log "[$n/${#PLAN[@]}] $s: start (about $(est $s) min)"
  t0=$(date +%s)
  if { [ "$FAKE" = 1 ] && true; } || bash run_wp6.sh "$s" >>"$LOG" 2>&1; then
    log "$s: measurement finished in $(( ($(date +%s) - t0) / 60 )) min"; ok=1
  else
    log "$s: FAILED (see the log); analysing what exists"; failed+=("$s"); ok=0
  fi
  fix_owner
  analyse "$s"; fix_owner
  log "$s: analysis written to results/wp6_analysis_$s.txt"
  [ $ok = 1 ] && touch "results/.wp6_done_$s" && chown "$U" "results/.wp6_done_$s"
  git_commit_push "WP6 $s: measurement results and analysis (automatic)" "$HERE/results" || log "git step for $s did not complete; results stay on disk"
  [ "$n" -lt "${#PLAN[@]}" ] && wait_idle
done
log "ALL DONE. Failed scenarios: ${failed[*]:-none}. Analyses: results/wp6_analysis_*.txt"
git_commit_push "WP6: final log" "$HERE/results" || true
