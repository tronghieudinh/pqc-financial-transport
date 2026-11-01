#!/usr/bin/env bash
# Paper 1: repeat the TCP-variant runs (CUBIC wide grid, delayed ACK, timestamps, both, exploratory BBR) with the CPU clock FIXED, unattended.
#
#   sudo --preserve-env=SSH_AUTH_SOCK bash run_variants_tuned.sh            # type the password once; everything else is automatic (about 2 h plus rests)
#   sudo --preserve-env=SSH_AUTH_SOCK bash run_variants_tuned.sh --dry-run  # print the plan, run nothing
#
# Why: the snapshot (results/env.json, commit 4650164) of the session that produced results/{ts,delack,delack_ts,bbr,cubic2}.csv records the governor
# ondemand with turbo enabled, while the validation campaigns ran with performance / no_turbo=1. The model and the analysis code are unchanged,
# so there is nothing to pre-register: only the clock differs.
# What it does, in order:
#   0. checks root, tools, load; computes the summary of the OLD (ondemand) files for comparison (results/ondemand_session/variants_summary.csv);
#   1. moves the old CSVs to results/ondemand_session/ (run_testbed.py skips configurations already in the output file, so they must be out of the way;
#      nothing is deleted) and commits + pushes that together with the script, before any measurement;
#   2. host_tune on (performance governor, no turbo); STOPS if the clock is not fixed; restored at the end or on any exit;
#   3. for each variant: run it (run_variants.sh <variant>), check that results/env.json says performance / no_turbo=1, chown to you, git add + commit + push
#      (as you, not as root), wait REST seconds (default 300) and until the machine is idle (load average < 0.7), then the next one;
#   4. analyses with python3 analyze_variants.py into results/variants_tuned_latex/ (it does NOT touch paper1/Latex), commits and pushes.
# A finished variant leaves results/.variants_done_<name>; run the script again after an interruption and it continues (each variant is resumable).
# Log: results/variants_run.log.   Options: --rest SECONDS (default 300)  --no-rest  --no-push  --no-commit  --only delack,ts  --skip bbr  --force  --dry-run
# git pushes need your ssh key: run with  sudo --preserve-env=SSH_AUTH_SOCK  (agent) or use a key without passphrase.
set -uo pipefail
cd "$(dirname "$0")"
HERE=$PWD
PY=${PY:-python3}
ORDER=(delack ts delack_ts cubic2 bbr)
EST=(delack:20 ts:20 delack_ts:20 cubic2:55 bbr:8)
ONLY=""; SKIP=""; REST=300; PUSH=1; COMMIT=1; FORCE=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY=$2; shift;; --skip) SKIP=$2; shift;; --rest) REST=$2; shift;; --no-rest) REST=0;; --no-push) PUSH=0;; --no-commit) COMMIT=0; PUSH=0;;
    --force) FORCE=1;; --dry-run) DRY=1;; -h|--help) sed -n 2,22p "$0"; exit 0;; *) echo "unknown option $1"; exit 1;;
  esac; shift
done
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
FAKE=${VT_FAKE:-0}     # test mode (no root, no measurement)
[ "$(id -u)" = 0 ] || [ "$FAKE" = 1 ] || { echo "run with sudo: sudo --preserve-env=SSH_AUTH_SOCK bash run_variants_tuned.sh"; exit 1; }
U=${SUDO_USER:-}; [ "$FAKE" = 1 ] && U=${U:-$(id -un)}
[ -n "$U" ] || { echo "run it through sudo from your normal user (SUDO_USER is empty)"; exit 1; }
if [ "$(id -u)" = 0 ]; then as_user() { sudo -u "$U" -H env ${SSH_AUTH_SOCK:+SSH_AUTH_SOCK="$SSH_AUTH_SOCK"} "$@"; }; else as_user() { "$@"; }; fi
ROOT=$(as_user git -C "$HERE" rev-parse --show-toplevel) || { echo "not in a git repository"; exit 1; }
mkdir -p results; chown "$U" results
# keep the machine awake for the whole run (re-executes itself once under systemd-inhibit)
if [ -z "${VT_INHIBITED:-}" ] && [ "$FAKE" != 1 ] && command -v systemd-inhibit >/dev/null; then
  exec env VT_INHIBITED=1 systemd-inhibit --what=sleep:idle:handle-lid-switch --who=variants --why="TCP-variant measurements (about 2 h)" bash "$0" "$@"
fi
LOG=results/variants_run.log
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
fix_owner() { chown -R "$U" results work 2>/dev/null || true; }

# ---------- 0. checks
for b in ip tc taskset git; do command -v $b >/dev/null || { log "ERROR: $b not found"; exit 1; }; done
[ -x ./tls_probe ] || { log "ERROR: tls_probe not built: run ./setup_host.sh first"; exit 1; }
[ -x ./host_tune.sh ] || { log "ERROR: host_tune.sh missing"; exit 1; }
log "load average now: $(cut -d' ' -f1-3 /proc/loadavg) (should be below 0.5; close other programs)"

git_commit_push() {   # message, paths...
  local msg=$1; shift
  [ $COMMIT = 1 ] || return 0
  local paths=() p
  for p in "$@"; do [ -e "$p" ] && paths+=("$p"); done
  [ ${#paths[@]} -gt 0 ] && as_user git -C "$ROOT" add -A -- "${paths[@]}" 2>>"$LOG"
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

# ---------- 1. archive the ondemand files (never deleted), commit and push before measuring
OLD=results/ondemand_session; mkdir -p "$OLD"
if [ ! -f "$OLD/variants_summary.csv" ]; then
  as_user $PY analyze_variants.py --latex "$HERE/results/ondemand_latex" >>"$LOG" 2>&1 && [ -f results/variants_summary.csv ] && cp results/variants_summary.csv "$OLD/variants_summary.csv" && log "summary of the ondemand files kept in $OLD/variants_summary.csv"
fi
for f in "${PLAN[@]}"; do
  if [ -f "results/$f.csv" ] && [ ! -f "$OLD/$f.csv" ] && [ ! -e "results/.variants_started_$f" ]; then mv "results/$f.csv" "$OLD/$f.csv"; log "archived results/$f.csv -> $OLD/"; fi
done
[ -f "$OLD/env_before.json" ] || { git -C "$ROOT" show "4650164:Paper/v5/Measurements/testbed/results/env.json" > "$OLD/env_before.json" 2>/dev/null || cp results/env.json "$OLD/env_before.json" 2>/dev/null || true; }
fix_owner
git_commit_push "Variants: archive the ondemand-session CSVs and add run_variants_tuned.sh (before the repeat with a fixed CPU clock)" "$HERE/run_variants_tuned.sh" "$HERE/results" || log "WARNING: the pre-measurement commit was not pushed; continuing"

# ---------- 2. host tuning, restored on exit
[ "$FAKE" = 1 ] || ./host_tune.sh on 2>&1 | tee -a "$LOG" >/dev/null
trap '[ "$FAKE" = 1 ] || ./host_tune.sh off >>"$LOG" 2>&1; fix_owner; log "host tuning restored"' EXIT
check_clock() {
  [ "$FAKE" = 1 ] && return 0
  local gov nt; gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null); nt=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)
  [ "$gov" = performance ] && [ "$nt" = 1 ] || { log "ERROR: CPU clock not fixed (governor=$gov no_turbo=$nt)"; return 1; }
}
check_clock || exit 1
log "clock fixed: governor performance, no_turbo 1"

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

# ---------- 3. the variants
n=0; failed=()
for s in "${PLAN[@]}"; do
  n=$((n + 1))
  if [ $FORCE = 0 ] && [ -e "results/.variants_done_$s" ]; then log "[$n/${#PLAN[@]}] $s: already done, skipping (use --force)"; continue; fi
  check_clock || { failed+=("$s"); continue; }
  log "[$n/${#PLAN[@]}] $s: start (about $(est $s) min)"
  touch "results/.variants_started_$s"; t0=$(date +%s)
  if { [ "$FAKE" = 1 ] && true; } || BBR=0 bash run_variants.sh "$s" >>"$LOG" 2>&1; then
    log "$s: finished in $(( ($(date +%s) - t0) / 60 )) min"; ok=1
  else
    log "$s: FAILED (see the log)"; failed+=("$s"); ok=0
  fi
  if [ "$FAKE" != 1 ] && ! grep -q '"governor": "performance"' results/env.json; then log "WARNING: results/env.json after $s does not say performance"; fi
  fix_owner
  [ $ok = 1 ] && touch "results/.variants_done_$s" && chown "$U" "results/.variants_done_$s"
  git_commit_push "Variants $s with a fixed CPU clock: measurement results (automatic)" "$HERE/results" || log "git step for $s did not complete; results stay on disk"
  [ "$n" -lt "${#PLAN[@]}" ] && wait_idle
done

# ---------- 4. analysis (does not touch paper1/Latex)
mkdir -p results/variants_tuned_latex; fix_owner
as_user $PY analyze_variants.py --latex "$HERE/results/variants_tuned_latex" >>"$LOG" 2>&1 && log "analysis written: results/variants_summary.csv, results/variants_tuned_latex/" || log "analysis FAILED (run python3 analyze_variants.py by hand)"
if [ -f "$OLD/variants_summary.csv" ] && [ -f results/variants_summary.csv ]; then
  { echo "# ondemand session (old) vs fixed clock (new); same configurations"; echo "## old"; cat "$OLD/variants_summary.csv"; echo "## new"; cat results/variants_summary.csv; } > results/variants_tuned_vs_ondemand.txt
fi
fix_owner
log "ALL DONE. Failed variants: ${failed[*]:-none}. Next: update Section 4.5 of the manuscript from results/variants_tuned_latex/ (numbers_variants.tex, tab_variants.tex)."
git_commit_push "Variants with a fixed CPU clock: analysis and final log" "$HERE/results" || true
