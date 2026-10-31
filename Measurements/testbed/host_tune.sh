#!/usr/bin/env bash
# Make timings stable: performance governor, no turbo. Reversible.
#   sudo ./host_tune.sh on      sudo ./host_tune.sh off      sudo ./host_tune.sh status
set -euo pipefail
STATE=/tmp/pqc_tune.state
G=/sys/devices/system/cpu
case "${1:-status}" in
  on)
    [ -f "$STATE" ] || { cat $G/cpu0/cpufreq/scaling_governor > "$STATE" 2>/dev/null || echo powersave > "$STATE";
                         echo "$(cat $G/intel_pstate/no_turbo 2>/dev/null || echo 0)" >> "$STATE"; }
    for c in $G/cpu[0-9]*/cpufreq/scaling_governor; do echo performance > "$c" 2>/dev/null || true; done
    [ -f $G/intel_pstate/no_turbo ] && echo 1 > $G/intel_pstate/no_turbo
    echo "tuned (previous state saved in $STATE)";;
  off)
    if [ -f "$STATE" ]; then
      gov=$(sed -n 1p "$STATE"); turbo=$(sed -n 2p "$STATE")
      for c in $G/cpu[0-9]*/cpufreq/scaling_governor; do echo "$gov" > "$c" 2>/dev/null || true; done
      [ -f $G/intel_pstate/no_turbo ] && echo "$turbo" > $G/intel_pstate/no_turbo
      rm -f "$STATE"; echo "restored"
    else echo "nothing to restore"; fi;;
esac
echo "governor: $(cat $G/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)  no_turbo: $(cat $G/intel_pstate/no_turbo 2>/dev/null || echo n/a)"
echo "frequencies (MHz): $(awk '/cpu MHz/{printf "%d ",$4}' /proc/cpuinfo)"
