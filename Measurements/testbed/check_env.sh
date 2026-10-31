#!/usr/bin/env bash
# Sanity checks before a sweep. Run as a normal user (uses sudo for the namespace test).
set -uo pipefail
cd "$(dirname "$0")"
PREFIX=${PQC_OPENSSL:-$HOME/opt/openssl-3.5}
ok() { echo "  [ok] $*"; }; bad() { echo "  [!!] $*"; FAIL=1; }
FAIL=0
for b in ip tc ethtool taskset python3 gcc; do command -v $b >/dev/null && ok "$b" || bad "missing $b (run setup_host.sh)"; done
command -v haproxy >/dev/null && ok haproxy || echo "  [..] haproxy missing: only the proxy topologies need it"
[ -x "$PREFIX/bin/openssl" ] && "$PREFIX/bin/openssl" version | grep -q " 3\.5" && ok "$("$PREFIX/bin/openssl" version)" || bad "OpenSSL 3.5 not found in $PREFIX"
[ -x ./tls_probe ] && ok tls_probe || bad "tls_probe not built"
for a in ECDSA-P256 ML-DSA-65; do [ -f ../certs/$a/d4/server.key ] && ok "certs + keys $a" || bad "keys for $a missing: run (cd .. && ./certs.sh)"; done
echo "namespaces + netem + route metrics:"
sudo ip netns del pqcchk 2>/dev/null
if sudo ip netns add pqcchk; then
  sudo ip netns exec pqcchk ip link set lo up
  sudo ip netns exec pqcchk tc qdisc add dev lo root netem delay 5ms rate 100mbit && ok "tc netem (delay + rate)" || bad "tc netem not available (sch_netem module?)"
  sudo ip netns exec pqcchk ip -6 route add ::1/128 dev lo initcwnd 20 initrwnd 100 congctl reno quickack 1 2>/dev/null && ok "route metrics (initcwnd, congctl, quickack)" || echo "  [..] route metrics on lo not accepted (will be tested on the veth link by the run)"
  sudo ip netns exec pqcchk ethtool -K lo gso off >/dev/null 2>&1; 
  sudo ip netns del pqcchk
else bad "cannot create a network namespace"; fi
echo "end-to-end (TLS over a shaped link, 30 ms RTT, ML-DSA-65 depth 3):"
sudo -E python3 run_testbed.py --profile smoke --suites "ML-DSA-65|ML-KEM-768" --depths 3 --rtts 30 --rates 100 --n 5 \
     --out /tmp/pqc_check/testbed_raw.csv 2>&1 | tail -6
python3 - <<'PY'
import csv, statistics as st
try:
    rows = list(csv.DictReader(open("/tmp/pqc_check/testbed_raw.csv")))
    b = [float(r["t_total_ms"]) for r in rows if r["net_id"] == "base" and not r["err"]]
    s = [float(r["t_total_ms"]) for r in rows if r["net_id"] == "shaped" and not r["err"]]
    print(f"  base median {st.median(b):.1f} ms, shaped median {st.median(s):.1f} ms (expect about +100 ms: 3 RTT + flights)")
    r = next(r for r in rows if r["net_id"] == "shaped")
    print(f"  client snd_mss={r['snd_mss']} (expect 1440), snd_cwnd0={r['snd_cwnd0']} (expect 10)")
except Exception as e:
    print("  end-to-end test produced no rows:", e)
PY
[ $FAIL = 0 ] && echo "ALL BASIC CHECKS PASSED" || echo "SOME CHECKS FAILED"
