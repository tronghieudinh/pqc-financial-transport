#!/usr/bin/env bash
# Step-by-step diagnosis of the namespace testbed. Run:  sudo ./diagnose.sh   and send the whole output.
cd "$(dirname "$0")" || exit 1
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
U=${SUDO_USER:-root}; H=$(getent passwd "$U" | cut -d: -f6)
export LD_LIBRARY_PATH=$H/opt/openssl-3.5/lib
M=$(cd .. && pwd); A=ECDSA-P256; B=ML-DSA-65
step() { echo; echo "=== $*"; }
trap 'python3 tbnet.py down >/dev/null 2>&1' EXIT

step "versions"; uname -r; ip -V; tc -V 2>&1 | head -1; "$H/opt/openssl-3.5/bin/openssl" version; ls -l tls_probe
step "certificates"; ls "$M/certs/$A/d1/" "$M/certs/$B/d3/" 2>&1 | head -20
for d in "$A/d1" "$B/d3"; do
  openssl_bin="$H/opt/openssl-3.5/bin/openssl"
  "$openssl_bin" verify -CAfile "$M/certs/$d/root.pem" -untrusted "$M/certs/$d/inter_chain.pem" "$M/certs/$d/server.pem" 2>&1 | tail -2
done
step "build namespaces (direct topology)"
python3 tbnet.py up 2>&1 | tail -5
step "shape: RTT 30 ms, 100 Mbit/s, MTU 1500, initcwnd 10"
python3 tbnet.py shape --rtt 30 --rate 100 --mtu 1500 --icw 10 2>&1 | tail -5
step "addresses, routes, qdisc"
ip netns exec pqcc ip -6 addr show dev vc0 | grep -E "inet6|mtu"
ip netns exec pqcc ip -6 route show | head
ip netns exec pqcc tc qdisc show dev vc0
ip netns exec pqcs tc qdisc show dev vs0
step "ping through the link (expect about 30 ms)"
ip netns exec pqcc ping -6 -c 3 -W 3 fd99:1::2 2>&1 | tail -4

probe_test() {  # alg depth group
  local alg=$1 d=$2 g=$3 c="$M/certs/$1/d$2"
  cat "$c/server.pem" "$c/inter_chain.pem" > /tmp/diag_s.pem; cat "$c/client.pem" "$c/inter_chain.pem" > /tmp/diag_c.pem
  step "TLS transaction: $alg depth $d group $g (mutual TLS)"
  ip netns exec pqcs ./tls_probe server --addr fd99:1::2 --port 4433 --cert /tmp/diag_s.pem --key "$c/server.key" \
        --ca "$c/root.pem" --mtls --groups "$g" > /tmp/diag_srv.out 2> /tmp/diag_srv.err &
  local pid=$!; sleep 1
  echo "-- listening sockets in the server namespace:"; ip netns exec pqcs ss -tln | grep 4433
  echo "-- client output:"
  timeout 60 ip netns exec pqcc ./tls_probe client --addr fd99:1::2 --port 4433 --ca "$c/root.pem" --cert /tmp/diag_c.pem \
        --key "$c/client.key" --groups "$g" --n 3 --warmup 1 --gap-ms 65 2>&1
  echo "-- server stdout/stderr:"; cat /tmp/diag_srv.out /tmp/diag_srv.err
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
}
probe_test $A 1 x25519
probe_test $B 3 MLKEM768
step "done. Expected: t_tcp about 30 ms, t_total about 100-200 ms, snd_mss 1440, snd_cwnd0 10, empty err column"
