#!/usr/bin/env bash
# Server-side handshake capacity: single-threaded s_server pinned to one Cortex-X925 core (cpu 18),
# saturated by 6 parallel s_time clients (cpus 5-9, 15); 10 s per configuration, chain depth 1
# (s_time cannot send client intermediates, so depth 1 keeps mutual TLS verifiable).
set -u
cd "$(dirname "$0")"
export LD_LIBRARY_PATH=$HOME/opt/openssl-3.5/lib
O=$HOME/opt/openssl-3.5/bin/openssl
C=certs
out=data/capacity.csv
echo "suite,mtls,handshakes,seconds,hs_per_s,server_cpu_util,server_cpu_ms_per_hs" > $out
port=56000
while read suite alg group; do
  for mtls in 0 1; do
    port=$((port+1)); d=$C/$alg/d1
    extra=""; [ $mtls = 1 ] && extra="-Verify 5"
    (cd $d && exec taskset -c 18 $O s_server -accept 127.0.0.1:$port -cert server.pem -key server.key \
        -verifyCAfile root.pem -num_tickets 0 -groups $group -quiet $extra) </dev/null >/dev/null 2>&1 &
    spid=$!; sleep 0.5
    t0=$(awk '{print $14+$15}' /proc/$spid/stat); w0=$(date +%s.%N)
    cnf=data/client_$group.cnf
    printf "openssl_conf = c\n[c]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\n" $group > $cnf
    pids=""
    for c in 5 6 7 8 9 15; do
      cauth=""; [ $mtls = 1 ] && cauth="-cert $d/client.pem -key $d/client.key"
      OPENSSL_CONF=$cnf taskset -c $c $O s_time -connect 127.0.0.1:$port -new -time 10 $cauth </dev/null > data/st_$c.txt 2>&1 &
      pids="$pids $!"
    done
    wait $pids
    t1=$(awk '{print $14+$15}' /proc/$spid/stat); w1=$(date +%s.%N)
    kill $spid; wait $spid 2>/dev/null
    n=$(cat data/st_*.txt | grep -o "^[0-9]* connections in" | awk '{s+=$1} END {print s+0}')
    util=$(echo "($t1-$t0)/100/($w1-$w0)" | bc -l)
    secs=$(echo "$w1-$w0" | bc -l)
    printf "%s,%s,%s,%.2f,%.1f,%.3f,%.4f\n" "$suite" $mtls $n $secs $(echo "$n/$secs" | bc -l) $util $(echo "$util*$secs*1000/$n" | bc -l) >> $out
    rm -f data/st_*.txt
  done
done <<'LIST'
ECDSA-P256|X25519 ECDSA-P256 x25519
ECDSA-P256|X25519MLKEM768 ECDSA-P256 X25519MLKEM768
RSA-2048|ECDHE-P256 RSA-2048 secp256r1
ML-DSA-44|ML-KEM-768 ML-DSA-44 MLKEM768
ML-DSA-65|ML-KEM-768 ML-DSA-65 MLKEM768
ML-DSA-87|ML-KEM-1024 ML-DSA-87 MLKEM1024
LIST
echo CAPACITY_DONE
