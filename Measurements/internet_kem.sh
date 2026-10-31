#!/usr/bin/env bash
# Real-Internet comparison of classical (X25519) and hybrid (X25519MLKEM768) key establishment.
# 100 interleaved rounds per server; 0.2 s pause between handshakes.
set -u
cd "$(dirname "$0")"
export LD_LIBRARY_PATH=$HOME/opt/openssl-3.5/lib
out=data/internet_kem.csv
echo "host,round,group,tcp_ms,handshake_ms,bytes_out,bytes_in,negotiated" > $out
for r in $(seq 1 100); do
  for h in cloudflare.com www.google.com; do
    for g in x25519 X25519MLKEM768; do
      line=$(taskset -c 19 ./tls_client_time $h 443 $g 2>/dev/null) && echo "$h,$r,$line" >> $out
      sleep 0.2
    done
  done
done
echo "INTERNET_DONE $(wc -l < $out)"
