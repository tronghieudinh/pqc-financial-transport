# Erratum: `capacity.csv` (and `Measurements/capacity.sh`) overstate the handshake rate by a factor of 2

Found 2026-11-01 while building the server-capacity test of paper 2 (`Measurements/testbed/capacity_test.py`).

`capacity.sh` counts handshakes with `openssl s_time -new`. Comparing that count with the number of handshakes the server itself
completed (`tls_serve`, counter `SSL_accept() == 1`) over the same window gave **26,132 completed server handshakes for 52,264
connections reported by `s_time`: `s_time` reports twice the number of handshakes the server performs.** Hence in `capacity.csv`
`handshakes`, `hs_per_s` are twice too high and `server_cpu_ms_per_hs` twice too low (for example ECDSA-P256 with server
authentication: 0.066 ms reported, about 0.13 ms real; measured again with the new harness: 0.134 ms, 7,457 handshakes/s/core on one
Cortex-X925 core). The ratios between suites are unaffected, because every row is off by the same factor.

Consequences
- Paper 1 does not use these numbers (they are in paper 2's server-capacity section only; `numbers.tex` still defines unused `\cap...` macros).
- Do not cite `capacity.csv`. Use `Measurements/testbed/results/capacity_*.csv` (event-driven server, load generator `tls_load`, CPU of the
  server processes read from the processes themselves, normalised by the transactions the server completed).
- The files are left unchanged as the record of the earlier measurement.
