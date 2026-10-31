# Measurements (v2)

Real inputs and a real-handshake validation for the simulator in `../Simulation`.
Platform: NVIDIA GX10 (Arm, 10 x Cortex-X925 + 10 x Cortex-A725), Linux 6.14,
OpenSSL 3.5.4 and liboqs 0.14.0 built from the official releases into `~/opt` (no system changes).

| Step | Script | Output (`data/`) |
|---|---|---|
| CPU per operation (median of 7 x 0.5 s, pinned to cpu 19 = X925 and cpu 4 = A725) | `bench_pqc.c`, `run_bench.sh` | `cpu_openssl_core*.csv`, `cpu_liboqs_core*.csv`, `env.txt` |
| Simulator inputs (patches `../Simulation/pqc_sim.py`) | `make_inputs.py` | `measured_inputs.json` |
| Real DER chains, 8 algorithms x depth 1-4 | `certs.sh` | `certs/` |
| Real TLS 1.3 handshakes through a byte-counting relay (21 per config) | `tls_trace.py`, `relay.py` | `tls_trace.csv` |
| Model vs reality: CPU, certificate sizes, compression, flights | `analyze_measurements.py` | `cpu_summary.csv`, `cert_sizes.csv`, `compression.csv`, `tls_vs_model.csv` |
| Real handshakes replayed over the 5G/6G channel (trace-driven) | `trace_driven.py` | `trace_driven_radio.csv`, `trace_driven_wired.csv` |

```bash
gcc -O2 -o bench_pqc bench_pqc.c -I$HOME/opt/openssl-3.5/include -L$HOME/opt/openssl-3.5/lib -lcrypto
./run_bench.sh && python3 make_inputs.py && ./certs.sh && python3 tls_trace.py 21
python3 analyze_measurements.py && python3 trace_driven.py 500
```

Notes
- `openssl speed` cannot time ML-DSA signing in 3.5.4, hence the EVP harness.
- OpenSSL 3.5 has no TLS code points for SLH-DSA or Falcon: certificates and CPU only.
- No `tc netem` (no administrator rights, unprivileged user namespaces blocked by AppArmor):
  the 5G experiment is trace-driven (real handshake bytes and CPU over the SimPy channel).
- `s_client -quiet` implies `-ign_eof`, so it sends no close_notify; the server's alert is ignored.
- Machine was shared (load 4-11) during measurement; medians and core pinning limit the effect.
