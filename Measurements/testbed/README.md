# Testbed: real OpenSSL 3.5 TLS 1.3 transactions over an emulated network

Purpose (paper 1, section "Testbed calibration"): check the transport model of `../../Simulation/pqc_sim.py`
against real handshakes that run through the Linux TCP stack over a link with controlled RTT, rate, MTU, loss
and initial window, and estimate the middlebox penalty (`pi`, `theta`) that the model leaves as a free parameter.

Target machine: Linux Mint, Core i7-5600U (2 cores / 4 threads), 8 GB RAM, root (sudo) available.

## What runs
```
client ns (pqcc) --vc0 ==== vs0-- server ns (pqcs)          topology "direct"
client ns (pqcc) --vc0 ==== vp0-- proxy ns (pqcp: HAProxy) --vp1 ==== vs0-- server ns    "proxy-tcp" / "proxy-inspect"
```
* IPv6 everywhere, TCP timestamps off -> MSS = MTU - 60, exactly the 40 + 20 header bytes of the model.
* `tc netem` (delay RTT/2 per direction, `rate`, `loss`) on both ends of the client link; GSO/TSO/GRO off.
* Per-peer routes: `initcwnd`, `initrwnd 100` (the model has no receive-window limit), `congctl reno`
  (the model is ACK-clocked slow start), `quickack 1`.
* `tls_probe` (C, OpenSSL 3.5): new TCP connection + full TLS 1.3 handshake (no tickets) + one request/response
  (default 302/222 B = ISO 8583 0200/0210), mutual TLS with the real DER chains of `../certs/`.
  It reports `t_tcp`, `t_hs`, `t_total`, bytes, and the MSS / initial cwnd the kernel actually used.
* Client and server are pinned to different physical cores (`lscpu`), HAProxy to the sibling thread.

## Procedure
```bash
cd Measurements/testbed
./setup_host.sh                      # once: packages, OpenSSL 3.5 in ~/opt, tls_probe, certificates
sudo ./host_tune.sh on               # performance governor, no turbo (restored by "off")
./check_env.sh                       # netns/netem/route metrics + one shaped transaction
sudo python3 run_testbed.py --profile smoke                       # ~2 min
python3 analyze_testbed.py results/testbed_raw.csv                # first look at model vs measurement
sudo python3 run_testbed.py --profile core --n 30                 # a few hours; resumable (re-run the same command)
sudo python3 run_testbed.py --profile proxy --topology proxy-tcp  # real middlebox (HAProxy, TCP proxy)
sudo python3 run_testbed.py --profile proxy --topology proxy-inspect   # HAProxy waiting for the full ClientHello
sudo python3 run_testbed.py --profile loss --n 200                # loss tails
python3 analyze_testbed.py results/testbed_raw.csv
sudo ./host_tune.sh off
```
`--list` prints the number of configurations and a time estimate; any axis can be overridden, for example
`--rtts 30 --rates 100 --mtus 1500 --depths 1,2,3,4 --suites "ML-DSA-65|ML-KEM-768"`.
`--profile full` (both mutual-TLS modes, initial window 10 and 32) takes about a night.

Do not use the machine for anything else during a run (two cores only), keep it on mains power, and let it
cool down if `host_tune.sh status` shows throttled frequencies.

### First-run validation with tcpdump (recommended once)
```bash
sudo python3 run_testbed.py --profile smoke --suites "ML-DSA-65|ML-KEM-768" --depths 3 --rtts 100 --n 3 --keep &
sleep 8; sudo ip netns exec pqcc tcpdump -i vc0 -nn -c 80 'tcp port 4433'   # while it runs
```
The server's first flight must be 10 segments of 1440 B, then a pause of one RTT before more data.
`sudo python3 tbnet.py down` removes the namespaces (also done automatically at the end of a run).

## Outputs (`results/`)
| file | content |
|---|---|
| `testbed_raw.csv` | one row per transaction (compress with gzip before committing a full sweep) |
| `env.json` | kernel, CPU, governor, turbo, OpenSSL version, arguments |
| `testbed_summary.csv` | median / p10 / p90 per configuration |
| `model_vs_testbed.csv` | measured excess latency vs model (T - T_cpu), size check, round-trip equivalents |
| `model_vs_testbed_stats.txt` | bias, MAE, relative error, Spearman rank correlation per suite, worst cases |
| `pi_theta_fit.csv` | least-squares `pi` for every threshold `theta` on the direct path |
| `proxy_delta.csv` | latency added by the real middlebox over the direct path (+ fit of pi, theta) |
| `model_vs_testbed.png` | scatter |

## How the comparison works
Excess = median time of a shaped configuration - median time of the unshaped "base" run of the same suite,
depth and mutual-TLS mode. Computation and library overhead lie on the critical path in both and cancel.
It is compared with `T - T_cpu` of `pqc_sim.run_flow()` for the same flow, link, MTU and initial window.
`size_ratio` compares the model's L7 bytes with the TLS bytes read and written by the client (expected 0.95-1.06).
If the direct path gives a fitted `pi` near 0, the kernel path supports the lower bound `pi = 0`; a real middlebox
adds latency (`proxy_delta.csv`), which is the empirical estimate of `pi` and `theta`.

## Known limits (state them in the paper)
* Only one pair of cores: client and server share the CPU package; the base run removes the common cost.
* netem `rate` counts the Ethernet header (14 B per packet) that the model does not; negligible at 1500 B, about 1 % at 1280 B.
* Reno with quickack, no timestamps and a large receive window is the closest Linux match to the model, not what
  production servers run (CUBIC, delayed ACK, timestamps): add `--cc cubic` runs to quantify the difference.
* HAProxy in TCP mode is one real middlebox, not all of them; the penalty is specific to it.
* `tbnet.py` and the proxy mode could not be run on the development machine (no root there). The probe, the
  orchestrator and the analysis were tested on loopback. If `check_env.sh` or the smoke run reports a problem
  with the namespace setup, fix `tbnet.py` first (every command it runs is shown by `python3 tbnet.py up --dry-run`).

## Extra TCP settings (revision of paper 1)

`run_variants.sh` repeats part of the grid with other kernel settings: CUBIC on a wider grid (`cubic2`), delayed ACKs (`delack`),
TCP timestamps (`ts`, MSS = MTU - 72) and both (`delack_ts`), optionally BBR (`BBR=1`, exploratory). `analyze_variants.py` compares each
variant with the stack model and, configuration by configuration, with the Reno / quick-ACK / no-timestamps measurements.

    sudo ./host_tune.sh on            # as before the other runs; "sudo ./host_tune.sh off" afterwards
    sudo bash run_variants.sh         # about 2 hours; resumable
    python3 analyze_variants.py       # no root; writes results/variants_summary.csv and the LaTeX table/numbers

## Session resumption (paper 2, WP1)

`tls_probe --resume` (both sides) measures RESUMED transactions: the client first runs a full transaction on its own connection to
obtain a TLS 1.3 ticket, then opens a new TCP connection that offers it (PSK with (EC)DHE key exchange, server tickets stateless; under
mutual TLS OpenSSL puts the client certificate in the ticket). The row of the resumed transaction carries `reused` (1 if the session
really was resumed; otherwise the row is an error `not_resumed`) and `prime_ms`, the total time of the full transaction just before it,
under the same network conditions. `run_testbed.py --resume` selects it; `run_resume.sh` runs the grids of paper 2 (about an hour);
`analyze_resume.py` compares the measurements with the stack model (`mode "resumed"`) and with the full handshake. Rebuild `tls_probe`
(`./setup_host.sh`) after pulling.

## Server capacity (paper 2, WP2)

`tls_serve` is an event-driven (epoll, non-blocking) TLS 1.3 server, one thread per process (`--reuseport` + `taskset` per core);
`tls_load` is a multi-threaded closed-loop load generator (new connection, handshake full or resumed, one request/response, close);
`capacity_test.py` starts the servers pinned to the server cores, saturates them from the other cores and reads the CPU time and the
number of completed transactions of each server process with SIGUSR1 over a measurement window. `analyze_capacity.py` compares the
CPU per transaction with the sum of the measured primitive costs. `run_capacity.sh` has the commands for the i7-5600U and the Arm
platform. Loopback only: it measures TLS, kernel and event-loop cost of the server, not NIC and interrupt cost of a real path.
`tls_probe server --reuseport` (blocking, one connection at a time) is kept for comparison (`capacity_test.py --server tls_probe`).
