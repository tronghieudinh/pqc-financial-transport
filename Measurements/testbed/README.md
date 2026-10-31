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
