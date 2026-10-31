# x86 CPU costs (paper 1, "Measurements" and the CPU-scale assumption)

The simulator's CPU inputs were measured on an Arm Cortex-X925 core; the paper scales them by 2 (measured Cortex-A725),
4 and 16 as *assumptions* for other hardware. This directory measures the same primitives, with the same method, on the
x86 testbed machine (Core i7-5600U, Broadwell, AVX2, no AVX-512, no SHA extensions) so that the factor is measured
for one x86 core, and checks the CPU model against the unshaped transactions of the testbed.

## Run (on the x86 machine; nothing else running)
```bash
cd Measurements/x86
./build_liboqs.sh                     # once: liboqs 0.14.0 for Falcon (5-15 min); OpenSSL 3.5 comes from testbed/setup_host.sh
sudo ../testbed/host_tune.sh on       # performance governor, no turbo
./run_bench_x86.sh                    # about 5 minutes -> data/cpu_openssl_x86.csv, cpu_liboqs_x86.csv, env_x86.txt
sudo ../testbed/host_tune.sh off
```
`run_bench_x86.sh` warns if the governor is not `performance` or turbo is on. Use `./run_bench_x86.sh 1` to pin another CPU.

## Analyse (any machine with the repository)
```bash
python3 analyze_cpu_x86.py            # -> data/cpu_x86_vs_arm.csv, data/cpu_validation.csv,
                                      #    ../../paper/numbers_cpu.tex, tables/tab_cpu_x86.tex
```
* `cpu_x86_vs_arm.csv`: every primitive, X925 / A725 / x86 cost and the ratios.
* `cpu_validation.csv`: median time of an unshaped testbed transaction against the sum of the modelled CPU steps built
  from the x86 costs; the residual is the library, kernel and scheduling overhead that the model does not contain.

The x86 costs are **not** written into `Simulation/pqc_sim.py` (it keeps the X925 values, `make_inputs.py`).
