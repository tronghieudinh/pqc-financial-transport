# pqc-financial-transport

Simulator, measurements and paper assets for

> **Round Trips, Not Computation: A Testbed-Validated Transport Model of Post-Quantum Authentication in Financial Messaging over TLS 1.3**
> Trong-Hieu Dinh (Banking Academy of Vietnam), <hieudt@hvnh.edu.vn>. Submitted to *Computers & Security*.

The study quantifies how the larger keys and signatures of post-quantum cryptography propagate through TLS 1.3, DER X.509
certificate chains and the application-layer signatures of ISO 8583, ISO 20022, SWIFT MX, OAuth 2.0 / OpenID Connect and
FAPI 2.0 on wired paths, with a per-segment transport model that is calibrated on CPU costs measured with OpenSSL 3.5 and
validated against real transactions over a kernel-emulated link.

## Layout

| Directory | Content |
|---|---|
| `Simulation/` | The transport model (`pqc_sim.py`), the independent event-driven cross-check (`crosscheck_simpy.py`), sensitivity and uncertainty analyses, unit tests, `run_paper1.sh` |
| `Measurements/` | CPU benchmark (`bench_pqc.c`), certificate generation (`certs.sh`), TLS handshake and application-object measurements, and their data (`data/`) |
| `Measurements/testbed/` | Network-namespace testbed: `tls_probe.c`, `tbnet.py`, `run_testbed.py`, `analyze_testbed.py`, raw results in `results/` |
| `Measurements/x86/` | The same CPU benchmark on an x86 core, and the comparison with the Arm measurements |
| `paper/` | LaTeX sources of the paper and its supplementary material, and `make_assets.py`, which generates every table, figure and number |

## Reproduce the results (no special hardware)

Python 3.10 or later with `pip install -r requirements.txt`; `latexmk` and a TeX Live installation with `elsarticle` are
needed only to build the PDFs.

```bash
bash reproduce.sh          # simulation sweeps (about a minute), testbed and CPU analysis, tables, figures, numbers, PDFs
```

`reproduce.sh` runs, in order: the unit tests and sweeps (`Simulation/run_paper1.sh`), the analysis of the testbed
measurements (`Measurements/testbed/paper_assets.py`) and of the x86 CPU measurements (`Measurements/x86/analyze_cpu_x86.py`),
and `paper/make_assets.py`. No number in the paper is typed by hand except those listed in the comments of `paper/main.tex`.

## Repeat the measurements (Linux, root for the testbed)

* **CPU costs** (`Measurements/run_bench.sh` on Arm, `Measurements/x86/run_bench_x86.sh` on x86): OpenSSL 3.5.4 and liboqs 0.14.0
  built from the official releases; see `Measurements/README.md` and `Measurements/x86/README.md`.
* **Real certificate chains**: `Measurements/certs.sh` (the test private keys are not distributed and are regenerated).
* **Testbed**: `Measurements/testbed/README.md` (network namespaces, `tc netem`, root; set-up script, smoke test, profiles).
  The raw results of the runs reported in the paper are in `Measurements/testbed/results/*.csv`.

## Data

| File(s) | Content |
|---|---|
| `Measurements/testbed/results/{core_a,segs,segs2,knee,grid_b,cubic,proxy_tcp,proxy_inspect}.csv` | One row per measured transaction: configuration, timings, bytes, kernel segment counters |
| `Measurements/testbed/results/env.json` | Machine, kernel, governor and software versions of a run |
| `Measurements/data/cpu_*_core*.csv`, `Measurements/x86/data/*.csv` | Per-operation CPU costs (Cortex-X925, Cortex-A725, Intel Core i7-5600U) |
| `Measurements/data/*.csv` | Certificate sizes, compression, real TLS handshake flights, application objects |
| `Simulation/results/*.csv` (generated) | Model output for the full wired grid |

## Legacy inputs

`Simulation/radio_results/`, `Simulation/sens/radio_*`, `Simulation/mitigations.csv`, `Simulation/loss_results.csv` and
`Simulation/radio_factor_ci.csv` come from earlier simulations of radio links, mitigations and packet loss, which use the
idealised closed form (`--stack v4`) and have not been re-validated. They are included only because `paper/make_assets.py`
also builds tables that this paper does not use, and one supplementary figure (packet loss) shows them with that caveat.
They are not part of the conclusions.

## Known limits

The model was validated on one stack: Linux TCP with Reno, OpenSSL 3.5, one machine, one TCP proxy. See the Limitations
section of the paper. The Docker recipe of earlier versions was not carried over because it could not be tested.

## Licence and citation

Code: MIT (`LICENSE`). Data: CC BY 4.0 (`LICENSE-DATA.md`). Please cite the paper and this repository (`CITATION.cff`).
