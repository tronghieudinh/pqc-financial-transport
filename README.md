# pqc-financial-transport

Simulator, measurements and paper assets for

> **The transport cost of post-quantum authentication in financial messaging** (Paper 1; the title is fixed at publication)
> Trong-Hieu Dinh (Banking Academy of Vietnam), <hieudt@hvnh.edu.vn>; Trong-Minh Hoang (Posts and Telecommunications Institute of Technology, corresponding author), <hoangtrongminh@ptit.edu.vn>. Submitted to *Computers & Security*.

The study quantifies how the larger keys and signatures of post-quantum cryptography propagate through TLS 1.3, DER X.509
certificate chains and the application-layer signatures of ISO 8583, ISO 20022, SWIFT MX, OAuth 2.0 / OpenID Connect and
FAPI 2.0 on wired paths, with a per-segment transport model that is calibrated on CPU costs measured with OpenSSL 3.5 and
validated against real transactions over a kernel-emulated link.

## Layout

| Directory | Content |
|---|---|
| `Simulation/` | The transport model (`pqc_sim.py`), the independent event-driven cross-check (`crosscheck_simpy.py`), sensitivity and uncertainty analyses, unit tests, `run_paper1.sh` |
| `Measurements/` | CPU benchmark (`bench_pqc.c`), certificate generation (`certs.sh`), TLS handshake and application-object measurements, and their data (`data/`) |
| `Measurements/testbed/` | Network-namespace testbed: `tls_probe.c`, `tbnet.py`, `run_testbed.py`, `run_variants.sh` (CUBIC, delayed ACK, timestamps, BBR), `analyze_testbed.py`, `residual_analysis.py`, `analyze_variants.py`, raw results in `results/` |
| `Measurements/x86/` | The same CPU benchmark on an x86 core, and the comparison with the Arm measurements |
| `paper/` | LaTeX sources of the earlier two-file version of the manuscript (main text and supplementary material) and `make_assets.py`, which generates its tables, figures and numbers from the measurements |
| `manuscript/` | LaTeX source of the merged single-file manuscript (appendices inside), its figures and `data/` (`testbed_configurations.csv`: the 226 validation configurations; `claim_checks.csv`: the source of each headline number; `measurement_checksums.csv`) |

## Reproduce the results (no special hardware)

Python 3.10 or later with `pip install -r requirements.txt`; `latexmk` and a TeX Live installation with `elsarticle` are
needed only to build the PDFs.

```bash
bash reproduce.sh          # simulation sweeps (about a minute), testbed and CPU analysis, tables, figures, numbers, PDFs
```

`reproduce.sh` runs, in order: the unit tests and sweeps (`Simulation/run_paper1.sh`), the analysis of the testbed
measurements (`Measurements/testbed/paper_assets.py`) and of the x86 CPU measurements (`Measurements/x86/analyze_cpu_x86.py`),
and `paper/make_assets.py`. The tables of the merged manuscript (`manuscript/`) were assembled from the outputs of these scripts and are typed in its LaTeX source; `manuscript/data/claim_checks.csv` lists the source of each headline number. `reproduce.sh` also runs the analyses added in v1.3 (ablation of the two stack mechanisms, asymmetric chain depth, uncertainty analysis with the middlebox delay fixed at 0).

## Repeat the measurements (Linux, root for the testbed)

* **CPU costs** (`Measurements/run_bench.sh` on Arm, `Measurements/x86/run_bench_x86.sh` on x86): OpenSSL 3.5.4 and liboqs 0.14.0
  built from the official releases; see `Measurements/README.md` and `Measurements/x86/README.md`.
* **Real certificate chains**: `Measurements/certs.sh` (the test private keys are not distributed and are regenerated).
* **Testbed**: `Measurements/testbed/README.md` (network namespaces, `tc netem`, root; set-up script, smoke test, profiles).
  The raw results of the runs reported in the paper are in `Measurements/testbed/results/*.csv`.

## Data

| File(s) | Content |
|---|---|
| `Measurements/testbed/results/{core_a,segs,segs2,knee,grid_b,cubic,cubic2,delack,ts,delack_ts,bbr,proxy_tcp,proxy_inspect}.csv` | One row per measured transaction: configuration, timings, bytes, kernel segment counters |
| `Measurements/testbed/results/env.json` | Machine, kernel, governor and software versions of a run |
| `Measurements/data/cpu_*_core*.csv`, `Measurements/x86/data/*.csv` | Per-operation CPU costs (Cortex-X925, Cortex-A725, Intel Core i7-5600U) |
| `Measurements/data/*.csv` | Certificate sizes, compression, real TLS handshake flights, application objects |
| `Simulation/results/*.csv` (generated) | Model output for the full wired grid |

## Legacy inputs (not validated, not used by the paper)

`Simulation/loss_sim.py`, `Simulation/radio_sim.py`, `Simulation/mitigations.py` and their outputs
(`Simulation/radio_results/`, `Simulation/sens/radio_*`, `Simulation/mitigations.csv`, `Simulation/loss_results.csv`,
`Simulation/radio_factor_ci.csv`) come from earlier simulations of radio links, mitigations and packet loss. They use the
idealised closed form (`--stack v4`), have **not** been re-validated against the testbed, and none of their results appears in the
paper or its Supplementary Material. They are kept because `paper/make_assets.py` still builds tables and a packet-loss figure
from them (`figures/fig_loss.pdf` and others) that the paper does not include, and for the later papers on these topics.
Do not cite them as validated results.

## Version history

- `paper1-v1.3` (this version): the merged manuscript (`manuscript/`); model code with a separate chain depth for the client (`build_flow(..., depth_client=)`, default unchanged: the checksum of 3,744 model results is identical to v1.2) and `Simulation/asymmetric_depth.py`; `Measurements/testbed/ablation_stack.py` (contribution of each stack mechanism); `Simulation/uncertainty.py --pi0`; the TCP-variant measurements (CUBIC, delayed ACK, timestamps, BBR) repeated with the CPU clock fixed (`run_variants_tuned.sh`; the first session, with the `ondemand` governor, is kept in `results/ondemand_session/`); the WP6 measurements of later work (loss with full and resumed transactions, latency under load, server capacity repeated, packet traces; scripts `run_all_wp6.sh`, `run_latency_resumed.sh`, `run_wp6b.sh`, `trace_run.py`, `capacity_latency.py`, `tls_load_open.c`). The results of Paper 1 are unchanged apart from the repeated variant measurements (MAE 1.19, 1.26, 1.32 and 1.23 ms for CUBIC, delayed ACK, timestamps and both, against 1.13, 1.18, 1.25 and 1.26 ms in the first session).
- `paper1-v1.2`: adds the measurements made after the main campaign (`resume.csv`, `resume_swift.csv`, `capacity_gx10*.csv`
  and their scripts: `tls_serve.c`, `tls_load.c`, `capacity_test.py`, `analyze_resume.py`, `analyze_capacity.py`, `supp_paper1_extra.py`), two
  supplementary tables built from them (S23, S24), a lossy variant of the model and a mitigation study that paper 2 will use
  (`Simulation/loss_sim.py`, `mitigations_wired.py`, `config_selector.py`), and the **erratum** below. Paper 1's results are unchanged.
- `paper1-v1.1.1`: DOI recorded in the manuscript; `paper1-v1.1`: stack-model validation under CUBIC, delayed ACKs, timestamps and BBR.

## Erratum

`Measurements/data/capacity.csv` and `Measurements/capacity.sh` (server capacity measured with `openssl s_time -new`) overstate the handshake rate
by a factor of 2, because `s_time` counts every handshake twice; see `Measurements/data/capacity_ERRATUM.md`. Paper 1 does not use these
numbers. The corrected measurement is `Measurements/testbed/capacity_test.py` (results in `Measurements/testbed/results/capacity_*.csv`).

## Known limits

The model was validated on one stack: Linux TCP with Reno, OpenSSL 3.5, one machine, one TCP proxy. See the Limitations
section of the paper. The Docker recipe of earlier versions was not carried over because it could not be tested.

## Licence and citation

Code: MIT (`LICENSE`). Data: CC BY 4.0 (`LICENSE-DATA.md`). Please cite the paper and this repository (`CITATION.cff`).
