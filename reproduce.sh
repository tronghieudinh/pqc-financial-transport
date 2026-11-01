#!/usr/bin/env bash
# Regenerate every simulation result, table, figure and number of the paper, and build the PDFs.
#   PY=python3 bash reproduce.sh
# The testbed and x86 measurements themselves need a Linux machine with root (see Measurements/testbed/README.md and
# Measurements/x86/README.md); their raw results are included, this script only analyses them.
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
(cd Simulation && PY=$PY ./run_paper1.sh)
(cd Measurements/testbed && $PY paper_assets.py && $PY residual_analysis.py && { [ -f results/delack.csv ] && $PY analyze_variants.py || true; })
(cd Measurements/testbed && { [ -f results/resume.csv ] && $PY analyze_resume.py results/resume.csv $( [ -f results/resume_swift.csv ] && echo results/resume_swift.csv ) >/dev/null || true; } && { [ -f results/capacity_gx10.csv ] && $PY analyze_capacity.py results/capacity_gx10.csv --costs x925 >/dev/null || true; } && $PY supp_paper1_extra.py >/dev/null)
(cd Measurements/x86 && $PY analyze_cpu_x86.py)
(cd Simulation && $PY asymmetric_depth.py >/dev/null && $PY uncertainty.py --pi0 >/dev/null)      # v1.3: asymmetric chain depth; uncertainty analysis with the middlebox delay at 0
(cd Measurements/testbed && $PY ablation_stack.py >/dev/null)                                       # v1.3: contribution of each stack mechanism (uses manuscript/data/testbed_configurations.csv)
(cd paper && rm -f des_check.json && $PY make_assets.py)
if command -v latexmk >/dev/null 2>&1; then
  (cd paper && latexmk -pdf -interaction=nonstopmode main.tex supplementary.tex)
else
  echo "latexmk not found: tables, figures and numbers were generated in paper/, the PDFs were not built"
fi
echo "done"
