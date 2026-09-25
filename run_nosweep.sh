#!/bin/bash
# IPsecGuard AI — full run WITHOUT re-sweeping. Uses existing testbed/dataset.csv.
# Deterministic: same dataset + fixed seeds = same accuracy every run.
set -e
cd "$(dirname "$0")"
B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; R=$'\033[0m'
sec(){ echo; echo "${B}${C}===== $1 =====${R}"; }

sec "0. Dependencies"
pip install --break-system-packages -q -r requirements.txt pytest 2>/dev/null || \
  pip install --break-system-packages -q fastapi "uvicorn[standard]" python-multipart pytest \
    xgboost scikit-learn pandas numpy scapy reportlab
echo "${G}deps ready${R}"

sec "1. Check dataset exists"
if [ ! -f testbed/dataset.csv ]; then
  echo "${Y}testbed/dataset.csv missing — cannot run without it. Restore it or run a sweep.${R}"
  exit 1
fi
echo "${G}dataset found: $(wc -l < testbed/dataset.csv) rows${R}"

sec "2. Test suite"
python3 -m pytest test_*.py -q || { echo "${Y}tests failed${R}"; exit 1; }

sec "3. Core pipeline demo"
python3 run_demo.py 2>/dev/null | grep -E "clf|score|out" || true

sec "4. Classifier evaluation (grouped k-fold CV)"
python3 evaluate.py testbed/dataset.csv

sec "5. Attack validation demo"
python3 run_validation_demo.py 2>/dev/null | grep -iE "IMPACT|delta|written|DOWNGRADE" | head -8 || true

sec "6. Refresh dashboard data (NO build_dashboard.py — keeps the good UI)"
python3 make_real_dashboard.py testbed/dataset.csv 2>/dev/null | grep -E "clf|out" || true

sec "7. Launch dashboard"
echo "Open ${B}http://localhost:8000${R}  ·  Ctrl+C to stop"
( sleep 3; explorer.exe "http://localhost:8000" 2>/dev/null || true ) &
uvicorn app:app --port 8000
