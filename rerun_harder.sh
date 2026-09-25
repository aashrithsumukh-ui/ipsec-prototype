#!/bin/bash
# Fresh sweep with heavy netem -> dataset -> evaluation. Writes results to a log.
cd "$(dirname "$0")"
LOG=rerun_result.txt
echo "=== IPsecGuard re-run started $(date) ===" | tee "$LOG"

echo "[0] starting docker + containers" | tee -a "$LOG"
sudo service docker start 2>/dev/null || true
cd testbed
docker compose up -d 2>&1 | tail -2 | tee -a "../$LOG"
sleep 4

echo "[1] clearing old data" | tee -a "../$LOG"
rm -f captures/*.pcap dataset.csv

echo "[2] sweep --repeat 3 (~60 min, heavy netem)  $(date)" | tee -a "../$LOG"
python3 sweep.py --repeat 3 2>&1 | tail -5 | tee -a "../$LOG"

echo "[3] building dataset  $(date)" | tee -a "../$LOG"
python3 build_dataset.py 2>&1 | tail -3 | tee -a "../$LOG"
cd ..

echo "[4] 4-fold grouped CV" | tee -a "$LOG"
python3 evaluate.py testbed/dataset.csv 2>&1 | tee -a "$LOG"

echo "[5] leave-one-config-out CV (strict)" | tee -a "$LOG"
python3 - << 'PY' 2>&1 | tee -a "$LOG"
import numpy as np, pandas as pd
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import accuracy_score, f1_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from ipsecguard.schema import FLOW_FEATURES
df = pd.read_csv("testbed/dataset.csv")
X = df[FLOW_FEATURES].values
le = LabelEncoder(); y = le.fit_transform(df["traffic_type"].values)
groups = df["config_id"].values
accs, f1s = [], []
for tr, te in LeaveOneGroupOut().split(X, y, groups):
    m = XGBClassifier(n_estimators=400, max_depth=4, learning_rate=0.08,
                      subsample=0.9, colsample_bytree=0.8, reg_lambda=2.0,
                      eval_metric="mlogloss", tree_method="hist", random_state=7)
    m.fit(X[tr], y[tr]); p = m.predict(X[te])
    accs.append(accuracy_score(y[te], p)); f1s.append(f1_score(y[te], p, average="macro"))
print(f"LOGO-CV: accuracy {np.mean(accs):.3f} +/- {np.std(accs):.3f}  range {min(accs):.3f}-{max(accs):.3f}")
print(f"LOGO-CV: f1_macro {np.mean(f1s):.3f} +/- {np.std(f1s):.3f}")
PY

echo "[6] refreshing dashboard data" | tee -a "$LOG"
python3 make_real_dashboard.py testbed/dataset.csv 2>&1 | tail -3 | tee -a "$LOG"

echo "=== DONE $(date) ===" | tee -a "$LOG"
echo "Results saved in rerun_result.txt"
