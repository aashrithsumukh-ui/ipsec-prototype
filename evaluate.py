"""Grouped k-fold CV: rotates which security profiles are held out, reports
the mean +/- std instead of one split's lucky/unlucky number."""
import os, sys
import numpy as np, pandas as pd
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ipsecguard.schema import FLOW_FEATURES

CSV = sys.argv[1] if len(sys.argv) > 1 else "testbed/dataset.csv"
df = pd.read_csv(CSV)
X = df[FLOW_FEATURES].values
le = LabelEncoder(); y = le.fit_transform(df["traffic_type"].values)
groups = df["config_id"].values
k = min(4, len(np.unique(groups)))
print(f"[eval] {len(df)} sessions, {len(np.unique(groups))} configs, {k}-fold grouped CV\n")

gkf = GroupKFold(n_splits=k)
accs, f1s, yt, yp = [], [], [], []
for i, (tr, te) in enumerate(gkf.split(X, y, groups), 1):
    m = XGBClassifier(n_estimators=400, max_depth=4, learning_rate=0.08,
                      subsample=0.9, colsample_bytree=0.8, reg_lambda=2.0,
                      eval_metric="mlogloss", tree_method="hist", random_state=7)
    m.fit(X[tr], y[tr]); p = m.predict(X[te])
    a, f = accuracy_score(y[te], p), f1_score(y[te], p, average="macro")
    accs.append(a); f1s.append(f); yt += list(y[te]); yp += list(p)
    print(f"  fold {i}: acc={a:.3f}  f1={f:.3f}")
print(f"\n[result] accuracy {np.mean(accs):.3f} +/- {np.std(accs):.3f}"
      f"   f1_macro {np.mean(f1s):.3f} +/- {np.std(f1s):.3f}")
print("\n[per-class]")
print(classification_report(yt, yp, target_names=le.classes_, zero_division=0))
