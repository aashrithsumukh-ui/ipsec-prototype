#!/usr/bin/env python3
"""Train the SAME models on REAL testbed data instead of synthetic.
The only change from run_demo.py is the data source line, marked below."""
import os, sys
import pandas as pd
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ipsecguard.classifier import TrafficClassifier
from ipsecguard.anomaly import AnomalyDetector

# ---- the ONE line that changes vs the synthetic demo ----
df = pd.read_csv("dataset.csv")          # was: from ipsecguard.synth import generate; df = generate()
# ---------------------------------------------------------

print(f"[data] {len(df)} real sessions across {df.config_id.nunique()} captures")
clf = TrafficClassifier(); m = clf.fit_eval(df)
print(f"[clf ] accuracy={m['accuracy']:.3f}  f1={m['f1_macro']:.3f}  ({m['split']})")
anom = AnomalyDetector().fit(df)
print(f"[anom] trained on {anom.trained_on} clean sessions")
print("[ok  ] models trained on real captures — identical downstream code")
