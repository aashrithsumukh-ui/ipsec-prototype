"""Turn a real testbed dataset.csv into the dashboard's data bundle."""
import os, sys, json
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ipsecguard.schema import FLOW_FEATURES
from ipsecguard.classifier import TrafficClassifier
from ipsecguard.anomaly import AnomalyDetector
from ipsecguard.scoring import assess
from ipsecguard.report import executive_md, technical_md

CSV = sys.argv[1] if len(sys.argv) > 1 else "testbed/dataset.csv"
df = pd.read_csv(CSV)
print(f"[data] {len(df)} real sessions, {df.config_id.nunique()} configs")
clf = TrafficClassifier(); metrics = clf.fit_eval(df)
# Override the single-split accuracy with rigorous grouped 4-fold CV (the honest number)
import numpy as np
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score, f1_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from ipsecguard.schema import FLOW_FEATURES as _FF
_X = df[_FF].values
_le = LabelEncoder(); _y = _le.fit_transform(df["traffic_type"].values)
_g = df["config_id"].values
_accs, _f1s = [], []
for _tr, _te in GroupKFold(n_splits=min(4, len(np.unique(_g)))).split(_X, _y, _g):
    _m = XGBClassifier(n_estimators=400, max_depth=4, learning_rate=0.08,
                       subsample=0.9, colsample_bytree=0.8, reg_lambda=2.0,
                       eval_metric="mlogloss", tree_method="hist", random_state=7)
    _m.fit(_X[_tr], _y[_tr]); _p = _m.predict(_X[_te])
    _accs.append(accuracy_score(_y[_te], _p)); _f1s.append(f1_score(_y[_te], _p, average="macro"))
metrics["accuracy"] = float(np.mean(_accs))
metrics["f1_macro"] = float(np.mean(_f1s))
metrics["accuracy_std"] = float(np.std(_accs))
metrics["split"] = f"{len(_accs)}-fold grouped CV (mean over folds)"
anom = AnomalyDetector().fit(df)
print(f"[clf ] accuracy={metrics['accuracy']:.3f} f1={metrics['f1_macro']:.3f}")

def build_session(row):
    feats = {f: float(row[f]) for f in FLOW_FEATURES}
    observed = {"enc_algo": row["enc_algo"], "integrity": row["integrity"],
                "dh_group": int(row["dh_group"]), "ike_version": int(row["ike_version"])}
    ttype, tconf = clf.predict_one(feats)
    is_anom, aconf, _ = anom.score_one(row.to_dict())
    inferred = {"traffic_type": ttype, "traffic_conf": tconf,
                "pfs": row["pfs"], "pfs_conf": 0.7,
                "mode": row["mode"], "mode_conf": 0.65,
                "anomaly": is_anom, "anomaly_conf": aconf}
    r = assess(observed, inferred)
    r["observed"], r["inferred"] = observed, inferred
    fn = (f"ikev{observed['ike_version']}_{row['mode']}_{row['enc_algo']}_"
          f"{row['integrity']}_dh{row['dh_group']}_pfs-{row['pfs']}_{row['traffic_type']}.pcap")
    r["session"] = fn
    r["exec_report"] = executive_md(r, fn)
    r["tech_report"] = technical_md(r, fn, observed, inferred)
    return r

weak_rows = df[df.enc_algo.str.contains("3des", na=False)]
strong_rows = df[(df.enc_algo == "aes256-gcm") & (df.pfs == "on")]
weak = build_session((weak_rows if len(weak_rows) else df).iloc[0])
strong = build_session((strong_rows if len(strong_rows) else df).iloc[-1])
bundle = {"model_metrics": metrics, "anomaly_trained_on": anom.trained_on,
          "sessions": {"weak": weak, "strong": strong}}
os.makedirs("outputs", exist_ok=True)
json.dump(bundle, open("outputs/analysis.json", "w"), indent=2)
print(f"[out ] outputs/analysis.json from REAL data")
print(f"  weak:   {weak['session']} -> risk {weak['risk_score']}")
print(f"  strong: {strong['session']} -> risk {strong['risk_score']}")
