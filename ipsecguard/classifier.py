"""Traffic-type classifier (INFERRED layer).

Predicts what kind of traffic rides inside an encrypted ESP tunnel, from flow
metadata alone. The single most important correctness rule is the HELD-OUT
CONFIG SPLIT: train and test never share a config_id, so we measure whether the
model learned traffic shape rather than memorising a tunnel. Without this, the
accuracy numbers are fiction.
"""
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from .schema import FLOW_FEATURES

class TrafficClassifier:
    def __init__(self):
        self.model = XGBClassifier(
            n_estimators=300, max_depth=5, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9, eval_metric="mlogloss",
            tree_method="hist", random_state=7)
        self.le = LabelEncoder()
        self.metrics = {}

    def fit_eval(self, df):
        X = df[FLOW_FEATURES].values
        y = self.le.fit_transform(df["traffic_type"].values)
        groups = df["config_id"].values
        # held-out CONFIG split — disjoint tunnels in train vs test
        gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=7)
        tr, te = next(gss.split(X, y, groups))
        self.model.fit(X[tr], y[tr])
        pred = self.model.predict(X[te])
        self.metrics = {
            "accuracy": float(accuracy_score(y[te], pred)),
            "f1_macro": float(f1_score(y[te], pred, average="macro")),
            "labels": list(self.le.classes_),
            "confusion": confusion_matrix(y[te], pred).tolist(),
            "n_train": int(len(tr)), "n_test": int(len(te)),
            "split": "held-out by config_id (disjoint tunnels)",
            "feature_importance": dict(sorted(
                zip(FLOW_FEATURES, self.model.feature_importances_.astype(float)),
                key=lambda kv: kv[1], reverse=True)),
        }
        return self.metrics

    def predict_one(self, feat_row):
        x = np.array([[feat_row[f] for f in FLOW_FEATURES]], dtype=float)
        proba = self.model.predict_proba(x)[0]
        idx = int(np.argmax(proba))
        return self.le.classes_[idx], float(proba[idx])
