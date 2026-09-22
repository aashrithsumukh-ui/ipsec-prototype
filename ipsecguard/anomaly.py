"""Anomaly detector (INFERRED layer).

Isolation Forest trained ONLY on well-configured, clean sessions. Anything that
deviates from that baseline is flagged for an analyst — this is the part that
catches problems no explicit rule was written for (e.g. an on-path relay's
timing distortion during a downgrade attempt).
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from .schema import FLOW_FEATURES

def _is_clean(row):
    weak_enc = row["enc_algo"] in ("3des-cbc",)
    weak_int = row["integrity"] in ("md5", "sha1")
    weak_dh  = row["dh_group"] in (2, 5)
    return not (weak_enc or weak_int or weak_dh or row["pfs"] == "off")

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(n_estimators=200, contamination=0.06,
                                     random_state=7)
        self.trained_on = 0

    def fit(self, df):
        clean = df[df.apply(_is_clean, axis=1)]
        self.model.fit(clean[FLOW_FEATURES].values)
        self.trained_on = int(len(clean))
        return self

    def score_one(self, feat_row):
        x = np.array([[feat_row[f] for f in FLOW_FEATURES]], dtype=float)
        raw = float(self.model.score_samples(x)[0])   # higher = more normal
        is_anom = bool(self.model.predict(x)[0] == -1)
        # map to a 0..1 'anomaly confidence' for the report
        conf = float(np.clip((-(raw) - 0.35) / 0.35, 0, 1)) if is_anom else 0.0
        return is_anom, conf, raw
