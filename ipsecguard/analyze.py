"""Analyze ONE real testbed pcap end-to-end with trained models.

    from ipsecguard.analyze import analyze_pcap
    result = analyze_pcap("cap.pcap", clf, anom)

This is the production path: real capture -> observed parse + flow features ->
ML inference -> NIST scoring -> tagged findings. Same models, same scoring as
the synthetic demo; only the front door changes.
"""
from .features import extract_flow_features
from .parser import parse_ike
from .scoring import assess
from .report import executive_md, technical_md

def analyze_pcap(pcap_path, clf, anom, pfs_hint=None, mode_hint=None):
    observed = parse_ike(pcap_path)                 # certain fields
    feats = extract_flow_features(pcap_path)        # ESP metadata

    ttype, tconf = clf.predict_one(feats)
    is_anom, aconf, _ = anom.score_one({**feats,
        "enc_algo": observed.get("enc_algo") or "aes256-gcm",
        "integrity": observed.get("integrity") or "sha256",
        "dh_group": observed.get("dh_group") or 19, "pfs": pfs_hint or "on"})

    inferred = {
        "traffic_type": ttype, "traffic_conf": tconf,
        "pfs": pfs_hint, "pfs_conf": 0.7 if pfs_hint else None,
        "mode": mode_hint, "mode_conf": 0.6 if mode_hint else None,
        "anomaly": is_anom, "anomaly_conf": aconf,
    }
    result = assess(observed, inferred)
    result["session"] = pcap_path
    result["observed"] = observed
    result["inferred"] = inferred
    result["flow_features"] = feats
    result["exec_report"] = executive_md(result, pcap_path)
    result["tech_report"] = technical_md(result, pcap_path, observed, inferred)
    return result
