"""End-to-end demo on synthetic data: generate -> train -> score a sample ->
emit metrics + a dashboard JSON + reports. Proves the analytical core runs.
Replace synth.generate() with real testbed pcaps via ipsecguard.analyze."""
import json, os
from ipsecguard.synth import generate
from ipsecguard.classifier import TrafficClassifier
from ipsecguard.anomaly import AnomalyDetector
from ipsecguard.scoring import assess
from ipsecguard.report import executive_md, technical_md

os.makedirs("outputs", exist_ok=True)
df = generate(n_configs=160, sessions_per_config=5)
print(f"[data] {len(df)} sessions across {df.config_id.nunique()} configs")

clf = TrafficClassifier(); metrics = clf.fit_eval(df)
print(f"[clf ] accuracy={metrics['accuracy']:.3f}  f1_macro={metrics['f1_macro']:.3f}  "
      f"(train {metrics['n_train']} / test {metrics['n_test']}, {metrics['split']})")
anom = AnomalyDetector().fit(df)
print(f"[anom] trained on {anom.trained_on} clean sessions")

# score two representative sessions: one weak, one strong
def make(observed, inferred):
    r = assess(observed, inferred)
    r["observed"], r["inferred"] = observed, inferred
    return r

weak = make(
    {"enc_algo": "3des-cbc", "integrity": "md5", "dh_group": 5, "ike_version": 1},
    {"traffic_type": "voip", "traffic_conf": 0.82, "pfs": "off", "pfs_conf": 0.71,
     "mode": "transport", "mode_conf": 0.63, "anomaly": True, "anomaly_conf": 0.66})
strong = make(
    {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
    {"traffic_type": "video", "traffic_conf": 0.9, "pfs": "on", "pfs_conf": 0.8,
     "mode": "tunnel", "mode_conf": 0.77, "anomaly": False, "anomaly_conf": 0.0})

for name, r in [("weak", weak), ("strong", strong)]:
    print(f"[score] {name:6s} risk={r['risk_score']:3d}/100  findings={len(r['findings'])}")

bundle = {
    "model_metrics": metrics,
    "anomaly_trained_on": anom.trained_on,
    "sessions": {
        "weak":  {**weak,  "session": "site-A_ikev1_3des_md5_dh5_pfs-off_transport.pcap",
                  "exec_report": executive_md(weak, "site-A (weak)"),
                  "tech_report": technical_md(weak, "site-A (weak)", weak["observed"], weak["inferred"])},
        "strong":{**strong,"session": "site-B_ikev2_aes256gcm_dh20_pfs-on_tunnel.pcap",
                  "exec_report": executive_md(strong, "site-B (strong)"),
                  "tech_report": technical_md(strong, "site-B (strong)", strong["observed"], strong["inferred"])},
    },
}
with open("outputs/analysis.json", "w") as f:
    json.dump(bundle, f, indent=2)
with open("outputs/exec_weak.md", "w") as f:
    f.write(bundle["sessions"]["weak"]["exec_report"])
with open("outputs/tech_weak.md", "w") as f:
    f.write(bundle["sessions"]["weak"]["tech_report"])
print("[out ] outputs/analysis.json + reports written")
