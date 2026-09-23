"""Attack Impact & Validation Demo script.

Runs the AttackValidationEngine across baseline and attack sessions,
prints a summary to console, and writes outputs/attack_impact_validation.json.
"""
import json
import os
from ipsecguard import compare_sessions

def main():
    os.makedirs("outputs", exist_ok=True)
    analysis_file = "outputs/analysis.json"

    if os.path.exists(analysis_file):
        with open(analysis_file) as f:
            data = json.load(f)
        base_s = data["sessions"]["strong"]
        atk_s = data["sessions"]["weak"]
    else:
        # Fallback inline sessions if analysis.json is absent
        base_s = {
            "session": "baseline_strong.pcap",
            "observed": {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
            "inferred": {"traffic_type": "web", "pfs": "on", "mode": "tunnel", "anomaly": False, "anomaly_conf": 0.0}
        }
        atk_s = {
            "session": "downgraded_weak.pcap",
            "observed": {"enc_algo": "3des-cbc", "integrity": "md5", "dh_group": 2, "ike_version": 1},
            "inferred": {"traffic_type": "bulk", "pfs": "off", "mode": "transport", "anomaly": True, "anomaly_conf": 0.82}
        }

    print("=" * 65)
    print(" IPsecGuard AI — Attack Impact & Validation Engine ")
    print("=" * 65)

    result = compare_sessions(base_s, atk_s)

    print(f"\n[+] BASELINE SESSION : {result['baseline_session']['session_id']}")
    print(f"    - Risk Score     : {result['baseline_session']['risk_score']}/100 ({result['baseline_session']['posture']})")
    print(f"    - Observed Suite : {result['baseline_session']['observed'].get('enc_algo')} | DH-{result['baseline_session']['observed'].get('dh_group')}")

    print(f"\n[+] ATTACK SESSION   : {result['attack_session']['session_id']}")
    print(f"    - Risk Score     : {result['attack_session']['risk_score']}/100 ({result['attack_session']['posture']})")
    print(f"    - Observed Suite : {result['attack_session']['observed'].get('enc_algo')} | DH-{result['attack_session']['observed'].get('dh_group')}")

    print(f"\n[!] SECURITY IMPACT  : {result['detected_security_impact']['severity'].upper()}")
    print(f"    - Score Delta    : {result['security_score']['difference']:+d} pts ({result['security_score']['posture_transition']})")
    print(f"    - Summary        : {result['detected_security_impact']['impact_summary']}")

    print("\n[+] DETECTED CONFIGURATION CHANGES:")
    for ch in result["detected_configuration_changes"]["changes"]:
        flag = " [DOWNGRADE]" if ch.get("downgraded") else ""
        print(f"    * {ch['parameter']:12s}: {ch['baseline']} -> {ch['attack']} (Impact: {ch['impact_level']}){flag}")

    print(f"\n[+] ANOMALY STATUS   :")
    anom = result["anomaly_detection"]
    print(f"    - Attack Anomaly : {anom['attack_anomaly']} (Confidence: {anom['anomaly_confidence']*100:.1f}%)")
    print(f"    - Note           : {anom['details']}")

    print(f"\n[+] CONFIDENCE & LIMITATIONS:")
    print(f"    - Overall Conf.  : {result['confidence_level']['overall'].upper()} ({result['confidence_level']['confidence_score']*100:.0f}%)")
    print(f"    - Limitations    : {len(result['limitations'])} note(s) recorded.")

    out_path = "outputs/attack_impact_validation.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    report_path = "outputs/validation_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(result.get("validation_report", ""))

    print(f"\n[>] Structured JSON successfully written to: {out_path}")
    print(f"[>] Evidence Markdown report written to   : {report_path}\n" + "=" * 65)

if __name__ == "__main__":
    main()
