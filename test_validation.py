"""Unit tests for the Attack Impact & Validation Engine."""
import json
import os
import unittest
from ipsecguard import AttackValidationEngine, compare_sessions
from ipsecguard.scoring import assess

class TestAttackValidationEngine(unittest.TestCase):

    def setUp(self):
        self.engine = AttackValidationEngine()
        # Load existing analysis sample if available
        self.analysis_path = "outputs/analysis.json"
        if os.path.exists(self.analysis_path):
            with open(self.analysis_path) as f:
                self.sample_data = json.load(f)
        else:
            self.sample_data = None

    def test_strong_vs_weak_from_analysis_json(self):
        """Test comparing the project's actual strong baseline vs weak attack session."""
        if not self.sample_data or "sessions" not in self.sample_data:
            self.skipTest("outputs/analysis.json not available")

        strong_s = self.sample_data["sessions"]["strong"]
        weak_s = self.sample_data["sessions"]["weak"]

        res = compare_sessions(strong_s, weak_s)

        # 1. Verify schema keys
        required_keys = [
            "baseline_session", "attack_session", "detected_configuration_changes",
            "security_score", "detected_security_impact", "anomaly_detection",
            "evidence", "confidence_level", "limitations"
        ]
        for key in required_keys:
            self.assertIn(key, res, f"Missing required top-level key: {key}")

        # 2. Verify score drop and difference calculation
        score_info = res["security_score"]
        self.assertEqual(score_info["before"], 100)
        self.assertEqual(score_info["after"], 10)
        self.assertEqual(score_info["difference"], -90)
        self.assertTrue(score_info["score_dropped"])

        # 3. Verify configuration changes detected
        changes = res["detected_configuration_changes"]
        self.assertTrue(changes["downgrade_detected"])
        params_changed = {c["parameter"] for c in changes["changes"]}
        self.assertIn("enc_algo", params_changed)
        self.assertIn("integrity", params_changed)
        self.assertIn("dh_group", params_changed)
        self.assertIn("pfs", params_changed)

        # 4. Verify Anomaly detection propagation
        anom_info = res["anomaly_detection"]
        self.assertFalse(anom_info["baseline_anomaly"])
        self.assertTrue(anom_info["attack_anomaly"])
        self.assertTrue(anom_info["anomaly_flagged_by_attack"])

        # 5. Verify Evidence & Confidence
        self.assertGreater(len(res["evidence"]), 0)
        self.assertEqual(res["confidence_level"]["overall"], "high")

        # 6. Verify Limitations
        self.assertGreater(len(res["limitations"]), 0)

    def test_pfs_impact_comparison(self):
        """Test validating PFS-enabled vs PFS-disabled IPsec session."""
        base_observed = {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2}
        base_inferred = {"traffic_type": "web", "pfs": "on", "mode": "tunnel", "anomaly": False}

        atk_observed = {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2}
        atk_inferred = {"traffic_type": "web", "pfs": "off", "mode": "tunnel", "anomaly": False}

        base_s = {"observed": base_observed, "inferred": base_inferred, "session": "pfs_on.pcap"}
        atk_s = {"observed": atk_observed, "inferred": atk_inferred, "session": "pfs_off.pcap"}

        res = self.engine.validate_comparison(base_s, atk_s)

        # Score with PFS off drops by 15 points
        self.assertEqual(res["security_score"]["before"], 100)
        self.assertEqual(res["security_score"]["after"], 85)
        self.assertEqual(res["security_score"]["difference"], -15)

        # Config change detected for PFS
        changes = res["detected_configuration_changes"]["changes"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["parameter"], "pfs")
        self.assertTrue(changes[0]["downgraded"])

        # Forward secrecy subscore drop
        sub_fs = res["security_score"]["subscores"]["forward_secrecy"]
        self.assertEqual(sub_fs["before"], 100)
        self.assertEqual(sub_fs["after"], 35)

    def test_identical_sessions_no_downgrade(self):
        """Test validating two identical sessions (no attack / no downgrade)."""
        observed = {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 19, "ike_version": 2}
        inferred = {"traffic_type": "web", "pfs": "on", "mode": "tunnel", "anomaly": False}

        s1 = {"observed": observed, "inferred": inferred}
        s2 = {"observed": observed, "inferred": inferred}

        res = self.engine.validate_comparison(s1, s2)
        self.assertFalse(res["detected_configuration_changes"]["downgrade_detected"])
        self.assertEqual(res["detected_configuration_changes"]["total_parameter_changes"], 0)
        self.assertEqual(res["security_score"]["difference"], 0)
        self.assertEqual(res["detected_security_impact"]["severity"], "low")

if __name__ == "__main__":
    unittest.main()
