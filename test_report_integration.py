"""Unit tests for Evidence-Based Security Report Integration."""
import json
import os
import unittest
from ipsecguard import (
    AttackValidationEngine,
    compare_sessions,
    create_downgrade_finding,
    create_pfs_finding,
    validation_report_md,
    executive_md,
    technical_md
)

class TestReportIntegration(unittest.TestCase):

    def setUp(self):
        self.engine = AttackValidationEngine()

    def test_downgrade_detected_finding_positive(self):
        """Test that DOWNGRADE-DETECTED finding is produced with correct details and no false positives."""
        base_s = {
            "session": "base_aes256_dh20.pcap",
            "observed": {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
            "inferred": {"pfs": "on", "mode": "tunnel", "anomaly": False}
        }
        atk_s = {
            "session": "atk_3des_dh2.pcap",
            "observed": {"enc_algo": "3des-cbc", "integrity": "md5", "dh_group": 2, "ike_version": 1},
            "inferred": {"pfs": "off", "mode": "transport", "anomaly": True}
        }

        res = compare_sessions(base_s, atk_s)
        findings = res["detected_security_impact"]["new_findings"]
        downgrade_f = next((f for f in findings if f["id"] == "DOWNGRADE-DETECTED"), None)

        self.assertIsNotNone(downgrade_f, "DOWNGRADE-DETECTED finding must be present on downgrade")
        self.assertEqual(downgrade_f["severity"], "critical")
        self.assertIn("3des-cbc", downgrade_f["detail"])
        self.assertIn("RFC 8247", downgrade_f["nist_ref"])

    def test_no_downgrade_no_false_positive(self):
        """Test that DOWNGRADE-DETECTED is NOT generated for clean/identical sessions."""
        base_s = {
            "session": "clean.pcap",
            "observed": {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
            "inferred": {"pfs": "on", "mode": "tunnel", "anomaly": False}
        }
        atk_s = {
            "session": "clean_clone.pcap",
            "observed": {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
            "inferred": {"pfs": "on", "mode": "tunnel", "anomaly": False}
        }

        res = compare_sessions(base_s, atk_s)
        findings = res["detected_security_impact"]["new_findings"]
        downgrade_f = next((f for f in findings if f["id"] == "DOWNGRADE-DETECTED"), None)
        self.assertIsNone(downgrade_f, "No DOWNGRADE-DETECTED finding should be generated for identical sessions")

    def test_pfs_validated_finding(self):
        """Test PFS-VALIDATED finding generation when PFS verification succeeds."""
        f = create_pfs_finding(status="validated", proof_details="New independent DH keys rotated (SPI 0xc14b...)")
        self.assertEqual(f.id, "PFS-VALIDATED")
        self.assertEqual(f.severity, "info")
        self.assertIn("0xc14b", f.detail)

        # In compare_sessions with explicit proof status
        base_s = {"observed": {"enc_algo": "aes256-gcm", "dh_group": 20}, "inferred": {"pfs": "on"}}
        atk_s = {"observed": {"enc_algo": "aes256-gcm", "dh_group": 20}, "inferred": {"pfs": "on"}}
        res = compare_sessions(base_s, atk_s, pfs_proof_status="validated")
        findings = res["detected_security_impact"]["new_findings"]
        pfs_f = next((f for f in findings if f["id"] == "PFS-VALIDATED"), None)
        self.assertIsNotNone(pfs_f)

    def test_pfs_disabled_finding(self):
        """Test PFS-OFF finding generation when PFS is disabled."""
        base_s = {"observed": {"enc_algo": "aes256-gcm", "dh_group": 20}, "inferred": {"pfs": "on"}}
        atk_s = {"observed": {"enc_algo": "aes256-gcm", "dh_group": 20}, "inferred": {"pfs": "off"}}
        res = compare_sessions(base_s, atk_s, pfs_proof_status="disabled")
        findings = res["detected_security_impact"]["new_findings"]
        pfs_f = next((f for f in findings if f["id"] == "PFS-OFF"), None)
        self.assertIsNotNone(pfs_f)
        self.assertEqual(pfs_f["severity"], "high")

    def test_pfs_inconclusive_finding(self):
        """Test PFS-INCONCLUSIVE finding generation when PFS cannot be confirmed."""
        f = create_pfs_finding(status="inconclusive", proof_details="No Child SA rekey observed in capture")
        self.assertEqual(f.id, "PFS-INCONCLUSIVE")
        self.assertEqual(f.severity, "medium")
        self.assertIn("No Child SA rekey", f.detail)

    def test_validation_report_markdown_generation(self):
        """Test that the generated Markdown validation report contains all required sections."""
        base_s = {
            "session": "siteA_strong.pcap",
            "observed": {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
            "inferred": {"pfs": "on", "mode": "tunnel", "anomaly": False}
        }
        atk_s = {
            "session": "siteA_downgraded.pcap",
            "observed": {"enc_algo": "3des-cbc", "integrity": "md5", "dh_group": 2, "ike_version": 1},
            "inferred": {"pfs": "off", "mode": "transport", "anomaly": True, "anomaly_conf": 0.85}
        }

        res = compare_sessions(base_s, atk_s)
        md = res["validation_report"]

        # Check required sections
        self.assertIn("# Security Assessment & Evidence Validation Report", md)
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Before-and-After Security Parameter Comparison", md)
        self.assertIn("## 3. Forward Secrecy (PFS) Verification Status", md)
        self.assertIn("## 4. Anomaly Detection & Flow Deviations", md)
        self.assertIn("## 5. Detected Security Impact & Vulnerabilities Exposed", md)
        self.assertIn("## 6. Grounded Evidence Ledger", md)
        self.assertIn("## 7. Confidence Assessment & Operational Limitations", md)
        self.assertIn("## 8. Prioritized Remediation Roadmap", md)

        # Check content details
        self.assertIn("DOWNGRADED", md)
        self.assertIn("3des-cbc", md)
        self.assertIn("Sweet32", md)
        self.assertIn("NIST SP 800-77", md)

if __name__ == "__main__":
    unittest.main()
