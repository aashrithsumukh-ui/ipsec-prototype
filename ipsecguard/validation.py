"""Attack Impact & Validation Engine for IPsecGuard AI.

Compares baseline (normal) and attack (downgrade / PFS-disabled) IPsec sessions,
evaluates parameter differences, security score deltas, behavioral anomalies,
generates supporting evidence, calculates confidence, details verification limitations,
and produces evidence-based validation reports.
"""

from typing import Dict, Any, List, Optional, Tuple
import copy
from .scoring import assess, WEAK_ENC, WEAK_INT, LEGACY_DH
from .findings import (
    OBSERVED, INFERRED, CONFIG, Finding,
    create_downgrade_finding, create_pfs_finding
)
from .report import validation_report_md, executive_md

# Strength ranks for parameter comparison (higher index = stronger / preferred)
ENC_RANKS = {
    "3des-cbc": 1,
    "des-cbc": 0,
    "aes128-cbc": 2,
    "aes256-cbc": 3,
    "aes128-gcm": 4,
    "aes256-gcm": 5,
    "chacha20-poly1305": 5,
}

INT_RANKS = {
    "md5": 0,
    "sha1": 1,
    "sha256": 2,
    "sha384": 3,
    "sha512": 4,
    "none": 5,  # Valid/preferred for AEAD ciphers like AES-GCM
}

DH_RANKS = {
    2: 0,
    5: 1,
    14: 2,
    19: 3,
    20: 3,
    21: 3,
}

PFS_RANKS = {
    "off": 0,
    "on": 1,
}

MODE_RANKS = {
    "transport": 0,
    "tunnel": 1,
}

def _get_posture_label(score: int) -> str:
    if score >= 85:
        return "Strong"
    elif score >= 65:
        return "Adequate"
    elif score >= 40:
        return "Degraded"
    elif score >= 20:
        return "Weak"
    else:
        return "Critical"

class AttackValidationEngine:
    """Validation engine comparing baseline vs attack IPsec sessions."""

    def __init__(self, clf=None, anom=None):
        self.clf = clf
        self.anom = anom

    def validate_comparison(
        self,
        baseline_session: Dict[str, Any],
        attack_session: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        pfs_proof_status: Optional[str] = None,
        pfs_proof_details: Optional[str] = None
    ) -> Dict[str, Any]:
        """Compares baseline vs attack session and generates a structured impact report."""
        base_s = self._normalize_session(baseline_session)
        atk_s = self._normalize_session(attack_session)

        # 1. Detect Configuration Changes
        config_diff = self._detect_configuration_changes(base_s, atk_s)

        # 2. Security Score Analysis
        score_analysis = self._compute_score_analysis(base_s, atk_s)

        # 3. Anomaly Analysis
        anomaly_analysis = self._compute_anomaly_analysis(base_s, atk_s)

        # 4. Security Impact Assessment & Validation Findings
        impact_analysis = self._assess_security_impact(
            base_s, atk_s, config_diff, score_analysis,
            pfs_proof_status=pfs_proof_status,
            pfs_proof_details=pfs_proof_details
        )

        # 5. Evidence Aggregation
        evidence = self._gather_evidence(base_s, atk_s, config_diff, anomaly_analysis, context, pfs_proof_status)

        # 6. Confidence Level Calculation
        confidence_info = self._calculate_confidence(base_s, atk_s, evidence)

        # 7. Limitations
        limitations = self._determine_limitations(base_s, atk_s, context)

        result = {
            "baseline_session": {
                "session_id": base_s.get("session", "baseline_session"),
                "risk_score": base_s.get("risk_score"),
                "posture": _get_posture_label(base_s.get("risk_score", 100)),
                "observed": base_s.get("observed", {}),
                "inferred": base_s.get("inferred", {}),
                "subscores": base_s.get("subscores", {}),
                "findings_count": len(base_s.get("findings", []))
            },
            "attack_session": {
                "session_id": atk_s.get("session", "attack_session"),
                "risk_score": atk_s.get("risk_score"),
                "posture": _get_posture_label(atk_s.get("risk_score", 0)),
                "observed": atk_s.get("observed", {}),
                "inferred": atk_s.get("inferred", {}),
                "subscores": atk_s.get("subscores", {}),
                "findings_count": len(atk_s.get("findings", []))
            },
            "detected_configuration_changes": config_diff,
            "security_score": score_analysis,
            "detected_security_impact": impact_analysis,
            "anomaly_detection": anomaly_analysis,
            "evidence": evidence,
            "confidence_level": confidence_info,
            "limitations": limitations,
        }

        # 8. Generate Evidence-based Markdown Reports
        result["validation_report"] = validation_report_md(result)
        result["exec_report"] = executive_md(atk_s, atk_s.get("session", "attack_session"))

        return result

    def validate_pcap_pair(
        self,
        baseline_pcap: str,
        attack_pcap: str,
        pfs_hint_base: str = "on",
        pfs_hint_atk: str = "on",
        mode_hint: str = "tunnel"
    ) -> Dict[str, Any]:
        """Analyzes two PCAP captures and runs comparison."""
        from .analyze import analyze_pcap
        if self.clf is None or self.anom is None:
            raise ValueError("Classifier and AnomalyDetector must be provided to validate PCAP pairs.")

        base_res = analyze_pcap(baseline_pcap, self.clf, self.anom, pfs_hint=pfs_hint_base, mode_hint=mode_hint)
        atk_res = analyze_pcap(attack_pcap, self.clf, self.anom, pfs_hint=pfs_hint_atk, mode_hint=mode_hint)
        return self.validate_comparison(base_res, atk_res, context={"baseline_pcap": baseline_pcap, "attack_pcap": attack_pcap})

    def _normalize_session(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures session has observed, inferred, risk_score, subscores, and findings."""
        s = copy.deepcopy(session)
        observed = s.get("observed", {})
        inferred = s.get("inferred", {})

        if "risk_score" not in s or "subscores" not in s or "findings" not in s:
            assessed = assess(observed, inferred)
            s["risk_score"] = assessed["risk_score"]
            s["subscores"] = assessed["subscores"]
            s["findings"] = assessed["findings"]
            s["threat_matrix"] = assessed["threat_matrix"]

        s["observed"] = observed
        s["inferred"] = inferred
        return s

    def _detect_configuration_changes(self, base_s: Dict[str, Any], atk_s: Dict[str, Any]) -> Dict[str, Any]:
        changes = []
        is_downgrade = False

        b_obs, a_obs = base_s.get("observed", {}), atk_s.get("observed", {})
        b_inf, a_inf = base_s.get("inferred", {}), atk_s.get("inferred", {})

        # 1. Encryption Algorithm
        b_enc, a_enc = b_obs.get("enc_algo"), a_obs.get("enc_algo")
        if b_enc and a_enc and b_enc != a_enc:
            b_r = ENC_RANKS.get(str(b_enc).lower(), 2)
            a_r = ENC_RANKS.get(str(a_enc).lower(), 2)
            downgraded = a_r < b_r
            if downgraded:
                is_downgrade = True
            impact = "high" if str(a_enc).lower() in WEAK_ENC else ("medium" if downgraded else "low")
            changes.append({
                "parameter": "enc_algo",
                "derivation": OBSERVED,
                "baseline": b_enc,
                "attack": a_enc,
                "downgraded": downgraded,
                "impact_level": impact,
                "details": f"Encryption algorithm shifted from {b_enc} to {a_enc}." + (" (Deprecated/Weak cipher)" if str(a_enc).lower() in WEAK_ENC else "")
            })

        # 2. Integrity Algorithm
        b_int, a_int = b_obs.get("integrity"), a_obs.get("integrity")
        if b_int and a_int and b_int != a_int:
            b_r = INT_RANKS.get(str(b_int).lower(), 2)
            a_r = INT_RANKS.get(str(a_int).lower(), 2)
            downgraded = a_r < b_r or str(a_int).lower() in WEAK_INT
            if downgraded:
                is_downgrade = True
            impact = "high" if str(a_int).lower() in ("md5",) else ("medium" if downgraded else "low")
            changes.append({
                "parameter": "integrity",
                "derivation": OBSERVED,
                "baseline": b_int,
                "attack": a_int,
                "downgraded": downgraded,
                "impact_level": impact,
                "details": f"Integrity check changed from {b_int} to {a_int}." + (f" ({a_int} is vulnerable to collision attacks)" if str(a_int).lower() in WEAK_INT else "")
            })

        # 3. Diffie-Hellman Group
        b_dh, a_dh = b_obs.get("dh_group"), a_obs.get("dh_group")
        if b_dh is not None and a_dh is not None and b_dh != a_dh:
            b_r = DH_RANKS.get(b_dh, 1)
            a_r = DH_RANKS.get(a_dh, 1)
            downgraded = a_r < b_r or a_dh in LEGACY_DH
            if downgraded:
                is_downgrade = True
            impact = "high" if a_dh in LEGACY_DH else ("medium" if downgraded else "low")
            changes.append({
                "parameter": "dh_group",
                "derivation": OBSERVED,
                "baseline": b_dh,
                "attack": a_dh,
                "downgraded": downgraded,
                "impact_level": impact,
                "details": f"DH Key exchange group changed from Group {b_dh} to Group {a_dh}." + (f" (Group {a_dh} is legacy/weak MODP)" if a_dh in LEGACY_DH else "")
            })

        # 4. IKE Version
        b_ike, a_ike = b_obs.get("ike_version"), a_obs.get("ike_version")
        if b_ike is not None and a_ike is not None and b_ike != a_ike:
            downgraded = a_ike < b_ike
            if downgraded:
                is_downgrade = True
            changes.append({
                "parameter": "ike_version",
                "derivation": OBSERVED,
                "baseline": b_ike,
                "attack": a_ike,
                "downgraded": downgraded,
                "impact_level": "medium" if downgraded else "low",
                "details": f"IKE protocol version changed from IKEv{b_ike} to IKEv{a_ike}."
            })

        # 5. PFS (Forward Secrecy)
        b_pfs = b_inf.get("pfs") or b_obs.get("pfs")
        a_pfs = a_inf.get("pfs") or a_obs.get("pfs")
        if b_pfs and a_pfs and b_pfs != a_pfs:
            downgraded = (b_pfs == "on" and a_pfs == "off")
            if downgraded:
                is_downgrade = True
            changes.append({
                "parameter": "pfs",
                "derivation": INFERRED if "pfs" in b_inf or "pfs" in a_inf else OBSERVED,
                "baseline": b_pfs,
                "attack": a_pfs,
                "downgraded": downgraded,
                "impact_level": "high" if downgraded else "low",
                "details": f"Perfect Forward Secrecy changed from {b_pfs} to {a_pfs}." + (" (Key compromise affects all past/future sessions)" if downgraded else "")
            })

        # 6. Mode (Tunnel vs Transport)
        b_mode = b_inf.get("mode") or b_obs.get("mode")
        a_mode = a_inf.get("mode") or a_obs.get("mode")
        if b_mode and a_mode and b_mode != a_mode:
            downgraded = (b_mode == "tunnel" and a_mode == "transport")
            changes.append({
                "parameter": "mode",
                "derivation": INFERRED if "mode" in b_inf or "mode" in a_inf else OBSERVED,
                "baseline": b_mode,
                "attack": a_mode,
                "downgraded": downgraded,
                "impact_level": "low",
                "details": f"IPsec encapsulation mode changed from {b_mode} to {a_mode}." + (" (Inner IP header exposed)" if downgraded else "")
            })

        return {
            "downgrade_detected": is_downgrade,
            "total_parameter_changes": len(changes),
            "changes": changes
        }

    def _compute_score_analysis(self, base_s: Dict[str, Any], atk_s: Dict[str, Any]) -> Dict[str, Any]:
        s_before = int(base_s.get("risk_score", 100))
        s_after = int(atk_s.get("risk_score", 0))
        diff = s_after - s_before

        b_sub = base_s.get("subscores", {})
        a_sub = atk_s.get("subscores", {})

        sub_diffs = {}
        for k in ["crypto_strength", "key_management", "forward_secrecy", "metadata_exposure"]:
            b_val = b_sub.get(k, 100)
            a_val = a_sub.get(k, 100)
            sub_diffs[k] = {
                "before": b_val,
                "after": a_val,
                "difference": a_val - b_val
            }

        p_before = _get_posture_label(s_before)
        p_after = _get_posture_label(s_after)

        return {
            "before": s_before,
            "after": s_after,
            "difference": diff,
            "score_dropped": diff < 0,
            "posture_transition": f"{p_before} -> {p_after}",
            "subscores": sub_diffs
        }

    def _compute_anomaly_analysis(self, base_s: Dict[str, Any], atk_s: Dict[str, Any]) -> Dict[str, Any]:
        b_inf = base_s.get("inferred", {})
        a_inf = atk_s.get("inferred", {})

        b_anom = bool(b_inf.get("anomaly", False))
        a_anom = bool(a_inf.get("anomaly", False))
        a_conf = float(a_inf.get("anomaly_conf", 0.0))

        flagged = a_anom and not b_anom
        return {
            "baseline_anomaly": b_anom,
            "attack_anomaly": a_anom,
            "anomaly_detected": a_anom,
            "anomaly_flagged_by_attack": flagged,
            "anomaly_confidence": a_conf,
            "timing_or_flow_deviation": a_anom,
            "details": "Behavioral anomaly detected in ESP traffic distribution (consistent with on-path tampering/relay timing shift)." if a_anom else "Traffic metadata matches baseline behavior."
        }

    def _assess_security_impact(
        self,
        base_s: Dict[str, Any],
        atk_s: Dict[str, Any],
        config_diff: Dict[str, Any],
        score_analysis: Dict[str, Any],
        pfs_proof_status: Optional[str] = None,
        pfs_proof_details: Optional[str] = None
    ) -> Dict[str, Any]:
        b_find_ids = {f.get("id") for f in base_s.get("findings", [])}
        new_findings = [f for f in atk_s.get("findings", []) if f.get("id") not in b_find_ids]

        exposed_vulns = []
        a_obs = atk_s.get("observed", {})
        a_inf = atk_s.get("inferred", {})

        if a_obs.get("enc_algo") in WEAK_ENC:
            exposed_vulns.append("Sweet32 Birthday Attack on 64-bit block ciphers (CVE-2016-2183)")
        if a_obs.get("integrity") == "md5":
            exposed_vulns.append("Cryptographic collision attacks on MD5 (RFC 6151)")
        elif a_obs.get("integrity") == "sha1":
            exposed_vulns.append("Practical collision attacks on SHA-1 (SHAttered)")
        if a_obs.get("dh_group") in (2, 5):
            exposed_vulns.append("Discrete Logarithm / Logjam Precomputation Attacks on small prime MODP groups (RFC 8247)")
        if a_inf.get("pfs") == "off":
            exposed_vulns.append("Loss of Forward Secrecy: Long-term key compromise allows retroactive plaintext recovery")
        if a_inf.get("mode") == "transport":
            exposed_vulns.append("Endpoint address and traffic flow pattern leakage (RFC 4301)")

        score_drop = abs(score_analysis["difference"])
        if score_drop >= 50 or any(c["impact_level"] == "high" for c in config_diff["changes"]):
            severity = "critical"
        elif score_drop >= 25 or any(c["impact_level"] == "medium" for c in config_diff["changes"]):
            severity = "high"
        elif score_drop > 0:
            severity = "medium"
        else:
            severity = "low" if not config_diff["downgrade_detected"] else "medium"

        # Generate DOWNGRADE-DETECTED finding if a downgrade occurred
        if config_diff.get("downgrade_detected"):
            downgrade_finding = create_downgrade_finding(
                changes=config_diff["changes"],
                score_drop=score_drop,
                derivation=OBSERVED if any(c.get("derivation") == OBSERVED for c in config_diff["changes"]) else INFERRED
            )
            new_findings.insert(0, downgrade_finding.to_dict())

        # Generate PFS finding based on verification / inferred state
        pfs_st = pfs_proof_status
        if not pfs_st:
            if a_inf.get("pfs") == "off":
                pfs_st = "disabled"
            elif a_inf.get("pfs") == "on":
                pfs_st = "validated"
            else:
                pfs_st = "inconclusive"

        pfs_finding = create_pfs_finding(
            status=pfs_st,
            proof_details=pfs_proof_details,
            confidence=a_inf.get("pfs_conf", 0.7)
        )
        # Avoid duplicate PFS-OFF if already in findings
        if not any(f.get("id") == pfs_finding.id for f in new_findings):
            new_findings.append(pfs_finding.to_dict())

        summary = (
            f"Security posture degraded by {score_drop} points ({score_analysis['posture_transition']}). "
            f"Identified {len(config_diff['changes'])} configuration delta(s) exposing {len(exposed_vulns)} primary vulnerability vector(s)."
        )

        return {
            "severity": severity,
            "score_reduction": score_drop,
            "impact_summary": summary,
            "vulnerabilities_exposed": exposed_vulns,
            "new_findings": new_findings,
            "pfs_verification_status": pfs_st
        }

    def _gather_evidence(
        self,
        base_s: Dict[str, Any],
        atk_s: Dict[str, Any],
        config_diff: Dict[str, Any],
        anomaly_analysis: Dict[str, Any],
        context: Optional[Dict[str, Any]],
        pfs_proof_status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        evidence = []

        # 1. Observed Handshake Evidence
        for c in config_diff["changes"]:
            if c.get("derivation") == OBSERVED:
                evidence.append({
                    "type": "observed_handshake_parameter",
                    "parameter": c["parameter"],
                    "derivation": OBSERVED,
                    "finding": f"{c['parameter']} negotiated {c['attack']} (previously {c['baseline']})",
                    "nist_reference": "NIST SP 800-77 Sec.3" if "enc" in c["parameter"] or "int" in c["parameter"] else "RFC 8247",
                    "certainty": "confirmed_in_cleartext_ike_sa_init"
                })

        # 2. Inferred Findings Evidence
        for c in config_diff["changes"]:
            if c.get("derivation") == INFERRED:
                evidence.append({
                    "type": "inferred_parameter_behavior",
                    "parameter": c["parameter"],
                    "derivation": INFERRED,
                    "finding": f"{c['parameter']} status transitioned to {c['attack']}",
                    "nist_reference": "NIST SP 800-77 Sec.4" if c["parameter"] == "pfs" else "RFC 4301",
                    "certainty": "inferred_from_metadata"
                })

        # 3. Anomaly evidence
        if anomaly_analysis.get("anomaly_detected"):
            evidence.append({
                "type": "behavioral_anomaly_detection",
                "derivation": INFERRED,
                "finding": f"Isolation Forest flagged ESP metadata deviation (anomaly confidence: {anomaly_analysis.get('anomaly_confidence', 0.0):.2f})",
                "nist_reference": "NIST SP 800-77 / Flow Heuristics",
                "certainty": "statistical_isolation_forest"
            })

        # 4. Contextual evidence
        if context:
            if "attack_pcap" in context:
                evidence.append({
                    "type": "capture_artifact",
                    "derivation": CONFIG,
                    "finding": f"Analyzed capture artifacts: {context.get('baseline_pcap')} vs {context.get('attack_pcap')}",
                    "certainty": "file_reference"
                })

        return evidence

    def _calculate_confidence(
        self,
        base_s: Dict[str, Any],
        atk_s: Dict[str, Any],
        evidence: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        observed_count = sum(1 for e in evidence if e.get("derivation") == OBSERVED)
        inferred_count = sum(1 for e in evidence if e.get("derivation") == INFERRED)

        if observed_count >= 2:
            overall = "high"
            score = 0.95
        elif observed_count >= 1 or inferred_count >= 2:
            overall = "medium"
            score = 0.75
        else:
            overall = "low"
            score = 0.50

        return {
            "overall": overall,
            "confidence_score": score,
            "observed_facts_count": observed_count,
            "inferred_facts_count": inferred_count,
            "rationale": "High confidence: Core cryptographic algorithms (cipher, integrity, DH) were directly observed from plaintext IKE_SA_INIT negotiation." if observed_count >= 2 else "Medium/Low confidence: Findings rely partially or primarily on inferred flow features."
        }

    def _determine_limitations(
        self,
        base_s: Dict[str, Any],
        atk_s: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> List[str]:
        limitations = []

        b_inf, a_inf = base_s.get("inferred", {}), atk_s.get("inferred", {})
        if "pfs" in b_inf or "pfs" in a_inf:
            limitations.append("PFS status is inferred from Child SA rekey heuristics or runtime hints unless live XFRM kernel state is inspected.")

        if "mode" in b_inf or "mode" in a_inf:
            limitations.append("Tunnel vs Transport mode was inferred from ESP packet sizes and IP encapsulation heuristics without inner packet decryption.")

        limitations.append("Encrypted ESP payload content is opaque; analysis is strictly grounded in cleartext IKE negotiation and ESP statistical metadata.")

        return limitations

def compare_sessions(
    baseline_session: Dict[str, Any],
    attack_session: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
    pfs_proof_status: Optional[str] = None,
    pfs_proof_details: Optional[str] = None
) -> Dict[str, Any]:
    """Convenience functional interface for validating baseline vs attack sessions."""
    engine = AttackValidationEngine()
    return engine.validate_comparison(
        baseline_session,
        attack_session,
        context=context,
        pfs_proof_status=pfs_proof_status,
        pfs_proof_details=pfs_proof_details
    )
