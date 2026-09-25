"""Analyze ONE real testbed pcap end-to-end with trained models, IPv6 support, and robust error handling.

    from ipsecguard.analyze import analyze_pcap, safe_analyze_pcap
    result = analyze_pcap("cap.pcap", clf, anom)

Production path:
1. PCAP validation & file integrity check (IPv4 & IPv6)
2. Handshake dissection (IKEv1 / IKEv2 over IPv4/IPv6) -> OBSERVED layer
3. Flow feature & metadata extraction (ESP packet timing/sizes/IP version)
4. Mode detection (Tunnel vs Transport)
5. ML inference (Traffic classification & Anomaly scoring)
6. NIST security posture assessment
7. Executive and Technical report generation
"""
import logging
from typing import Any, Dict, Optional

from .features import extract_flow_features, extract_ip_flow_metadata
from .parser import parse_ike, validate_ike_parameters
from .scoring import assess
from .report import executive_md, technical_md
from .mode_detector import detect_ipsec_mode
from .pcap_validator import validate_pcap_file
from .errors import (
    ErrorCode,
    IPsecGuardError,
    PCAPValidationError,
    AnalysisPipelineError,
    FeatureExtractionError,
    format_error_response,
)

logger = logging.getLogger("ipsecguard.analyze")


def analyze_pcap(
    pcap_path: str,
    clf,
    anom,
    pfs_hint: Optional[str] = None,
    mode_hint: Optional[str] = None,
    fallback_hint: Optional[Dict[str, Any]] = None,
    expected_parameters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Analyzes a single IPv4/IPv6 PCAP capture with strict stage-by-stage validation.

    Raises PCAPValidationError or AnalysisPipelineError on fatal issues.
    """
    # 1. Pre-flight PCAP validation & IP census
    census = validate_pcap_file(pcap_path, min_packets=1, require_ipsec=False)
    ip_version = census.get("ip_version", "v4")

    # 2. Handshake Dissection (OBSERVED Layer)
    try:
        observed = parse_ike(pcap_path, fallback_hint=fallback_hint)
    except Exception as e:
        raise AnalysisPipelineError(
            message=f"IKE protocol parsing failed: {e}",
            stage="ike_parsing",
            error_code=ErrorCode.IKE_PARSING_FAILED,
            retryable=False,
            details=str(e)
        )

    # Attach observed IP version and endpoints
    observed["ip_version"] = ip_version
    observed["endpoints"] = census.get("endpoints", {})

    # 3. IKE Parameter Validation
    ike_validation = validate_ike_parameters(observed, reference_data=expected_parameters)

    # 4. Mode Detection (handles IPv4 and IPv6 headers)
    try:
        mode_detection = detect_ipsec_mode(pcap_path, fallback_hint=mode_hint)
    except Exception as e:
        logger.warning(f"Mode detection failed, falling back to hint/default: {e}")
        mode_detection = {
            "detected_mode": mode_hint or "tunnel",
            "confidence": 0.5,
            "derivation": "fallback_default",
            "evidence": ["Mode detection degraded due to dissection error."],
            "limitations": [str(e)]
        }

    detected_mode = mode_detection["detected_mode"]
    mode_conf = mode_detection["confidence"]

    # 5. Flow Feature & Metadata Extraction (ESP Metadata)
    feats = None
    has_esp_features = False
    try:
        feats = extract_flow_features(pcap_path, min_esp=1)
        has_esp_features = True
    except Exception as e:
        # Non-fatal degradation if IKE packets are present
        if census["ike_packets"] > 0:
            logger.info(f"No ESP packets found in {pcap_path}; proceeding with handshake-only evaluation.")
            feats = {
                "pkt_size_mean": 0.0, "pkt_size_std": 0.0, "pkt_size_p10": 0.0,
                "pkt_size_p50": 0.0, "pkt_size_p90": 0.0, "iat_mean": 0.0,
                "iat_std": 0.0, "burstiness": 0.0, "pps": 0.0, "bytes_ratio_updown": 1.0,
                "small_pkt_frac": 0.0, "large_pkt_frac": 0.0, "flow_dur_s": 0.0,
                "pkt_count": 0.0, "iat_cv": 0.0, "size_cv": 0.0, "iat_p10": 0.0, "iat_p90": 0.0
            }
        else:
            raise FeatureExtractionError(
                message=f"Feature extraction failed on {pcap_path}: {e}",
                details=str(e)
            )

    flow_metadata = extract_ip_flow_metadata(pcap_path)

    # 6. ML Classification & Anomaly Detection
    ttype, tconf = "unknown", 0.0
    is_anom, aconf = False, 0.0

    if has_esp_features and clf is not None:
        try:
            ttype, tconf = clf.predict_one(feats)
        except Exception as e:
            logger.warning(f"Traffic classification failed: {e}")
            ttype, tconf = "unclassified", 0.0

    if has_esp_features and anom is not None:
        try:
            is_anom, aconf, _ = anom.score_one({
                **feats,
                "enc_algo": observed.get("enc_algo") or "aes256-gcm",
                "integrity": observed.get("integrity") or "sha256",
                "dh_group": observed.get("dh_group") or 19,
                "pfs": pfs_hint or "on"
            })
        except Exception as e:
            logger.warning(f"Anomaly detection failed: {e}")
            is_anom, aconf = False, 0.0

    inferred = {
        "traffic_type": ttype,
        "traffic_conf": float(tconf),
        "pfs": pfs_hint,
        "pfs_conf": 0.7 if pfs_hint else None,
        "mode": detected_mode,
        "mode_conf": float(mode_conf),
        "anomaly": bool(is_anom),
        "anomaly_conf": float(aconf),
        "ip_version": ip_version,
    }

    # 7. NIST Scoring & Findings
    try:
        result = assess(observed, inferred)
    except Exception as e:
        raise AnalysisPipelineError(
            message=f"Security assessment scoring failed: {e}",
            stage="scoring",
            error_code=ErrorCode.SCORING_FAILED,
            retryable=False,
            details=str(e)
        )

    # 8. Report Generation
    try:
        exec_rep = executive_md(result, pcap_path)
        tech_rep = technical_md(result, pcap_path, observed, inferred)
    except Exception as e:
        logger.warning(f"Report generation error: {e}")
        exec_rep = f"# Security Assessment Report\nAnalysis completed for `{pcap_path}` with risk score {result.get('risk_score', 0)}/100."
        tech_rep = f"# Technical Report\nAnalysis completed for `{pcap_path}`."

    result["session"] = pcap_path
    result["ip_version"] = ip_version
    result["census"] = census
    result["flow_metadata"] = flow_metadata
    result["observed"] = observed
    result["inferred"] = inferred
    result["mode_detection"] = mode_detection
    result["ike_validation"] = ike_validation
    result["flow_features"] = feats
    result["exec_report"] = exec_rep
    result["tech_report"] = tech_rep
    result["warnings"] = census.get("warnings", []) + observed.get("warnings", [])

    return result


def safe_analyze_pcap(
    pcap_path: str,
    clf,
    anom,
    pfs_hint: Optional[str] = None,
    mode_hint: Optional[str] = None,
    fallback_hint: Optional[Dict[str, Any]] = None,
    expected_parameters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Safe wrapper around analyze_pcap that catches all exceptions and returns a uniform JSON dictionary."""
    try:
        res = analyze_pcap(
            pcap_path=pcap_path,
            clf=clf,
            anom=anom,
            pfs_hint=pfs_hint,
            mode_hint=mode_hint,
            fallback_hint=fallback_hint,
            expected_parameters=expected_parameters
        )
        return {"status": "success", "data": res}
    except IPsecGuardError as e:
        return e.to_dict()
    except Exception as e:
        return format_error_response(
            message=f"An unexpected internal error occurred during analysis: {e}",
            error_code=ErrorCode.INTERNAL_ANALYSIS_ERROR,
            stage="pipeline",
            retryable=False,
            details=str(e)
        )
