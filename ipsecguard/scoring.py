"""Scoring engine (rule layer, grounded in NIST SP 800-77 / relevant RFCs).

Deterministic and explainable: start at 100, deduct for each weakness, and emit
a Finding for every deduction so nothing is a black box. Also produces four
subscores and a likelihood x impact threat matrix.
"""
from .findings import Finding, OBSERVED, INFERRED

WEAK_ENC   = {"3des-cbc", "des-cbc"}
WEAK_INT   = {"md5": 20, "sha1": 12}
LEGACY_DH  = {2: 20, 5: 18}

def assess(observed, inferred):
    """observed/inferred are dicts of parsed + ML-derived session facts."""
    findings, score = [], 100

    # ---- cryptographic strength (from OBSERVED IKE cipher + integrity) ----
    enc = observed.get("enc_algo") or "unknown"
    integ = observed.get("integrity") or "unknown"
    if enc in WEAK_ENC:
        score -= 25
        findings.append(Finding("ENC-3DES", "Deprecated cipher (3DES)",
            f"IKE SA negotiated {enc}. 3DES is deprecated (64-bit block, Sweet32).",
            OBSERVED, "high", None, "NIST SP 800-77 Sec.3; RFC 8221",
            "Move to AES-GCM (AES-256-GCM preferred).", "medium", "high"))
    elif enc.startswith("aes128"):
        score -= 5
        findings.append(Finding("ENC-128", "128-bit cipher in use",
            f"{enc} is acceptable but AES-256 gives more long-term margin.",
            OBSERVED, "low", None, "NIST SP 800-57",
            "Prefer AES-256-GCM for long-lived tunnels.", "low", "low"))
    if integ in WEAK_INT:
        score -= WEAK_INT[integ]
        findings.append(Finding(f"INT-{integ.upper()}", f"Weak integrity ({integ})",
            f"{integ} is broken/deprecated for integrity protection.",
            OBSERVED, "high" if integ == "md5" else "medium", None, "RFC 8247",
            "Use SHA-256 or SHA-384 (or an AEAD cipher).", "medium", "high"))

    # ---- key management (from OBSERVED DH group) ----
    dh = observed.get("dh_group")
    if dh in LEGACY_DH:
        score -= LEGACY_DH[dh]
        findings.append(Finding(f"DH-{dh}", f"Legacy DH group {dh}",
            f"MODP group {dh} is below current strength guidance.",
            OBSERVED, "high", None, "RFC 8247; NIST SP 800-77",
            "Use group 19/20/21 (ECP) or 14+ (MODP) at minimum.", "medium", "high"))
    elif dh == 14:
        score -= 3
        findings.append(Finding("DH-14", "MODP-2048 (group 14)",
            "Acceptable, but ECP groups (19-21) are preferred going forward.",
            OBSERVED, "low", None, "RFC 8247",
            "Consider ECP group 19/20 for efficiency and margin.", "low", "low"))

    # ---- forward secrecy (INFERRED: rekey side-channel / config) ----
    pfs = inferred.get("pfs")
    if pfs == "off":
        score -= 15
        findings.append(Finding("PFS-OFF", "Perfect Forward Secrecy disabled",
            "No fresh DH on Child SA rekey — one key compromise exposes more traffic.",
            INFERRED, "high", inferred.get("pfs_conf", 0.7), "NIST SP 800-77 Sec.4",
            "Enable PFS (add a DH group to the ESP proposal).", "medium", "high"))

    # ---- metadata exposure (INFERRED mode) ----
    mode = inferred.get("mode")
    if mode == "transport":
        findings.append(Finding("MODE-TRANSPORT", "Transport mode detected",
            "Inner IP header is not encapsulated — endpoint addresses are exposed.",
            INFERRED, "low", inferred.get("mode_conf", 0.6), "RFC 4301 Sec.3.2",
            "Use tunnel mode where addressing privacy matters.", "low", "medium"))

    # ---- anomaly (INFERRED) ----
    if inferred.get("anomaly"):
        score -= 10
        findings.append(Finding("ANOMALY", "Behavioural anomaly flagged",
            "ESP flow deviates from the clean-session baseline — investigate "
            "(possible on-path relay, downgrade, or misconfiguration).",
            INFERRED, "medium", inferred.get("anomaly_conf", 0.5), "-",
            "Manually review this session's path and negotiation.", "medium", "high"))

    score = max(0, min(100, score))
    subscores = {
        "crypto_strength": _sub(enc, integ),
        "key_management":  _sub_dh(dh),
        "forward_secrecy": 100 if pfs == "on" else (35 if pfs == "off" else 60),
        "metadata_exposure": 60 if mode == "transport" else 90,
    }
    return {"risk_score": score, "subscores": subscores,
            "findings": [f.to_dict() for f in findings],
            "threat_matrix": _matrix(findings)}

def _sub(enc, integ):
    s = 100
    if enc in WEAK_ENC: s -= 45
    elif enc.startswith("aes128"): s -= 10
    if integ in WEAK_INT: s -= WEAK_INT[integ] + 10
    return max(0, s)

def _sub_dh(dh):
    if dh in LEGACY_DH: return 40
    if dh == 14: return 85
    if dh in (19, 20, 21): return 100
    return 70

def _matrix(findings):
    cells = {}
    for f in findings:
        key = f"{f.likelihood}|{f.impact}"
        cells.setdefault(key, []).append({"id": f.id, "title": f.title, "severity": f.severity})
    return cells
