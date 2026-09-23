"""The confidence-tagged finding model — the thesis of the project in code.

Every finding declares HOW it was derived:
  observed  -> read directly from plaintext IKE_SA_INIT (certain)
  inferred  -> produced by ML / heuristic from encrypted-traffic metadata
  config    -> known only because we control the testbed (validation use only)
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any

OBSERVED = "observed"
INFERRED = "inferred"
CONFIG   = "config"

@dataclass
class Finding:
    id: str
    title: str
    detail: str
    derivation: str                      # observed | inferred | config
    severity: str                        # info | low | medium | high | critical
    confidence: Optional[float] = None   # None for observed; 0..1 for inferred
    nist_ref: str = ""
    recommendation: str = ""
    likelihood: str = "low"              # for the threat matrix
    impact: str = "low"

    def to_dict(self):
        d = asdict(self)
        d["confidence_pct"] = None if self.confidence is None else round(self.confidence * 100)
        return d

def create_downgrade_finding(
    changes: List[Dict[str, Any]],
    score_drop: int = 0,
    derivation: str = OBSERVED,
    confidence: Optional[float] = None
) -> Finding:
    """Creates a dedicated DOWNGRADE-DETECTED finding from detected parameter changes."""
    param_summaries = []
    for c in changes:
        param_summaries.append(f"{c['parameter']} ({c.get('baseline')} -> {c.get('attack')})")

    summary_str = ", ".join(param_summaries) if param_summaries else "unspecified security parameters"
    detail = (
        f"Active on-path or configuration downgrade detected. Security parameters downgraded: {summary_str}. "
        f"Overall risk score reduced by {abs(score_drop)} points."
    )

    sev = "critical" if score_drop >= 50 or any(c.get("impact_level") == "high" for c in changes) else "high"

    return Finding(
        id="DOWNGRADE-DETECTED",
        title="IPsec Cryptographic Downgrade Detected",
        detail=detail,
        derivation=derivation,
        severity=sev,
        confidence=confidence if derivation != OBSERVED else None,
        nist_ref="NIST SP 800-77 Sec.3; RFC 8247",
        recommendation="Enforce strict proposal policies on both peers; strip weak/legacy ciphers (3DES, DES, MD5, DH-2/5) from responder configurations.",
        likelihood="high",
        impact="high" if sev == "critical" else "medium"
    )

def create_pfs_finding(
    status: str,  # "validated" | "disabled" | "inconclusive"
    proof_details: Optional[str] = None,
    confidence: Optional[float] = None,
    derivation: str = INFERRED
) -> Finding:
    """Creates a PFS verification finding based on evidence."""
    st = status.lower()
    if st == "validated":
        detail = proof_details or "Child SA rekey introduces fresh, independent Diffie-Hellman key material (verified via cryptographic key fingerprint rotation)."
        return Finding(
            id="PFS-VALIDATED",
            title="Perfect Forward Secrecy Verified",
            detail=detail,
            derivation=derivation,
            severity="info",
            confidence=confidence if derivation != OBSERVED else None,
            nist_ref="NIST SP 800-77 Sec.4; RFC 8247",
            recommendation="PFS is operating correctly. Maintain PFS on Child SA configurations.",
            likelihood="low",
            impact="low"
        )
    elif st in ("disabled", "off"):
        detail = proof_details or "No fresh DH on Child SA rekey — one key compromise exposes all past and future session traffic."
        return Finding(
            id="PFS-OFF",
            title="Perfect Forward Secrecy Disabled",
            detail=detail,
            derivation=derivation,
            severity="high",
            confidence=confidence if derivation != OBSERVED else None,
            nist_ref="NIST SP 800-77 Sec.4",
            recommendation="Enable PFS (add a DH group to the ESP proposal).",
            likelihood="medium",
            impact="high"
        )
    else:  # inconclusive
        detail = proof_details or "PFS status could not be verified definitively from available traffic metadata (no rekey event captured or runtime kernel state unavailable)."
        return Finding(
            id="PFS-INCONCLUSIVE",
            title="PFS Verification Inconclusive",
            detail=detail,
            derivation=INFERRED,
            severity="medium",
            confidence=confidence if confidence is not None else 0.5,
            nist_ref="NIST SP 800-77 Sec.4",
            recommendation="Capture traffic through a full Child SA rekey cycle or inspect gateway XFRM state to confirm PFS operation.",
            likelihood="low",
            impact="medium"
        )
