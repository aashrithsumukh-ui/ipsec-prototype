"""Report generation: executive, technical, and evidence-based validation reports."""
from typing import Dict, Any, List

def _band(score):
    return ("Critical", "#b3261e") if score < 40 else \
           ("At risk", "#d97706") if score < 70 else \
           ("Acceptable", "#2f7d32") if score < 88 else ("Strong", "#1b5e20")

def executive_md(result: Dict[str, Any], session: str) -> str:
    """Produces an executive summary report from assessment results."""
    band, _ = _band(result["risk_score"])
    top = sorted(result.get("findings", []),
                 key=lambda f: {"critical":4,"high":3,"medium":2,"low":1,"info":0}.get(f.get("severity", "info"), 0),
                 reverse=True)[:4]
    lines = [
        f"# Executive Summary — IPsecGuard AI",
        f"**Session:** {session}",
        f"**Risk score:** {result['risk_score']}/100  ·  **Posture:** {band}",
        ""
    ]

    # Include downgrade alert if present in findings
    downgrade_f = next((f for f in result.get("findings", []) if f.get("id") == "DOWNGRADE-DETECTED"), None)
    if downgrade_f:
        lines += [
            f"> [!CRITICAL] **Active Downgrade Detected**",
            f"> {downgrade_f.get('detail')}",
            ""
        ]

    # Include PFS verification status if present
    pfs_f = next((f for f in result.get("findings", []) if f.get("id") in ("PFS-VALIDATED", "PFS-OFF", "PFS-INCONCLUSIVE")), None)
    if pfs_f:
        lines += [
            f"**Forward Secrecy (PFS) Status:** {pfs_f.get('title')} (`{pfs_f.get('id')}`)",
            ""
        ]

    lines.append("## Top risks")
    if not top:
        lines.append("- No significant weaknesses detected.")
    for f in top:
        tag = "observed" if f.get("derivation") == "observed" else f"inferred, {f.get('confidence_pct')}%"
        lines.append(f"- **{f.get('title')}** ({f.get('severity')}, {tag}) — {f.get('recommendation')}")
    return "\n".join(lines)

def technical_md(result: Dict[str, Any], session: str, observed: Dict[str, Any], inferred: Dict[str, Any]) -> str:
    """Produces a detailed technical analysis report."""
    lines = [
        f"# Technical Report — IPsecGuard AI",
        f"Session: `{session}`",
        "",
        f"Risk score: **{result['risk_score']}/100**",
        "",
        "## Observed (read from plaintext IKE_SA_INIT)"
    ]
    for k, v in observed.items():
        if not str(k).startswith("_"):
            lines.append(f"- {k}: `{v}`")
    lines += ["", "## Inferred (from encrypted-traffic metadata)"]
    for k, v in inferred.items():
        if not str(k).endswith("_conf") and not str(k).startswith("_"):
            lines.append(f"- {k}: `{v}`")
    lines += ["", "## Subscores"]
    for k, v in result.get("subscores", {}).items():
        lines.append(f"- {k.replace('_',' ')}: {v}/100")
    lines += ["", "## Findings"]
    for f in result.get("findings", []):
        tag = "OBSERVED (certain)" if f.get("derivation") == "observed" else f"INFERRED ({f.get('confidence_pct')}% confidence)"
        lines += [
            f"### [{f.get('severity', 'info').upper()}] {f.get('title')}  —  {tag}",
            f"{f.get('detail')}",
            f"- NIST/RFC: {f.get('nist_ref', 'NIST SP 800-77')}",
            f"- Recommendation: {f.get('recommendation', '')}",
            ""
        ]
    return "\n".join(lines)

def validation_report_md(val_result: Dict[str, Any]) -> str:
    """Generates an evidence-based security validation & attack impact Markdown report."""
    base = val_result.get("baseline_session", {})
    atk = val_result.get("attack_session", {})
    sec_score = val_result.get("security_score", {})
    diff = val_result.get("detected_configuration_changes", {})
    impact = val_result.get("detected_security_impact", {})
    anom = val_result.get("anomaly_detection", {})
    evidence = val_result.get("evidence", [])
    conf = val_result.get("confidence_level", {})
    limitations = val_result.get("limitations", [])

    lines = [
        "# Security Assessment & Evidence Validation Report",
        "**IPsecGuard AI — Attack Impact & Verification Engine**",
        "",
        "## 1. Executive Summary",
        f"- **Baseline Session:** `{base.get('session_id', 'baseline')}` (Risk Score: **{base.get('risk_score')}/100**, Posture: **{base.get('posture')}**)",
        f"- **Attack / Negotiated Session:** `{atk.get('session_id', 'attack')}` (Risk Score: **{atk.get('risk_score')}/100**, Posture: **{atk.get('posture')}**)",
        f"- **Score Transition:** `{sec_score.get('before')}` → `{sec_score.get('after')}` (Delta: **{sec_score.get('difference'):+d} points**, Posture: **{sec_score.get('posture_transition')}**)",
        f"- **Impact Severity:** **{impact.get('severity', 'unknown').upper()}**",
        f"- **Summary:** {impact.get('impact_summary', '')}",
        ""
    ]

    # Downgrade detection status callout
    is_downgrade = diff.get("downgrade_detected", False)
    if is_downgrade:
        lines += [
            "> [!CRITICAL] **Cryptographic Downgrade Detected**",
            f"> An active proposal downgrade was identified across {diff.get('total_parameter_changes', 0)} security parameter(s). Strong proposals were suppressed during negotiation.",
            ""
        ]
    else:
        lines += [
            "> [!NOTE] **No Cryptographic Downgrade Detected**",
            "> Security configuration remains consistent with baseline posture.",
            ""
        ]

    # Parameter Comparison Table
    lines += [
        "## 2. Before-and-After Security Parameter Comparison",
        "",
        "| Parameter | Baseline | After Attack / Negotiated | Derivation | Change Status | Impact Level |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    for c in diff.get("changes", []):
        status = "**DOWNGRADED**" if c.get("downgraded") else "Modified"
        lines.append(
            f"| `{c.get('parameter')}` | `{c.get('baseline')}` | `{c.get('attack')}` | {c.get('derivation')} | {status} | {c.get('impact_level', 'low').upper()} |"
        )
    if not diff.get("changes"):
        lines.append("| — | Identical | Identical | — | Unchanged | LOW |")

    # Subscore breakdown table
    lines += [
        "",
        "### Security Subscore Breakdown",
        "",
        "| Subscore Category | Baseline | After Attack | Difference |",
        "| :--- | :--- | :--- | :--- |"
    ]
    for k, v in sec_score.get("subscores", {}).items():
        name = k.replace("_", " ").title()
        lines.append(f"| {name} | {v.get('before')}/100 | {v.get('after')}/100 | {v.get('difference'):+d} |")

    # PFS Verification
    lines += [
        "",
        "## 3. Forward Secrecy (PFS) Verification Status",
        ""
    ]
    pfs_change = next((c for c in diff.get("changes", []) if c.get("parameter") == "pfs"), None)
    if pfs_change and pfs_change.get("attack") == "off":
        lines += [
            "- **PFS State:** **DISABLED / MISSING** (`PFS-OFF`)",
            "- **Cryptographic Risk:** No fresh Diffie-Hellman exchange is conducted during Child SA rekeys. Compromise of the long-term IKE secret compromises all past and future encrypted traffic.",
            "- **Recommendation:** Enable PFS in IPsec proposals (`pfs=yes` / add DH group to ESP proposal)."
        ]
    elif base.get("inferred", {}).get("pfs") == "on" and atk.get("inferred", {}).get("pfs") == "on":
        lines += [
            "- **PFS State:** **ENABLED & ACTIVE** (`PFS-VALIDATED`)",
            "- **Cryptographic Assurance:** Diffie-Hellman key rotation active on Child SA rekeys, maintaining forward secrecy boundaries."
        ]
    else:
        lines += [
            "- **PFS State:** **INCONCLUSIVE / UNVERIFIED** (`PFS-INCONCLUSIVE`)",
            "- **Cryptographic Note:** No rekey event was captured in the traffic metadata to verify fresh key generation.",
            "- **Recommendation:** Verify gateway `ipsec.conf` or monitor full Child SA rekey lifecycle."
        ]

    # Anomaly Detection
    lines += [
        "",
        "## 4. Anomaly Detection & Flow Deviations",
        f"- **Baseline Anomaly:** `{anom.get('baseline_anomaly')}`",
        f"- **Attack Anomaly:** `{anom.get('attack_anomaly')}` (Confidence: **{anom.get('anomaly_confidence', 0.0)*100:.1f}%**)",
        f"- **Flow Analysis:** {anom.get('details', '')}"
    ]

    # Vulnerabilities Exposed
    lines += [
        "",
        "## 5. Detected Security Impact & Vulnerabilities Exposed"
    ]
    for vuln in impact.get("vulnerabilities_exposed", []):
        lines.append(f"- ⚠️ **{vuln}**")
    if not impact.get("vulnerabilities_exposed"):
        lines.append("- No critical vulnerabilities exposed.")

    # Evidence
    lines += [
        "",
        "## 6. Grounded Evidence Ledger (NIST SP 800-77 & RFCs)",
        ""
    ]
    for ev in evidence:
        deriv = ev.get("derivation", "observed").upper()
        ref = ev.get("nist_reference", "NIST SP 800-77")
        lines.append(f"- **[{deriv}]** {ev.get('finding')} *(Ref: {ref})*")

    # Confidence & Limitations
    lines += [
        "",
        "## 7. Confidence Assessment & Operational Limitations",
        f"- **Overall Confidence:** **{conf.get('overall', 'high').upper()}** ({conf.get('confidence_score', 0.95)*100:.0f}%)",
        f"- **Observed Facts:** {conf.get('observed_facts_count', 0)} certain (read from plaintext IKE_SA_INIT)",
        f"- **Inferred Facts:** {conf.get('inferred_facts_count', 0)} estimated (ML/heuristics from encrypted ESP traffic)",
        f"- **Rationale:** {conf.get('rationale', '')}",
        "",
        "### Limitations:"
    ]
    for lim in limitations:
        lines.append(f"- {lim}")

    # Recommended Actions
    lines += [
        "",
        "## 8. Prioritized Remediation Roadmap"
    ]
    if is_downgrade:
        lines.append("1. **Enforce Proposal Whitelist:** Remove 3DES, DES, MD5, and MODP Groups 2/5 from both Moon and Sun gateway proposals.")
        lines.append("2. **Mandate AES-256-GCM / ECP DH:** Require AES-256-GCM (IKE & ESP) and DH group 19/20/21 (ECP) or group 14+ (MODP-2048).")
    if pfs_change and pfs_change.get("attack") == "off":
        lines.append("3. **Activate PFS on Child SAs:** Append DH groups to `esp` configuration proposals (e.g. `esp=aes256gcm128-ecp384!`).")
    lines.append("4. **Enable On-Path Tamper Auditing:** Monitor IKE exchange message checksums and inspect relay anomalies.")

    return "\n".join(lines)
