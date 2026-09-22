"""Report generation: executive (plain-language) + technical (full detail)."""
def _band(score):
    return ("Critical", "#b3261e") if score < 40 else \
           ("At risk", "#d97706") if score < 70 else \
           ("Acceptable", "#2f7d32") if score < 88 else ("Strong", "#1b5e20")

def executive_md(result, session):
    band, _ = _band(result["risk_score"])
    top = sorted(result["findings"],
                 key=lambda f: {"critical":4,"high":3,"medium":2,"low":1,"info":0}[f["severity"]],
                 reverse=True)[:3]
    lines = [f"# Executive Summary — IPsecGuard AI",
             f"**Session:** {session}",
             f"**Risk score:** {result['risk_score']}/100  ·  **Posture:** {band}", "",
             "## Top risks"]
    if not top:
        lines.append("- No significant weaknesses detected.")
    for f in top:
        tag = "observed" if f["derivation"] == "observed" else f"inferred, {f['confidence_pct']}%"
        lines.append(f"- **{f['title']}** ({f['severity']}, {tag}) — {f['recommendation']}")
    return "\n".join(lines)

def technical_md(result, session, observed, inferred):
    lines = [f"# Technical Report — IPsecGuard AI", f"Session: `{session}`", "",
             f"Risk score: **{result['risk_score']}/100**", "",
             "## Observed (read from plaintext IKE_SA_INIT)"]
    for k, v in observed.items():
        if not k.startswith("_"):
            lines.append(f"- {k}: `{v}`")
    lines += ["", "## Inferred (from encrypted-traffic metadata)"]
    for k, v in inferred.items():
        if not k.endswith("_conf") and not k.startswith("_"):
            lines.append(f"- {k}: `{v}`")
    lines += ["", "## Subscores"]
    for k, v in result["subscores"].items():
        lines.append(f"- {k.replace('_',' ')}: {v}/100")
    lines += ["", "## Findings"]
    for f in result["findings"]:
        tag = "OBSERVED (certain)" if f["derivation"] == "observed" else f"INFERRED ({f['confidence_pct']}% confidence)"
        lines += [f"### [{f['severity'].upper()}] {f['title']}  —  {tag}",
                  f"{f['detail']}",
                  f"- NIST/RFC: {f['nist_ref']}",
                  f"- Recommendation: {f['recommendation']}", ""]
    return "\n".join(lines)
