"""The confidence-tagged finding model — the thesis of the project in code.

Every finding declares HOW it was derived:
  observed  -> read directly from plaintext IKE_SA_INIT (certain)
  inferred  -> produced by ML / heuristic from encrypted-traffic metadata
  config    -> known only because we control the testbed (validation use only)
"""
from dataclasses import dataclass, field, asdict
from typing import Optional

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
