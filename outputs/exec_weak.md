# Executive Summary — IPsecGuard AI
**Session:** site-A (weak)
**Risk score:** 12/100  ·  **Posture:** Critical

## Top risks
- **Deprecated cipher (3DES)** (high, observed) — Move to AES-GCM (AES-256-GCM preferred).
- **Weak integrity (md5)** (high, observed) — Use SHA-256 or SHA-384 (or an AEAD cipher).
- **Legacy DH group 5** (high, observed) — Use group 19/20/21 (ECP) or 14+ (MODP) at minimum.