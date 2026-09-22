# Technical Report — IPsecGuard AI
Session: `site-A (weak)`

Risk score: **12/100**

## Observed (read from plaintext IKE_SA_INIT)
- enc_algo: `3des-cbc`
- integrity: `md5`
- dh_group: `5`
- ike_version: `1`

## Inferred (from encrypted-traffic metadata)
- traffic_type: `voip`
- pfs: `off`
- mode: `transport`
- anomaly: `True`

## Subscores
- crypto strength: 25/100
- key management: 40/100
- forward secrecy: 35/100
- metadata exposure: 60/100

## Findings
### [HIGH] Deprecated cipher (3DES)  —  OBSERVED (certain)
IKE SA negotiated 3des-cbc. 3DES is deprecated (64-bit block, Sweet32).
- NIST/RFC: NIST SP 800-77 Sec.3; RFC 8221
- Recommendation: Move to AES-GCM (AES-256-GCM preferred).

### [HIGH] Weak integrity (md5)  —  OBSERVED (certain)
md5 is broken/deprecated for integrity protection.
- NIST/RFC: RFC 8247
- Recommendation: Use SHA-256 or SHA-384 (or an AEAD cipher).

### [HIGH] Legacy DH group 5  —  OBSERVED (certain)
MODP group 5 is below current strength guidance.
- NIST/RFC: RFC 8247; NIST SP 800-77
- Recommendation: Use group 19/20/21 (ECP) or 14+ (MODP) at minimum.

### [HIGH] Perfect Forward Secrecy disabled  —  INFERRED (71% confidence)
No fresh DH on Child SA rekey — one key compromise exposes more traffic.
- NIST/RFC: NIST SP 800-77 Sec.4
- Recommendation: Enable PFS (add a DH group to the ESP proposal).

### [LOW] Transport mode detected  —  INFERRED (63% confidence)
Inner IP header is not encapsulated — endpoint addresses are exposed.
- NIST/RFC: RFC 4301 Sec.3.2
- Recommendation: Use tunnel mode where addressing privacy matters.

### [MEDIUM] Behavioural anomaly flagged  —  INFERRED (66% confidence)
ESP flow deviates from the clean-session baseline — investigate (possible on-path relay, downgrade, or misconfiguration).
- NIST/RFC: -
- Recommendation: Manually review this session's path and negotiation.
