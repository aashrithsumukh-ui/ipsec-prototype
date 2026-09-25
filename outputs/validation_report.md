# Security Assessment & Evidence Validation Report
**IPsecGuard AI — Attack Impact & Verification Engine**

## 1. Executive Summary
- **Baseline Session:** `ikev2_tunnel_aes256-gcm_none_dh20_pfs-on_web.pcap` (Risk Score: **100/100**, Posture: **Strong**)
- **Attack / Negotiated Session:** `ikev1_transport_3des-cbc_md5_dh2_pfs-off_bulk.pcap` (Risk Score: **20/100**, Posture: **Weak**)
- **Score Transition:** `100` → `20` (Delta: **-80 points**, Posture: **Strong -> Weak**)
- **Impact Severity:** **CRITICAL**
- **Summary:** Security posture degraded by 80 points (Strong -> Weak). Identified 6 configuration delta(s) exposing 5 primary vulnerability vector(s).

> [!CRITICAL] **Cryptographic Downgrade Detected**
> An active proposal downgrade was identified across 6 security parameter(s). Strong proposals were suppressed during negotiation.

## 2. Before-and-After Security Parameter Comparison

| Parameter | Baseline | After Attack / Negotiated | Derivation | Change Status | Impact Level |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `enc_algo` | `aes256-gcm` | `3des-cbc` | observed | **DOWNGRADED** | HIGH |
| `integrity` | `none` | `md5` | observed | **DOWNGRADED** | HIGH |
| `dh_group` | `20` | `2` | observed | **DOWNGRADED** | HIGH |
| `ike_version` | `2` | `1` | observed | **DOWNGRADED** | MEDIUM |
| `pfs` | `on` | `off` | inferred | **DOWNGRADED** | HIGH |
| `mode` | `tunnel` | `transport` | inferred | **DOWNGRADED** | LOW |

### Security Subscore Breakdown

| Subscore Category | Baseline | After Attack | Difference |
| :--- | :--- | :--- | :--- |
| Crypto Strength | 100/100 | 25/100 | -75 |
| Key Management | 100/100 | 40/100 | -60 |
| Forward Secrecy | 100/100 | 35/100 | -65 |
| Metadata Exposure | 90/100 | 60/100 | -30 |

## 3. Forward Secrecy (PFS) Verification Status

- **PFS State:** **DISABLED / MISSING** (`PFS-OFF`)
- **Cryptographic Risk:** No fresh Diffie-Hellman exchange is conducted during Child SA rekeys. Compromise of the long-term IKE secret compromises all past and future encrypted traffic.
- **Recommendation:** Enable PFS in IPsec proposals (`pfs=yes` / add DH group to ESP proposal).

## 4. Anomaly Detection & Flow Deviations
- **Baseline Anomaly:** `False`
- **Attack Anomaly:** `False` (Confidence: **0.0%**)
- **Flow Analysis:** Traffic metadata matches baseline behavior.

## 5. Detected Security Impact & Vulnerabilities Exposed
- ⚠️ **Sweet32 Birthday Attack on 64-bit block ciphers (CVE-2016-2183)**
- ⚠️ **Cryptographic collision attacks on MD5 (RFC 6151)**
- ⚠️ **Discrete Logarithm / Logjam Precomputation Attacks on small prime MODP groups (RFC 8247)**
- ⚠️ **Loss of Forward Secrecy: Long-term key compromise allows retroactive plaintext recovery**
- ⚠️ **Endpoint address and traffic flow pattern leakage (RFC 4301)**

## 6. Grounded Evidence Ledger (NIST SP 800-77 & RFCs)

- **[OBSERVED]** enc_algo negotiated 3des-cbc (previously aes256-gcm) *(Ref: NIST SP 800-77 Sec.3)*
- **[OBSERVED]** integrity negotiated md5 (previously none) *(Ref: NIST SP 800-77 Sec.3)*
- **[OBSERVED]** dh_group negotiated 2 (previously 20) *(Ref: RFC 8247)*
- **[OBSERVED]** ike_version negotiated 1 (previously 2) *(Ref: RFC 8247)*
- **[INFERRED]** pfs status transitioned to off *(Ref: NIST SP 800-77 Sec.4)*
- **[INFERRED]** mode status transitioned to transport *(Ref: RFC 4301)*

## 7. Confidence Assessment & Operational Limitations
- **Overall Confidence:** **HIGH** (95%)
- **Observed Facts:** 4 certain (read from plaintext IKE_SA_INIT)
- **Inferred Facts:** 2 estimated (ML/heuristics from encrypted ESP traffic)
- **Rationale:** High confidence: Core cryptographic algorithms (cipher, integrity, DH) were directly observed from plaintext IKE_SA_INIT negotiation.

### Limitations:
- PFS status is inferred from Child SA rekey heuristics or runtime hints unless live XFRM kernel state is inspected.
- Tunnel vs Transport mode was inferred from ESP packet sizes and IP encapsulation heuristics without inner packet decryption.
- Encrypted ESP payload content is opaque; analysis is strictly grounded in cleartext IKE negotiation and ESP statistical metadata.

## 8. Prioritized Remediation Roadmap
1. **Enforce Proposal Whitelist:** Remove 3DES, DES, MD5, and MODP Groups 2/5 from both Moon and Sun gateway proposals.
2. **Mandate AES-256-GCM / ECP DH:** Require AES-256-GCM (IKE & ESP) and DH group 19/20/21 (ECP) or group 14+ (MODP-2048).
3. **Activate PFS on Child SAs:** Append DH groups to `esp` configuration proposals (e.g. `esp=aes256gcm128-ecp384!`).
4. **Enable On-Path Tamper Auditing:** Monitor IKE exchange message checksums and inspect relay anomalies.