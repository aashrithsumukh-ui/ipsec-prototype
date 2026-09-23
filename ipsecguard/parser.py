"""IKE handshake parser & protocol validator — the OBSERVED layer.

Extracts and validates security parameters directly from IKEv1 and IKEv2 packet
captures and payloads according to RFC 7296 (IKEv2) and RFC 2409 / RFC 2408 (IKEv1):
- IKE version (IKEv1 / IKEv2)
- Encryption algorithm & key length (e.g. AES-256-GCM, AES-128-GCM, 3DES-CBC, DES-CBC)
- Integrity / authentication algorithm (e.g. None/AEAD, SHA256, SHA384, SHA1, MD5)
- Diffie-Hellman group (e.g. Group 20, 19, 14, 5, 2)
- PRF algorithm (e.g. PRF-HMAC-SHA256, PRF-HMAC-SHA1, PRF-HMAC-MD5)
- Security Association proposals and transforms
- Strict evidence classification: OBSERVED (packet evidence), INFERRED, UNKNOWN, or FALLBACK_HINT.
- Security validation & weakness detection against NIST SP 800-77 guidelines.
"""
import json
import os
import shutil
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple, Union

# ==============================================================================
# RFC 7296 (IKEv2) Protocol Constants & Dictionaries
# ==============================================================================

IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

IKEV2_PAYLOAD_TYPES = {
    0: "NONE",
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "NONCE",
    41: "NOTIFY",
    43: "DELETE",
    44: "VENDOR_ID",
    45: "TSi",
    46: "TSr",
    47: "SK",
    48: "CP",
    49: "EAP",
}

IKEV2_TRANSFORM_TYPES = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "D-H",
    5: "ESN",
}

IKEV2_ENCR_TRANSFORMS = {
    1: "des-iv64",
    2: "des-cbc",
    3: "3des-cbc",
    11: "null",
    12: "aes-cbc",
    13: "aes-ctr",
    14: "aes-ccm-8",
    15: "aes-ccm-12",
    16: "aes-ccm-16",
    18: "aes-gcm-8",
    19: "aes-gcm-12",
    20: "aes-gcm-16",
    23: "camellia-cbc",
    28: "chacha20-poly1305",
}

IKEV2_PRF_TRANSFORMS = {
    1: "prf-hmac-md5",
    2: "prf-hmac-sha1",
    4: "prf-hmac-sha256",
    5: "prf-hmac-sha384",
    6: "prf-hmac-sha512",
    7: "prf-aes128-xcbc",
}

IKEV2_INTEG_TRANSFORMS = {
    0: "none",
    1: "md5",
    2: "sha1",
    5: "aes-xcbc-96",
    12: "sha256",
    13: "sha384",
    14: "sha512",
}

IKEV2_DH_GROUPS = {
    1: 1,    # 768-bit MODP
    2: 2,    # 1024-bit MODP
    5: 5,    # 1536-bit MODP
    14: 14,  # 2048-bit MODP
    15: 15,  # 3072-bit MODP
    16: 16,  # 4096-bit MODP
    19: 19,  # 256-bit Random ECP (NIST P-256)
    20: 20,  # 384-bit Random ECP (NIST P-384)
    21: 21,  # 521-bit Random ECP (NIST P-521)
    31: 31,  # Curve25519
}

# ==============================================================================
# RFC 2409 / RFC 2408 (IKEv1 / ISAKMP) Protocol Constants & Dictionaries
# ==============================================================================

IKEV1_EXCHANGE_TYPES = {
    2: "Identity Protection (Main Mode)",
    4: "Aggressive Mode",
    32: "Quick Mode",
    33: "New Group Mode",
    34: "Informational",
}

IKEV1_ENCR_ALGORITHMS = {
    1: "des-cbc",
    2: "idea-cbc",
    3: "blowfish-cbc",
    4: "rc5-r16-b64-cbc",
    5: "3des-cbc",
    6: "cast-cbc",
    7: "aes-cbc",
    12: "aes-cbc",
}

IKEV1_HASH_ALGORITHMS = {
    1: "md5",
    2: "sha1",
    3: "tiger",
    4: "sha256",
    5: "sha384",
    6: "sha512",
}

IKEV1_AUTH_METHODS = {
    1: "psk",
    2: "dss",
    3: "rsa-sig",
    4: "rsa-enc",
    5: "revised-rsa-enc",
}

IKEV1_DH_GROUPS = {
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    14: 14,
    19: 19,
    20: 20,
}


# ==============================================================================
# Core IKE Binary Dissection Functions
# ==============================================================================

def _parse_ikev2_transforms(sa_body: bytes, offset: int, end_offset: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Walks IKEv2 proposals and transforms inside an SA payload."""
    proposals = []
    summary = {
        "enc_algo": None,
        "integrity": None,
        "dh_group": None,
        "prf": None,
        "key_length": None,
    }

    prop_off = offset
    while prop_off + 8 <= end_offset and prop_off + 8 <= len(sa_body):
        try:
            next_prop, _r, prop_len, prop_num, proto_id, spi_sz, num_transforms = struct.unpack(
                "!BBHBBBB", sa_body[prop_off:prop_off + 8]
            )
        except Exception:
            break

        if prop_len <= 0 or prop_off + prop_len > len(sa_body):
            break

        prop_end = prop_off + prop_len
        trans_off = prop_off + 8 + spi_sz

        current_proposal = {
            "proposal_num": prop_num,
            "protocol_id": proto_id,
            "protocol_name": {1: "IKE", 2: "AH", 3: "ESP"}.get(proto_id, f"Proto-{proto_id}"),
            "spi_size": spi_sz,
            "transforms": [],
        }

        while trans_off + 8 <= prop_end and trans_off + 8 <= len(sa_body):
            try:
                next_trans, _r2, trans_len, trans_type, _r3, trans_id = struct.unpack(
                    "!BBHBBH", sa_body[trans_off:trans_off + 8]
                )
            except Exception:
                break

            if trans_len <= 0:
                break

            key_len = None
            attr_off = trans_off + 8
            trans_end = trans_off + trans_len
            while attr_off + 4 <= trans_end and attr_off + 4 <= len(sa_body):
                try:
                    attr_type, attr_val = struct.unpack("!HH", sa_body[attr_off:attr_off + 4])
                    if attr_type in (0x800E, 14):  # Key Length Attribute
                        key_len = attr_val
                except Exception:
                    pass
                attr_off += 4

            trans_info = {
                "transform_type": trans_type,
                "type_name": IKEV2_TRANSFORM_TYPES.get(trans_type, f"Type-{trans_type}"),
                "transform_id": trans_id,
                "key_length": key_len,
            }

            # Map to standard field names
            if trans_type == 1:  # ENCR
                enc_name = IKEV2_ENCR_TRANSFORMS.get(trans_id, f"encr-{trans_id}")
                if "gcm" in enc_name:
                    k = key_len or 256
                    enc_name = f"aes{k}-gcm"
                elif "aes-cbc" in enc_name:
                    k = key_len or 256
                    enc_name = f"aes{k}-cbc"
                trans_info["name"] = enc_name
                if summary["enc_algo"] is None:
                    summary["enc_algo"] = enc_name
                    summary["key_length"] = key_len

            elif trans_type == 2:  # PRF
                prf_name = IKEV2_PRF_TRANSFORMS.get(trans_id, f"prf-{trans_id}")
                trans_info["name"] = prf_name
                if summary["prf"] is None:
                    summary["prf"] = prf_name

            elif trans_type == 3:  # INTEG
                integ_name = IKEV2_INTEG_TRANSFORMS.get(trans_id, f"integ-{trans_id}")
                trans_info["name"] = integ_name
                if summary["integrity"] is None:
                    summary["integrity"] = integ_name

            elif trans_type == 4:  # D-H Group
                dh_val = IKEV2_DH_GROUPS.get(trans_id, trans_id)
                trans_info["dh_group"] = dh_val
                if summary["dh_group"] is None:
                    summary["dh_group"] = dh_val

            current_proposal["transforms"].append(trans_info)
            trans_off += trans_len
            if next_trans == 0:
                break

        proposals.append(current_proposal)
        if next_prop == 0:
            break
        prop_off = prop_end

    # For AEAD ciphers (GCM / ChaCha20), integrity is integrated (None)
    if summary["enc_algo"] and "gcm" in summary["enc_algo"] and summary["integrity"] is None:
        summary["integrity"] = "none"

    return proposals, summary


def _parse_ikev1_transforms(sa_body: bytes, offset: int, end_offset: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Walks IKEv1 proposals and transform attributes inside an ISAKMP SA payload."""
    proposals = []
    summary = {
        "enc_algo": None,
        "integrity": None,
        "dh_group": None,
        "auth_method": None,
        "key_length": None,
    }

    if len(sa_body) < offset + 8:
        return proposals, summary

    # IKEv1 SA payload header: DOI (4 bytes), Situation (4 bytes)
    doi, situation = struct.unpack("!II", sa_body[offset:offset + 8])
    prop_off = offset + 8

    while prop_off + 8 <= end_offset and prop_off + 8 <= len(sa_body):
        try:
            next_prop, _r, prop_len, prop_num, proto_id, spi_sz, num_transforms = struct.unpack(
                "!BBHBBBB", sa_body[prop_off:prop_off + 8]
            )
        except Exception:
            break

        if prop_len <= 0 or prop_off + prop_len > len(sa_body):
            break

        prop_end = prop_off + prop_len
        trans_off = prop_off + 8 + spi_sz

        current_proposal = {
            "proposal_num": prop_num,
            "protocol_id": proto_id,
            "protocol_name": {1: "ISAKMP", 2: "AH", 3: "ESP"}.get(proto_id, f"Proto-{proto_id}"),
            "spi_size": spi_sz,
            "transforms": [],
        }

        while trans_off + 8 <= prop_end and trans_off + 8 <= len(sa_body):
            try:
                next_trans, _r2, trans_len, trans_num, trans_id, _r3 = struct.unpack(
                    "!BBHBBH", sa_body[trans_off:trans_off + 8]
                )
            except Exception:
                break

            if trans_len <= 0:
                break

            # Parse IKEv1 ISAKMP Attributes
            attr_off = trans_off + 8
            trans_end = trans_off + trans_len
            attrs = {}

            while attr_off + 4 <= trans_end and attr_off + 4 <= len(sa_body):
                try:
                    raw_type, val = struct.unpack("!HH", sa_body[attr_off:attr_off + 4])
                    is_basic = (raw_type & 0x8000) != 0
                    atype = raw_type & 0x7FFF
                    if is_basic:
                        attrs[atype] = val
                        attr_off += 4
                    else:
                        # Variable length attribute: 2 bytes type, 2 bytes length, then val bytes
                        alen = val
                        attr_off += 4 + alen
                except Exception:
                    break

            # Map IKEv1 Attributes
            # 1: Encryption, 2: Hash, 3: Auth, 4: Group, 14: Key Length
            enc_id = attrs.get(1)
            hash_id = attrs.get(2)
            auth_id = attrs.get(3)
            group_id = attrs.get(4)
            key_len = attrs.get(14)

            enc_name = IKEV1_ENCR_ALGORITHMS.get(enc_id, f"encr-{enc_id}" if enc_id else None)
            if enc_name and "aes" in enc_name:
                k = key_len or 256
                enc_name = f"aes{k}-cbc"

            hash_name = IKEV1_HASH_ALGORITHMS.get(hash_id, f"hash-{hash_id}" if hash_id else None)
            auth_name = IKEV1_AUTH_METHODS.get(auth_id, f"auth-{auth_id}" if auth_id else None)
            dh_val = IKEV1_DH_GROUPS.get(group_id, group_id)

            trans_info = {
                "transform_num": trans_num,
                "transform_id": trans_id,
                "encryption": enc_name,
                "hash": hash_name,
                "auth_method": auth_name,
                "dh_group": dh_val,
                "key_length": key_len,
            }

            if summary["enc_algo"] is None and enc_name:
                summary["enc_algo"] = enc_name
                summary["key_length"] = key_len
            if summary["integrity"] is None and hash_name:
                summary["integrity"] = hash_name
            if summary["dh_group"] is None and dh_val:
                summary["dh_group"] = dh_val
            if summary["auth_method"] is None and auth_name:
                summary["auth_method"] = auth_name

            current_proposal["transforms"].append(trans_info)
            trans_off += trans_len
            if next_trans == 0:
                break

        proposals.append(current_proposal)
        if next_prop == 0:
            break
        prop_off = prop_end

    return proposals, summary


def dissect_ike_packet(raw_data: bytes) -> Optional[Dict[str, Any]]:
    """Dissects a single IKE UDP payload directly from raw bytes.

    Handles port 500 (standard IKE) and port 4500 (NAT-Traversal with 4-byte Non-ESP marker).
    """
    if not raw_data or len(raw_data) < 28:
        return None

    # Handle NAT-T Non-ESP marker (0x00000000)
    has_non_esp_marker = False
    payload = raw_data
    if payload[:4] == b"\x00\x00\x00\x00":
        has_non_esp_marker = True
        payload = payload[4:]

    if len(payload) < 28:
        return None

    try:
        spi_i, spi_r, next_payload, ver_byte, exchange_type, flags, msg_id, total_len = struct.unpack(
            "!8s8sBBBBII", payload[:28]
        )
    except Exception:
        return None

    major_ver = (ver_byte >> 4) & 0x0F
    minor_ver = ver_byte & 0x0F
    ike_version = 2 if major_ver >= 2 else 1

    exchange_name = (
        IKEV2_EXCHANGE_TYPES.get(exchange_type, f"IKEv2-Exch-{exchange_type}")
        if ike_version == 2
        else IKEV1_EXCHANGE_TYPES.get(exchange_type, f"IKEv1-Exch-{exchange_type}")
    )

    result = {
        "ike_version": ike_version,
        "major_version": major_ver,
        "minor_version": minor_ver,
        "exchange_type_id": exchange_type,
        "exchange_type": exchange_name,
        "spi_initiator": f"0x{spi_i.hex()}",
        "spi_responder": f"0x{spi_r.hex()}",
        "flags": flags,
        "is_initiator": bool(flags & 0x08) if ike_version == 2 else bool(flags & 0x00),
        "is_response": bool(flags & 0x20) if ike_version == 2 else False,
        "message_id": msg_id,
        "packet_length": total_len,
        "has_non_esp_marker": has_non_esp_marker,
        "proposals": [],
        "enc_algo": None,
        "integrity": None,
        "dh_group": None,
        "prf": None,
        "key_length": None,
        "auth_method": None,
        "payloads_present": [],
    }

    # Walk payloads
    cur_payload_type = next_payload
    cur_offset = 28
    payload_end = min(len(payload), total_len) if total_len > 0 else len(payload)

    while cur_offset + 4 <= payload_end and cur_payload_type != 0:
        try:
            nxt_p, p_flags, p_len = struct.unpack("!BBH", payload[cur_offset:cur_offset + 4])
        except Exception:
            break

        if p_len < 4 or cur_offset + p_len > len(payload):
            break

        p_name = (
            IKEV2_PAYLOAD_TYPES.get(cur_payload_type, f"Payload-{cur_payload_type}")
            if ike_version == 2
            else f"Payload-{cur_payload_type}"
        )
        result["payloads_present"].append(p_name)

        p_body_start = cur_offset + 4
        p_body_end = cur_offset + p_len

        # Parse SA Payload (Type 33 in IKEv2, Type 1 in IKEv1)
        if (ike_version == 2 and cur_payload_type == 33) or (ike_version == 1 and cur_payload_type == 1):
            if ike_version == 2:
                props, summ = _parse_ikev2_transforms(payload, p_body_start, p_body_end)
            else:
                props, summ = _parse_ikev1_transforms(payload, p_body_start, p_body_end)

            result["proposals"].extend(props)
            for k, v in summ.items():
                if v is not None and result.get(k) is None:
                    result[k] = v

        # Parse Key Exchange (KE) Payload (Type 34 in IKEv2, Type 4 in IKEv1)
        elif ike_version == 2 and cur_payload_type == 34:
            if p_body_start + 4 <= p_body_end:
                try:
                    dh_grp, _res = struct.unpack("!HH", payload[p_body_start:p_body_start + 4])
                    if result["dh_group"] is None:
                        result["dh_group"] = IKEV2_DH_GROUPS.get(dh_grp, dh_grp)
                except Exception:
                    pass

        cur_payload_type = nxt_p
        cur_offset += p_len

    return result


# ==============================================================================
# Public API & Evidence Classification
# ==============================================================================

def parse_ike(pcap_or_packets: Union[str, list, Any], fallback_hint: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Inspects and extracts IKE parameters from PCAP files or packet streams with strict evidence classification.

    Returns a structured dictionary containing:
    - ike_version: int (1 or 2)
    - enc_algo: str (e.g. "aes256-gcm", "3des-cbc")
    - integrity: str (e.g. "none", "sha256", "md5")
    - dh_group: int (e.g. 20, 19, 14, 5, 2)
    - prf: str (optional)
    - key_length: int (optional)
    - proposals: list of structured SA proposals
    - exchange_types: list of unique exchange names
    - evidence_classification: dict mapping fields to "observed" | "inferred" | "unknown" | "fallback_hint"
    - extraction_status: "success" | "partial" | "no_ike_packets" | "failed"
    - unsupported_fields: list
    - warnings: list
    """
    # Initialize output schema with explicit classification
    out = {
        "ike_version": None,
        "enc_algo": None,
        "integrity": None,
        "dh_group": None,
        "prf": None,
        "key_length": None,
        "auth_method": None,
        "spi_initiator": None,
        "spi_responder": None,
        "proposals": [],
        "exchange_types": [],
        "payloads_present": [],
        "evidence_classification": {
            "ike_version": "unknown",
            "enc_algo": "unknown",
            "integrity": "unknown",
            "dh_group": "unknown",
            "prf": "unknown",
            "proposals": "unknown",
        },
        "extraction_status": "no_ike_packets",
        "unsupported_fields": [],
        "warnings": [],
        "_source": "scapy-binary-dissector",
    }

    # 1. Check if TShark is present and input is a valid file path
    if isinstance(pcap_or_packets, str) and shutil.which("tshark") and os.path.exists(pcap_or_packets):
        try:
            tshark_out = _via_tshark(pcap_or_packets)
            if tshark_out.get("ike_version") is not None:
                return tshark_out
        except Exception as e:
            out["warnings"].append(f"TShark parser fallback: {e}")

    # 2. Extract packets via Scapy
    packets = []
    if isinstance(pcap_or_packets, str):
        if not os.path.exists(pcap_or_packets):
            out["extraction_status"] = "failed"
            out["warnings"].append(f"PCAP file not found: {pcap_or_packets}")
            return _apply_fallback_hints(out, fallback_hint)

        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_or_packets)
        except Exception as e:
            out["extraction_status"] = "failed"
            out["warnings"].append(f"Scapy failed to read PCAP: {e}")
            return _apply_fallback_hints(out, fallback_hint)
    elif isinstance(pcap_or_packets, (list, tuple)):
        packets = list(pcap_or_packets)
    else:
        packets = [pcap_or_packets]

    # 3. Dissect IKE packets
    from scapy.layers.inet import UDP
    from scapy.packet import Raw

    ike_packets_found = 0
    unique_exchanges = set()
    unique_payloads = set()

    for pkt in packets:
        raw_bytes = None
        if UDP in pkt:
            udp_layer = pkt[UDP]
            if udp_layer.dport in (500, 4500) or udp_layer.sport in (500, 4500):
                raw_bytes = bytes(udp_layer.payload)
        elif hasattr(pkt, "load"):
            raw_bytes = pkt.load
        elif isinstance(pkt, bytes):
            raw_bytes = pkt

        if not raw_bytes or len(raw_bytes) < 28:
            continue

        dissected = dissect_ike_packet(raw_bytes)
        if not dissected:
            continue

        ike_packets_found += 1
        unique_exchanges.add(dissected["exchange_type"])
        unique_payloads.update(dissected["payloads_present"])

        # Update observed fields from handshake
        if out["ike_version"] is None and dissected["ike_version"]:
            out["ike_version"] = dissected["ike_version"]
            out["evidence_classification"]["ike_version"] = "observed"

        if out["spi_initiator"] is None:
            out["spi_initiator"] = dissected["spi_initiator"]
        if out["spi_responder"] is None:
            out["spi_responder"] = dissected["spi_responder"]

        if dissected.get("enc_algo") and out["enc_algo"] is None:
            out["enc_algo"] = dissected["enc_algo"]
            out["evidence_classification"]["enc_algo"] = "observed"
            out["key_length"] = dissected.get("key_length")

        if dissected.get("integrity") is not None and out["integrity"] is None:
            out["integrity"] = dissected["integrity"]
            out["evidence_classification"]["integrity"] = "observed"

        if dissected.get("dh_group") and out["dh_group"] is None:
            out["dh_group"] = dissected["dh_group"]
            out["evidence_classification"]["dh_group"] = "observed"

        if dissected.get("prf") and out["prf"] is None:
            out["prf"] = dissected["prf"]
            out["evidence_classification"]["prf"] = "observed"

        if dissected.get("auth_method") and out["auth_method"] is None:
            out["auth_method"] = dissected["auth_method"]

        if dissected.get("proposals"):
            out["proposals"].extend(dissected["proposals"])
            out["evidence_classification"]["proposals"] = "observed"

    out["exchange_types"] = sorted(list(unique_exchanges))
    out["payloads_present"] = sorted(list(unique_payloads))

    # Evaluate overall extraction status
    if ike_packets_found > 0:
        if out["enc_algo"] and out["dh_group"]:
            out["extraction_status"] = "success"
        else:
            out["extraction_status"] = "partial"
            out["warnings"].append("Handshake observed but cipher or DH group not negotiated in cleartext.")
    else:
        out["extraction_status"] = "no_ike_packets"
        out["warnings"].append("No IKE handshake packets (UDP 500/4500) found in capture.")

    # 4. Apply fallback hints if packet evidence is missing
    out = _apply_fallback_hints(out, fallback_hint)
    return out


def _apply_fallback_hints(out: Dict[str, Any], fallback_hint: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Applies optional fallback hints strictly without claiming them as observed."""
    if not fallback_hint:
        return out

    for field in ["enc_algo", "integrity", "dh_group", "ike_version"]:
        if out.get(field) is None and field in fallback_hint:
            val = fallback_hint[field]
            if val is not None:
                out[field] = val
                out["evidence_classification"][field] = "fallback_hint"

    if out["extraction_status"] == "no_ike_packets" and any(
        out["evidence_classification"][f] == "fallback_hint" for f in ["enc_algo", "dh_group"]
    ):
        out["_source"] = "fallback_hint"

    return out


def _via_tshark(pcap_path: str) -> Dict[str, Any]:
    """TShark dissector integration for rich ISAKMP environments."""
    cmd = [
        "tshark", "-r", pcap_path, "-Y",
        "isakmp && (isakmp.exchangetype==34 || isakmp.exchangetype==2)",
        "-T", "json"
    ]
    raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    data = json.loads(raw or "[]")

    out = {
        "ike_version": None,
        "enc_algo": None,
        "integrity": None,
        "dh_group": None,
        "prf": None,
        "proposals": [],
        "exchange_types": [],
        "evidence_classification": {
            "ike_version": "unknown",
            "enc_algo": "unknown",
            "integrity": "unknown",
            "dh_group": "unknown",
        },
        "extraction_status": "no_ike_packets",
        "unsupported_fields": [],
        "warnings": [],
        "_source": "tshark",
    }

    for pkt in data:
        layers = pkt.get("_source", {}).get("layers", {})
        isa = layers.get("isakmp")
        if not isa:
            continue

        ver = isa.get("isakmp.version")
        out["ike_version"] = 2 if (ver and ver.startswith("2")) else 1
        out["evidence_classification"]["ike_version"] = "observed"

        blob = json.dumps(isa).lower()
        for name, tag in [
            ("aes-gcm", "aes256-gcm"),
            ("aes-cbc", "aes256-cbc"),
            ("3des", "3des-cbc"),
            ("des", "des-cbc"),
        ]:
            if name in blob:
                out["enc_algo"] = tag
                out["evidence_classification"]["enc_algo"] = "observed"
                break

        for name in ["sha2-256", "sha256", "sha384", "sha1", "md5"]:
            if name in blob:
                out["integrity"] = name.replace("sha2-", "sha")
                out["evidence_classification"]["integrity"] = "observed"
                break

        for g in ["group 21", "group 20", "group 19", "group 14", "group 5", "group 2", "group 1"]:
            if g in blob:
                out["dh_group"] = int(g.split()[-1])
                out["evidence_classification"]["dh_group"] = "observed"
                break

        out["extraction_status"] = "success"
        break

    return out


# ==============================================================================
# IKE Validation & Weakness Verification Engine
# ==============================================================================

def validate_ike_parameters(
    extracted_data: Dict[str, Any],
    reference_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Validates extracted IKE parameters against NIST SP 800-77 criteria and reference expectations.

    Identifies:
    - Outdated/weak cryptography (DES, 3DES, MD5, SHA-1, DH groups 1, 2, 5).
    - Negotiation anomalies and unexpected changes.
    - Missing or incomplete IKE negotiation components.
    - Parsing failures.
    """
    findings = []
    unexpected_changes = []
    missing_fields = []

    enc = extracted_data.get("enc_algo")
    integ = extracted_data.get("integrity")
    dh = extracted_data.get("dh_group")
    ver = extracted_data.get("ike_version")

    # 1. Cryptographic Weakness Checks (NIST SP 800-77)
    if enc:
        enc_lower = str(enc).lower()
        if "3des" in enc_lower:
            findings.append({
                "id": "CRYPTO-3DES-DEPRECATED",
                "severity": "high",
                "title": "3DES-CBC Encryption Negotiated in IKE Proposal",
                "detail": f"Observed cipher '{enc}' is vulnerable to Sweet32 (CVE-2016-2183) collision attacks.",
                "nist_ref": "NIST SP 800-77 Rev. 1 §3.1 / SP 800-131A",
            })
        elif "des" in enc_lower and "3des" not in enc_lower:
            findings.append({
                "id": "CRYPTO-DES-CRITICAL",
                "severity": "critical",
                "title": "Single-DES Encryption Negotiated",
                "detail": f"Observed cipher '{enc}' has 56-bit key length, breakable in real time.",
                "nist_ref": "NIST SP 800-77 Rev. 1 §3.1 / RFC 8247",
            })

    if integ:
        integ_lower = str(integ).lower()
        if "md5" in integ_lower:
            findings.append({
                "id": "AUTH-MD5-VULNERABLE",
                "severity": "high",
                "title": "MD5 Hash Negotiated for Integrity",
                "detail": f"MD5 is cryptographically broken with practical collision attacks.",
                "nist_ref": "NIST SP 800-77 Rev. 1 §3.2 / RFC 6151",
            })
        elif "sha1" in integ_lower:
            findings.append({
                "id": "AUTH-SHA1-DEPRECATED",
                "severity": "medium",
                "title": "SHA-1 Hash Negotiated for Integrity",
                "detail": f"SHA-1 is deprecated for all cryptographic operations.",
                "nist_ref": "NIST SP 800-77 Rev. 1 §3.2 / SP 800-131A",
            })

    if dh:
        if dh in (1, 2):
            findings.append({
                "id": "DH-GROUP-INSECURE",
                "severity": "critical",
                "title": f"Diffie-Hellman Group {dh} (MODP <= 1024) Insecure",
                "detail": f"DH group {dh} is vulnerable to Logjam precomputation attacks.",
                "nist_ref": "NIST SP 800-77 Rev. 1 §3.3 / RFC 8247 §2.4",
            })
        elif dh == 5:
            findings.append({
                "id": "DH-GROUP5-WEAK",
                "severity": "medium",
                "title": "Diffie-Hellman Group 5 (1536-bit MODP) Below Modern Baseline",
                "detail": "MODP-1536 provides ~90-bit security margin; NIST requires >= 112-bit (Group 14+).",
                "nist_ref": "NIST SP 800-77 Rev. 1 §3.3 / RFC 8247",
            })

    if ver == 1:
        findings.append({
            "id": "IKEV1-LEGACY",
            "severity": "medium",
            "title": "Legacy IKEv1 Protocol in Use",
            "detail": "IKEv1 lacks native AEAD support and has known authentication design weaknesses.",
            "nist_ref": "NIST SP 800-77 Rev. 1 §2.1",
        })

    # 2. Check for missing fields
    for k in ["ike_version", "enc_algo", "dh_group"]:
        if extracted_data.get(k) is None:
            missing_fields.append(k)

    # 3. Compare with reference expectations if provided
    if reference_data:
        for field, expected_val in reference_data.items():
            extracted_val = extracted_data.get(field)
            if extracted_val is not None and expected_val is not None and str(extracted_val).lower() != str(expected_val).lower():
                unexpected_changes.append({
                    "parameter": field,
                    "expected": expected_val,
                    "extracted": extracted_val,
                    "evidence": extracted_data.get("evidence_classification", {}).get(field, "unknown"),
                })

    is_valid = len(findings) == 0 and len(unexpected_changes) == 0 and len(missing_fields) == 0

    return {
        "is_valid": is_valid,
        "extraction_status": extracted_data.get("extraction_status", "unknown"),
        "weaknesses_identified": findings,
        "unexpected_changes": unexpected_changes,
        "missing_fields": missing_fields,
        "evidence_classification": extracted_data.get("evidence_classification", {}),
        "total_weaknesses": len(findings),
    }
