"""Unit tests for IKE Protocol Parsing, Evidence Classification & Validation."""
import unittest
import struct
from scapy.all import IP, UDP, Raw
from ipsecguard.parser import parse_ike, dissect_ike_packet, validate_ike_parameters


def _build_ikev2_sa_init_packet(
    enc_id=20,  # 20 = AES-GCM-16
    key_len=256,
    prf_id=4,   # 4 = PRF_HMAC_SHA2_256
    integ_id=0, # 0 = NONE (AEAD)
    dh_id=20,   # 20 = 384-bit ECP (Group 20)
    nat_t=False
):
    """Constructs a valid binary IKEv2 IKE_SA_INIT packet with SA and KE payloads."""
    # Transforms
    transforms = bytearray()
    
    # Transform 1: ENCR (Type 1)
    if key_len:
        t1 = struct.pack("!BBHBBH", 3, 0, 12, 1, 0, enc_id) + struct.pack("!HH", 0x800E, key_len)
    else:
        t1 = struct.pack("!BBHBBH", 3, 0, 8, 1, 0, enc_id)
    transforms += t1

    # Transform 2: PRF (Type 2)
    t2 = struct.pack("!BBHBBH", 3, 0, 8, 2, 0, prf_id)
    transforms += t2

    # Transform 3: INTEG (Type 3)
    t3 = struct.pack("!BBHBBH", 3, 0, 8, 3, 0, integ_id)
    transforms += t3

    # Transform 4: D-H (Type 4, last transform)
    t4 = struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_id)
    transforms += t4

    # Proposal header: next_prop=0, res=0, prop_len, prop_num=1, proto=1 (IKE), spi_sz=0, num_trans=4
    prop_len = 8 + len(transforms)
    proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, 4) + bytes(transforms)

    # SA Payload (Type 33): next_payload=34 (KE), flags=0, sa_len
    sa_len = 4 + len(proposal)
    sa_payload = struct.pack("!BBH", 34, 0, sa_len) + proposal

    # KE Payload (Type 34): next_payload=0, flags=0, ke_len=8+32, dh_group=dh_id, res=0, ke_data
    ke_len = 8 + 32
    ke_payload = struct.pack("!BBHHH", 0, 0, ke_len, dh_id, 0) + (b"\xaa" * 32)

    # IKE Header: SPIi (8B), SPIr (8B), Next Payload (33=SA), Version (0x20=2.0), Exch (34=IKE_SA_INIT), Flags (0x08=Init), MsgID (0), Length
    total_len = 28 + len(sa_payload) + len(ke_payload)
    ike_hdr = struct.pack("!8s8sBBBBII", b"\x11\x22\x33\x44\x55\x66\x77\x88", b"\x00"*8, 33, 0x20, 34, 0x08, 0, total_len)

    raw_ike = ike_hdr + sa_payload + ke_payload
    if nat_t:
        raw_ike = b"\x00\x00\x00\x00" + raw_ike

    pkt = IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=4500 if nat_t else 500, dport=4500 if nat_t else 500) / Raw(raw_ike)
    return pkt


def _build_ikev1_main_mode_packet():
    """Constructs a valid binary IKEv1 Main Mode ISAKMP packet with 3DES-CBC, MD5, and DH-2."""
    # Attribute 1: Enc=5 (3DES), Attribute 2: Hash=1 (MD5), Attribute 3: Auth=1 (PSK), Attribute 4: Group=2 (MODP-1024)
    attrs = bytearray()
    attrs += struct.pack("!HH", 0x8001, 5)  # 3DES-CBC
    attrs += struct.pack("!HH", 0x8002, 1)  # MD5
    attrs += struct.pack("!HH", 0x8003, 1)  # PSK
    attrs += struct.pack("!HH", 0x8004, 2)  # DH Group 2

    # Transform: next_trans=0, res=0, trans_len=8+len(attrs), trans_num=1, trans_id=1 (KEY_IKE), res=0
    trans_len = 8 + len(attrs)
    transform = struct.pack("!BBHBBH", 0, 0, trans_len, 1, 1, 0) + bytes(attrs)

    # Proposal: next_prop=0, res=0, prop_len=8+trans_len, prop_num=1, proto=1 (ISAKMP), spi_sz=0, num_trans=1
    prop_len = 8 + len(transform)
    proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, 1) + transform

    # SA Payload (Type 1): next_payload=0, res=0, sa_len=12+prop_len, DOI=1 (IPsec), Situation=1
    sa_len = 12 + len(proposal)
    sa_payload = struct.pack("!BBHII", 0, 0, sa_len, 1, 1) + proposal

    # ISAKMP Header: Initiator Cookie (8B), Responder Cookie (8B), Next Payload (1=SA), Version (0x10=1.0), Exch (2=Main Mode), Flags (0), MsgID (0), Length
    total_len = 28 + len(sa_payload)
    hdr = struct.pack("!8s8sBBBBII", b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11", b"\x00"*8, 1, 0x10, 2, 0, 0, total_len)

    raw_isakmp = hdr + sa_payload
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / Raw(raw_isakmp)
    return pkt


class TestIKEProtocolParser(unittest.TestCase):

    def test_ikev2_sa_init_parsing(self):
        """Test accurate parsing of modern IKEv2 IKE_SA_INIT with AES-256-GCM and DH Group 20."""
        pkt = _build_ikev2_sa_init_packet(enc_id=20, key_len=256, dh_id=20)
        res = parse_ike([pkt])

        self.assertEqual(res["ike_version"], 2)
        self.assertEqual(res["enc_algo"], "aes256-gcm")
        self.assertEqual(res["integrity"], "none")
        self.assertEqual(res["dh_group"], 20)
        self.assertEqual(res["prf"], "prf-hmac-sha256")
        self.assertEqual(res["extraction_status"], "success")

        # Evidence classification must be OBSERVED
        self.assertEqual(res["evidence_classification"]["ike_version"], "observed")
        self.assertEqual(res["evidence_classification"]["enc_algo"], "observed")
        self.assertEqual(res["evidence_classification"]["dh_group"], "observed")

    def test_ikev2_nat_t_non_esp_marker(self):
        """Test IKEv2 dissection with 4-byte Non-ESP marker on port 4500."""
        pkt = _build_ikev2_sa_init_packet(enc_id=12, key_len=128, dh_id=14, nat_t=True)
        res = parse_ike([pkt])

        self.assertEqual(res["ike_version"], 2)
        self.assertEqual(res["enc_algo"], "aes128-cbc")
        self.assertEqual(res["dh_group"], 14)
        self.assertEqual(res["evidence_classification"]["enc_algo"], "observed")

    def test_ikev1_main_mode_parsing(self):
        """Test accurate parsing of legacy IKEv1 Main Mode with 3DES-CBC, MD5, and DH-2."""
        pkt = _build_ikev1_main_mode_packet()
        res = parse_ike([pkt])

        self.assertEqual(res["ike_version"], 1)
        self.assertEqual(res["enc_algo"], "3des-cbc")
        self.assertEqual(res["integrity"], "md5")
        self.assertEqual(res["dh_group"], 2)
        self.assertEqual(res["extraction_status"], "success")
        self.assertEqual(res["evidence_classification"]["enc_algo"], "observed")

    def test_evidence_classification_when_no_ike_present(self):
        """Test that missing IKE packets are strictly labeled as unknown without fabricating data."""
        non_ike_pkt = IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=80, dport=80) / Raw(b"GET / HTTP/1.1\r\n")
        res = parse_ike([non_ike_pkt])

        self.assertIsNone(res["enc_algo"])
        self.assertIsNone(res["dh_group"])
        self.assertEqual(res["extraction_status"], "no_ike_packets")
        self.assertEqual(res["evidence_classification"]["enc_algo"], "unknown")
        self.assertEqual(res["evidence_classification"]["dh_group"], "unknown")

    def test_fallback_hint_labeling(self):
        """Test that hints used as fallbacks are clearly labeled as fallback_hint and NOT observed."""
        non_ike_pkt = IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=80, dport=80) / Raw(b"GET / HTTP/1.1\r\n")
        hint = {"enc_algo": "aes256-gcm", "dh_group": 19, "integrity": "none"}
        res = parse_ike([non_ike_pkt], fallback_hint=hint)

        self.assertEqual(res["enc_algo"], "aes256-gcm")
        self.assertEqual(res["dh_group"], 19)
        self.assertEqual(res["evidence_classification"]["enc_algo"], "fallback_hint")
        self.assertEqual(res["evidence_classification"]["dh_group"], "fallback_hint")
        self.assertNotEqual(res["evidence_classification"]["enc_algo"], "observed")

    def test_ike_parameter_validation_clean(self):
        """Test parameter validation on a modern, secure IKEv2 session."""
        pkt = _build_ikev2_sa_init_packet(enc_id=20, key_len=256, dh_id=20)
        extracted = parse_ike([pkt])
        val = validate_ike_parameters(extracted, reference_data={"enc_algo": "aes256-gcm", "dh_group": 20})

        self.assertTrue(val["is_valid"])
        self.assertEqual(len(val["weaknesses_identified"]), 0)
        self.assertEqual(len(val["unexpected_changes"]), 0)

    def test_ike_parameter_validation_weaknesses(self):
        """Test parameter validation identifying weak crypto (3DES, MD5, DH-2, IKEv1)."""
        pkt = _build_ikev1_main_mode_packet()
        extracted = parse_ike([pkt])
        val = validate_ike_parameters(extracted, reference_data={"enc_algo": "aes256-gcm", "dh_group": 20})

        self.assertFalse(val["is_valid"])
        weakness_ids = [w["id"] for w in val["weaknesses_identified"]]
        self.assertIn("CRYPTO-3DES-DEPRECATED", weakness_ids)
        self.assertIn("AUTH-MD5-VULNERABLE", weakness_ids)
        self.assertIn("DH-GROUP-INSECURE", weakness_ids)
        self.assertIn("IKEV1-LEGACY", weakness_ids)

        # Mismatch against expected reference
        self.assertGreater(len(val["unexpected_changes"]), 0)


if __name__ == "__main__":
    unittest.main()
