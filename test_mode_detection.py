"""Unit tests for Automatic IPsec Tunnel & Transport Mode Detection."""
import unittest
from scapy.all import IP, UDP, Raw
from scapy.layers.ipsec import ESP
from ipsecguard import detect_ipsec_mode

class TestModeDetection(unittest.TestCase):

    def test_tunnel_mode_via_nested_ip(self):
        """Test direct observation of nested IP encapsulation (IP-in-IP tunnel)."""
        inner_pkt = IP(src="10.0.1.5", dst="10.0.2.5") / Raw(b"GET / HTTP/1.1\r\n\r\n")
        outer_pkt = IP(src="192.168.10.10", dst="192.168.20.20", proto=50) / ESP(spi=0x12345678, seq=1) / inner_pkt

        res = detect_ipsec_mode([outer_pkt])
        self.assertEqual(res["detected_mode"], "tunnel")
        self.assertEqual(res["derivation"], "observed")
        self.assertGreaterEqual(res["confidence"], 0.95)
        self.assertIn("nested IP", res["evidence"][0])

    def test_transport_mode_via_ikev2_notify(self):
        """Test direct observation of IKEv2 USE_TRANSPORT_MODE notify payload (0x4007)."""
        # IKE packet carrying notify type 16391 (0x4007)
        ike_payload = b"\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x40\x07\x00\x08\x01\x00\x00\x00"
        ike_pkt = IP(src="192.168.10.10", dst="192.168.20.20") / UDP(sport=500, dport=500) / Raw(ike_payload)

        res = detect_ipsec_mode([ike_pkt])
        self.assertEqual(res["detected_mode"], "transport")
        self.assertEqual(res["derivation"], "observed")
        self.assertGreaterEqual(res["confidence"], 0.95)
        self.assertIn("USE_TRANSPORT_MODE", res["evidence"][0])

    def test_transport_mode_via_ikev1_encap_attr(self):
        """Test direct observation of IKEv1 Quick Mode attribute 4 (val=2 Transport)."""
        # IKEv1 SA payload with attribute 4 = 2 (\x80\x04\x00\x02)
        ike_payload = b"\x00\x00\x00\x00" + b"\x80\x04\x00\x02"
        ike_pkt = IP(src="192.168.10.10", dst="192.168.20.20") / UDP(sport=500, dport=500) / Raw(ike_payload)

        res = detect_ipsec_mode([ike_pkt])
        self.assertEqual(res["detected_mode"], "transport")
        self.assertEqual(res["derivation"], "observed")
        self.assertIn("Transport Mode", res["evidence"][0])

    def test_standard_esp_tunnel_default(self):
        """Test that plain ESP traffic defaults to Tunnel mode per RFC 7296 when no Transport notify is present."""
        esp_pkt = IP(src="192.168.10.10", dst="192.168.20.20", proto=50) / ESP(spi=0x99887766, seq=10) / Raw(b"X" * 100)

        res = detect_ipsec_mode([esp_pkt])
        self.assertEqual(res["detected_mode"], "tunnel")
        self.assertEqual(res["derivation"], "inferred")
        self.assertGreaterEqual(res["confidence"], 0.75)

    def test_fallback_hint_when_inconclusive(self):
        """Test using fallback hint on inconclusive / non-IPsec captures."""
        non_ipsec_pkt = IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=53) / Raw(b"DNS")

        res = detect_ipsec_mode([non_ipsec_pkt], fallback_hint="transport")
        self.assertEqual(res["detected_mode"], "transport")
        self.assertEqual(res["derivation"], "hint")
        self.assertGreater(len(res["limitations"]), 0)

    def test_session_dict_detection(self):
        """Test detecting mode from session dictionary metadata."""
        sess_dict = {
            "inferred": {"mode": "transport", "mode_conf": 0.65},
            "flow_features": {"pkt_size_mean": 540.0}
        }
        res = detect_ipsec_mode(sess_dict)
        self.assertEqual(res["detected_mode"], "transport")
        self.assertEqual(res["confidence"], 0.65)

if __name__ == "__main__":
    unittest.main()
