"""Unit tests for IPv6 IPsec Analysis Support."""
import os
import struct
import tempfile
import unittest

from scapy.all import Ether, IP, IPv6, UDP, Raw, wrpcap
from scapy.layers.ipsec import ESP

from ipsecguard.pcap_validator import validate_pcap_file
from ipsecguard.features import extract_flow_features, extract_ip_flow_metadata
from ipsecguard.mode_detector import detect_ipsec_mode
from ipsecguard.parser import parse_ike
from ipsecguard.analyze import analyze_pcap, safe_analyze_pcap
from ipsecguard.classifier import TrafficClassifier
from ipsecguard.anomaly import AnomalyDetector
from ipsecguard.synth import generate

ETH_HDR = lambda: Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")


def _build_synthetic_ipv6_ikev2_packet(enc_id=20, key_len=256, dh_id=20):
    """Constructs a minimal synthetic IPv6 IKEv2 IKE_SA_INIT packet for parser testing."""
    transforms = bytearray()
    # ENCR
    transforms += struct.pack("!BBHBBH", 3, 0, 12, 1, 0, enc_id) + struct.pack("!HH", 0x800E, key_len)
    # PRF
    transforms += struct.pack("!BBHBBH", 3, 0, 8, 2, 0, 4)
    # INTEG
    transforms += struct.pack("!BBHBBH", 3, 0, 8, 3, 0, 0)
    # D-H
    transforms += struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_id)

    prop_len = 8 + len(transforms)
    proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, 4) + bytes(transforms)
    sa_len = 4 + len(proposal)
    sa_payload = struct.pack("!BBH", 34, 0, sa_len) + proposal

    ke_len = 8 + 32
    ke_payload = struct.pack("!BBHHH", 0, 0, ke_len, dh_id, 0) + (b"\xcc" * 32)

    total_len = 28 + len(sa_payload) + len(ke_payload)
    ike_hdr = struct.pack("!8s8sBBBBII", b"\x01\x02\x03\x04\x05\x06\x07\x08", b"\x00"*8, 33, 0x20, 34, 0x08, 0, total_len)
    raw_ike = ike_hdr + sa_payload + ke_payload

    pkt = ETH_HDR() / IPv6(src="2001:db8:1::1", dst="2001:db8:2::2") / UDP(sport=500, dport=500) / Raw(raw_ike)
    return pkt


class TestIPv6IPsecSupport(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.df = generate(60, 5)
        cls.clf = TrafficClassifier()
        cls.clf.fit_eval(cls.df)
        cls.anom = AnomalyDetector().fit(cls.df)

    def setUp(self):
        self.temp_files = []

    def tearDown(self):
        for path in self.temp_files:
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except Exception:
                    pass

    def _create_temp_pcap(self, packets) -> str:
        f = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        f.close()
        wrpcap(f.name, packets)
        self.temp_files.append(f.name)
        return f.name

    def test_ipv6_flow_feature_extraction(self):
        """Test feature extraction on IPv6 ESP packets."""
        pkts = [
            ETH_HDR() / IPv6(src="2001:db8:abcd::1", dst="2001:db8:abcd::2", nh=50) / ESP(spi=0x998877, seq=i) / Raw(b"E" * (100 + i * 10))
            for i in range(1, 15)
        ]
        feats = extract_flow_features(pkts, min_esp=5)

        self.assertEqual(feats["pkt_count"], 14.0)
        self.assertGreater(feats["pkt_size_mean"], 100.0)
        self.assertIn("bytes_ratio_updown", feats)

    def test_ipv6_flow_metadata_and_endpoints(self):
        """Test extraction of IPv6 source and destination endpoints, byte counts, and IP version."""
        pkts = [
            ETH_HDR() / IPv6(src="2001:db8::10", dst="2001:db8::20", nh=50) / ESP(spi=0x1122, seq=1) / Raw(b"A"*50),
            ETH_HDR() / IPv6(src="2001:db8::20", dst="2001:db8::10", nh=50) / ESP(spi=0x1122, seq=2) / Raw(b"B"*60),
        ]
        meta = extract_ip_flow_metadata(pkts)

        self.assertEqual(meta["ip_version"], "v6")
        self.assertEqual(meta["ipv6_packets"], 2)
        self.assertEqual(meta["ipv4_packets"], 0)
        self.assertIn("2001:db8::10", meta["ipv6_endpoints"]["sources"])
        self.assertIn("2001:db8::20", meta["ipv6_endpoints"]["destinations"])

    def test_ipv6_ike_dissection(self):
        """Test cleartext IKEv2 dissection carried over IPv6 transport."""
        pkt = _build_synthetic_ipv6_ikev2_packet(enc_id=20, key_len=256, dh_id=20)
        res = parse_ike([pkt])

        self.assertEqual(res["ike_version"], 2)
        self.assertEqual(res["enc_algo"], "aes256-gcm")
        self.assertEqual(res["dh_group"], 20)
        self.assertEqual(res["evidence_classification"]["enc_algo"], "observed")

    def test_ipv6_nested_ip_tunnel_mode_detection(self):
        """Test automatic tunnel mode detection on IPv6-in-IPv6 encapsulated packets."""
        inner_pkt = IPv6(src="fd00:1::10", dst="fd00:2::20") / Raw(b"DATA")
        outer_pkt = ETH_HDR() / IPv6(src="2001:db8:1::1", dst="2001:db8:2::2", nh=50) / ESP(spi=0x5544, seq=1) / inner_pkt

        res = detect_ipsec_mode([outer_pkt])
        self.assertEqual(res["detected_mode"], "tunnel")
        self.assertEqual(res["derivation"], "observed")
        self.assertGreaterEqual(res["confidence"], 0.95)

    def test_ipv6_pcap_validator_census(self):
        """Test that validate_pcap_file detects IPv6 sessions accurately in census."""
        pkts = [
            ETH_HDR() / IPv6(src="fe80::1", dst="fe80::2", nh=50) / ESP(spi=0x7777, seq=1) / Raw(b"TEST"*10)
        ]
        pcap_path = self._create_temp_pcap(pkts)
        census = validate_pcap_file(pcap_path)

        self.assertEqual(census["ip_version"], "v6")
        self.assertEqual(census["ipv6_packets"], 1)
        self.assertEqual(census["ipv4_packets"], 0)
        self.assertTrue(census["has_ipsec_traffic"])

    def test_dual_stack_census(self):
        """Test census detection of dual-stack IPv4 and IPv6 traffic in the same capture."""
        p_v4 = ETH_HDR() / IP(src="192.168.1.1", dst="192.168.1.2", proto=50) / ESP(spi=0x11, seq=1) / Raw(b"V4")
        p_v6 = ETH_HDR() / IPv6(src="2001:db8::1", dst="2001:db8::2", nh=50) / ESP(spi=0x22, seq=1) / Raw(b"V6")
        pcap_path = self._create_temp_pcap([p_v4, p_v6])
        census = validate_pcap_file(pcap_path)

        self.assertEqual(census["ip_version"], "dual-stack")
        self.assertEqual(census["ipv4_packets"], 1)
        self.assertEqual(census["ipv6_packets"], 1)

    def test_ipv4_regression_preservation(self):
        """Test that standard IPv4 captures continue to analyze cleanly without regression."""
        pkts = [
            ETH_HDR() / IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / ESP(spi=0x3344, seq=i) / Raw(b"REG"*20)
            for i in range(10)
        ]
        pcap_path = self._create_temp_pcap(pkts)
        res = analyze_pcap(pcap_path, self.clf, self.anom)

        self.assertEqual(res["ip_version"], "v4")
        self.assertEqual(res["census"]["ipv4_packets"], 10)
        self.assertEqual(res["census"]["ipv6_packets"], 0)
        self.assertIn("risk_score", res)

    def test_end_to_end_ipv6_analyze_pcap(self):
        """Test full end-to-end analysis on an IPv6 IPsec session capture."""
        ike_pkt = _build_synthetic_ipv6_ikev2_packet(enc_id=20, key_len=256, dh_id=20)
        esp_pkts = [
            ETH_HDR() / IPv6(src="2001:db8:1::1", dst="2001:db8:2::2", nh=50) / ESP(spi=0x1234, seq=i) / Raw(b"X"*120)
            for i in range(1, 12)
        ]
        pcap_path = self._create_temp_pcap([ike_pkt] + esp_pkts)

        res = analyze_pcap(pcap_path, self.clf, self.anom)
        self.assertEqual(res["ip_version"], "v6")
        self.assertEqual(res["observed"]["enc_algo"], "aes256-gcm")
        self.assertEqual(res["observed"]["dh_group"], 20)
        self.assertIn("2001:db8:1::1", res["flow_metadata"]["ipv6_endpoints"]["sources"])
        self.assertIn("risk_score", res)
        self.assertEqual(res["mode_detection"]["detected_mode"], "tunnel")


if __name__ == "__main__":
    unittest.main()
