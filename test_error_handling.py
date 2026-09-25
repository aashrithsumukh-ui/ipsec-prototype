"""Unit tests for Feature 4: Comprehensive Error Handling & Input Validation."""
import os
import struct
import tempfile
import unittest

from scapy.all import IP, UDP, Raw, wrpcap
from scapy.layers.ipsec import ESP

from ipsecguard.errors import (
    ErrorCode,
    IPsecGuardError,
    PCAPValidationError,
    PCAPFileNotFoundError,
    EmptyPCAPError,
    CorruptedPCAPError,
    UnsupportedPCAPFormatError,
    InsufficientPacketsError,
    format_error_response,
)
from ipsecguard.pcap_validator import validate_pcap_file, check_pcap_magic_header
from ipsecguard.analyze import analyze_pcap, safe_analyze_pcap
from ipsecguard.classifier import TrafficClassifier
from ipsecguard.anomaly import AnomalyDetector
from ipsecguard.synth import generate


class TestErrorHandlingAndValidation(unittest.TestCase):

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

    def _create_temp_file(self, content: bytes, suffix: str = ".pcap") -> str:
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        f.write(content)
        f.flush()
        f.close()
        self.temp_files.append(f.name)
        return f.name

    def test_missing_file_validation(self):
        """Test that non-existent file paths raise PCAPFileNotFoundError."""
        bad_path = "non_existent_capture_12345.pcap"
        with self.assertRaises(PCAPFileNotFoundError) as ctx:
            validate_pcap_file(bad_path)
        self.assertEqual(ctx.exception.error_code, ErrorCode.PCAP_FILE_NOT_FOUND)
        self.assertEqual(ctx.exception.stage, "pcap_validation")

    def test_empty_file_validation(self):
        """Test that 0-byte files raise EmptyPCAPError."""
        empty_path = self._create_temp_file(b"")
        with self.assertRaises(EmptyPCAPError) as ctx:
            validate_pcap_file(empty_path)
        self.assertEqual(ctx.exception.error_code, ErrorCode.PCAP_EMPTY_FILE)

    def test_unsupported_format_validation(self):
        """Test that non-PCAP files (e.g. text or random binary) raise UnsupportedPCAPFormatError."""
        txt_path = self._create_temp_file(b"This is just a plain text file, not a PCAP!")
        with self.assertRaises(UnsupportedPCAPFormatError) as ctx:
            validate_pcap_file(txt_path)
        self.assertEqual(ctx.exception.error_code, ErrorCode.PCAP_UNSUPPORTED_FORMAT)

    def test_corrupted_pcap_header(self):
        """Test that truncated PCAP headers raise CorruptedPCAPError."""
        truncated_path = self._create_temp_file(b"\xa1\xb2\xc3\xd4\x00\x02")  # only 6 bytes
        with self.assertRaises(CorruptedPCAPError) as ctx:
            validate_pcap_file(truncated_path)
        self.assertEqual(ctx.exception.error_code, ErrorCode.PCAP_CORRUPTED)

    def test_corrupted_packet_data(self):
        """Test that valid PCAP header followed by corrupted garbage raises CorruptedPCAPError."""
        # 24-byte PCAP header + garbage packet records
        pcap_hdr = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        garbage_pcap = self._create_temp_file(pcap_hdr + b"\xff\x00\xaa\xbb" * 10)
        with self.assertRaises(CorruptedPCAPError) as ctx:
            validate_pcap_file(garbage_pcap)
        self.assertEqual(ctx.exception.error_code, ErrorCode.PCAP_CORRUPTED)

    def test_valid_pcap_validation_census(self):
        """Test that valid PCAPs pass validation and generate a correct protocol census."""
        p1 = IP(src="192.168.1.10", dst="192.168.1.20", proto=50) / ESP(spi=0x1234, seq=1) / Raw(b"DATA1")
        p2 = IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=500, dport=500) / Raw(b"\x00"*28)
        valid_path = self._create_temp_file(b"")
        wrpcap(valid_path, [p1, p2])

        census = validate_pcap_file(valid_path, min_packets=1)
        self.assertTrue(census["is_valid"])
        self.assertEqual(census["total_packets"], 2)
        self.assertEqual(census["ip_packets"], 2)
        self.assertEqual(census["esp_packets"], 1)
        self.assertEqual(census["ike_packets"], 1)
        self.assertTrue(census["has_ipsec_traffic"])

    def test_safe_analyze_pcap_on_corrupted_file(self):
        """Test that safe_analyze_pcap returns a structured error dictionary instead of crashing."""
        corrupted_path = self._create_temp_file(b"CORRUPTED_NOT_PCAP_BYTES")
        res = safe_analyze_pcap(corrupted_path, self.clf, self.anom)

        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error_code"], ErrorCode.PCAP_UNSUPPORTED_FORMAT)
        self.assertEqual(res["stage"], "pcap_validation")
        self.assertFalse(res["retryable"])
        self.assertIn("timestamp", res)
        self.assertIsInstance(res["message"], str)

    def test_safe_analyze_pcap_on_missing_file(self):
        """Test that safe_analyze_pcap returns structured error for missing file."""
        res = safe_analyze_pcap("does_not_exist.pcap", self.clf, self.anom)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error_code"], ErrorCode.PCAP_FILE_NOT_FOUND)
        self.assertEqual(res["stage"], "pcap_validation")

    def test_safe_analyze_pcap_on_valid_capture(self):
        """Test that safe_analyze_pcap succeeds on valid captures without error."""
        pkts = [
            IP(src="192.168.1.10", dst="192.168.1.20", proto=50) / ESP(spi=0x1234, seq=i) / Raw(b"X"*100)
            for i in range(10)
        ]
        valid_path = self._create_temp_file(b"")
        wrpcap(valid_path, pkts)

        res = safe_analyze_pcap(valid_path, self.clf, self.anom)
        self.assertEqual(res["status"], "success")
        self.assertIn("data", res)
        self.assertEqual(res["data"]["census"]["esp_packets"], 10)

    def test_format_error_response_schema(self):
        """Test structured error response schema compliance."""
        err_dict = format_error_response(
            message="Test error message",
            error_code=ErrorCode.SCORING_FAILED,
            stage="scoring",
            retryable=True,
            details={"param": "invalid"}
        )
        self.assertEqual(err_dict["status"], "error")
        self.assertEqual(err_dict["error_code"], ErrorCode.SCORING_FAILED)
        self.assertEqual(err_dict["message"], "Test error message")
        self.assertEqual(err_dict["stage"], "scoring")
        self.assertTrue(err_dict["retryable"])
        self.assertEqual(err_dict["details"], {"param": "invalid"})
        self.assertIn("timestamp", err_dict)


if __name__ == "__main__":
    unittest.main()
