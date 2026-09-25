"""Unit tests for PDF Export Engine."""
import io
import json
import os
import unittest

from ipsecguard.pdf_export import (
    generate_security_report_pdf,
    generate_validation_report_pdf,
    generate_benchmark_report_pdf,
)


class TestPDFExport(unittest.TestCase):

    def setUp(self):
        # Load sample data
        with open("outputs/analysis.json", encoding="utf-8") as f:
            self.analysis_data = json.load(f)
        with open("outputs/attack_impact_validation.json", encoding="utf-8") as f:
            self.validation_data = json.load(f)
        with open("outputs/evaluation_benchmark.json", encoding="utf-8") as f:
            self.benchmark_data = json.load(f)

    def test_generate_security_report_pdf_bytes(self):
        """Test generating PDF security report in-memory buffer."""
        sess_data = self.analysis_data["sessions"]["weak"]
        pdf_bytes = generate_security_report_pdf(sess_data)

        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 2000)

    def test_generate_validation_report_pdf_bytes(self):
        """Test generating PDF attack validation dossier."""
        pdf_bytes = generate_validation_report_pdf(self.validation_data)

        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 2000)

    def test_generate_benchmark_report_pdf_bytes(self):
        """Test generating PDF benchmark report."""
        pdf_bytes = generate_benchmark_report_pdf(self.benchmark_data)

        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 2000)

    def test_generate_pdf_to_file(self):
        """Test writing PDF directly to disk target."""
        tmp_target = "outputs/temp_test_report.pdf"
        try:
            sess_data = self.analysis_data["sessions"]["strong"]
            generate_security_report_pdf(sess_data, output_target=tmp_target)
            self.assertTrue(os.path.exists(tmp_target))
            self.assertGreater(os.path.getsize(tmp_target), 2000)
        finally:
            if os.path.exists(tmp_target):
                os.unlink(tmp_target)


if __name__ == "__main__":
    unittest.main()
