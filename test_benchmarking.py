"""Unit tests for Automated Security Evaluation & Benchmarking."""
import os
import unittest
from ipsecguard import SecurityBenchmarkEngine, run_security_evaluation
from ipsecguard.synth import generate

class TestSecurityBenchmarkEngine(unittest.TestCase):

    def setUp(self):
        # Small dataset for fast test execution
        self.df = generate(n_configs=20, sessions_per_config=2, seed=123)
        self.engine = SecurityBenchmarkEngine()

    def test_benchmark_execution_and_schema(self):
        """Test that benchmark runs cleanly and returns all required keys."""
        res = self.engine.run_benchmark(df=self.df)

        self.assertIn("benchmark_summary", res)
        self.assertIn("metrics", res)
        self.assertIn("failed_test_details", res)
        self.assertIn("sample_predictions", res)
        self.assertIn("limitations_and_unavailable_metrics", res)
        self.assertIn("markdown_report", res)

        summary = res["benchmark_summary"]
        self.assertGreater(summary["total_test_cases"], 0)
        self.assertEqual(summary["total_test_cases"], summary["passed_cases"] + summary["failed_cases"])
        self.assertGreaterEqual(summary["pass_rate_pct"], 90.0)

    def test_metrics_ranges_and_consistency(self):
        """Test that computed precision, recall, F1, and accuracy are within [0.0, 1.0]."""
        res = self.engine.run_benchmark(df=self.df)
        m = res["metrics"]

        # Weakness metrics
        w_m = m["weakness_detection"]
        self.assertTrue(0.0 <= w_m["precision"] <= 1.0)
        self.assertTrue(0.0 <= w_m["recall"] <= 1.0)
        self.assertTrue(0.0 <= w_m["f1_score"] <= 1.0)
        self.assertGreaterEqual(w_m["true_positives"], 0)

        # Downgrade metrics
        dg_m = m["downgrade_detection"]
        self.assertTrue(0.0 <= dg_m["accuracy"] <= 1.0)
        self.assertTrue(0.0 <= dg_m["precision"] <= 1.0)
        self.assertTrue(0.0 <= dg_m["recall"] <= 1.0)
        self.assertTrue(0.0 <= dg_m["false_positive_rate"] <= 1.0)
        self.assertTrue(0.0 <= dg_m["false_negative_rate"] <= 1.0)

        # PFS metrics
        pfs_m = m["pfs_verification"]
        self.assertTrue(0.0 <= pfs_m["accuracy"] <= 1.0)
        self.assertEqual(pfs_m["total_evaluated"], len(self.df))

        # Performance metrics
        perf = m["performance"]
        self.assertGreater(perf["total_benchmark_time_seconds"], 0)
        self.assertGreater(perf["average_analysis_latency_ms"], 0)

    def test_run_security_evaluation_file_output(self):
        """Test that run_security_evaluation writes outputs to disk."""
        out_json = "outputs/test_eval_benchmark.json"
        out_md = "outputs/test_eval_report.md"

        res = run_security_evaluation(df=self.df, out_json=out_json, out_md=out_md)
        self.assertTrue(os.path.exists(out_json))
        self.assertTrue(os.path.exists(out_md))

        # Check content in markdown
        with open(out_md, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("# Automated Security Evaluation & Benchmarking Report", content)
        self.assertIn("## 1. Executive Summary", content)
        self.assertIn("## 2. Security Weakness Detection Accuracy", content)
        self.assertIn("## 3. Attack Downgrade & PFS Verification Performance", content)
        self.assertIn("## 5. Limitations & Unsupported Metrics", content)

        # Clean up test output files
        if os.path.exists(out_json): os.remove(out_json)
        if os.path.exists(out_md): os.remove(out_md)

if __name__ == "__main__":
    unittest.main()
