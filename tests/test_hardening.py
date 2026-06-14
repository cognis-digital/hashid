"""Hardening tests: error paths, edge cases, and input validation."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hashid.core import identify, estimate_crack, analyze, TOOL_NAME, TOOL_VERSION
from hashid.cli import main


class TestIdentifyTypeGuard(unittest.TestCase):
    """identify() must raise TypeError for non-string input."""

    def test_none_raises_type_error(self):
        with self.assertRaises(TypeError) as ctx:
            identify(None)
        self.assertIn("identify() expects a str", str(ctx.exception))

    def test_int_raises_type_error(self):
        with self.assertRaises(TypeError):
            identify(12345)

    def test_bytes_raises_type_error(self):
        with self.assertRaises(TypeError):
            identify(b"deadbeef")


class TestEstimateCrackValidation(unittest.TestCase):
    """estimate_crack() must reject bad charset/length parameters."""

    def _md5_candidate(self):
        return identify("5f4dcc3b5aa765d61d8327deb882cf99")[0]

    def test_charset_zero_raises(self):
        with self.assertRaises(ValueError) as ctx:
            estimate_crack(self._md5_candidate(), charset_size=0)
        self.assertIn("charset_size", str(ctx.exception))

    def test_charset_negative_raises(self):
        with self.assertRaises(ValueError):
            estimate_crack(self._md5_candidate(), charset_size=-10)

    def test_charset_one_raises(self):
        with self.assertRaises(ValueError):
            estimate_crack(self._md5_candidate(), charset_size=1)

    def test_password_len_zero_raises(self):
        with self.assertRaises(ValueError) as ctx:
            estimate_crack(self._md5_candidate(), password_len=0)
        self.assertIn("password_len", str(ctx.exception))

    def test_password_len_negative_raises(self):
        with self.assertRaises(ValueError):
            estimate_crack(self._md5_candidate(), password_len=-3)

    def test_valid_params_still_work(self):
        est = estimate_crack(self._md5_candidate(), charset_size=2, password_len=1)
        self.assertGreater(est.keyspace, 0)


class TestAnalyzeEdgeCases(unittest.TestCase):
    """analyze() must handle edge cases gracefully."""

    def test_blank_input_returns_empty_result(self):
        result = analyze("   ")
        self.assertEqual(result["input_length"], 0)
        self.assertEqual(result["candidates"], [])
        self.assertIsNone(result["best_guess"])
        self.assertIsNone(result["crack_estimate"])

    def test_none_raises_type_error(self):
        with self.assertRaises(TypeError):
            analyze(None)

    def test_bad_charset_propagates_value_error(self):
        with self.assertRaises(ValueError):
            analyze("5f4dcc3b5aa765d61d8327deb882cf99", charset_size=0)


class TestCLIHardening(unittest.TestCase):
    """CLI must return exit 2 with a clear message for bad input."""

    def test_missing_file_exits_two(self):
        rc = main(["identify", "-f", "/nonexistent/path/xyz.txt"])
        self.assertEqual(rc, 2)

    def test_all_comments_file_exits_two(self):
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False) as f:
            f.write("# comment\n\n  \n")
            fname = f.name
        try:
            rc = main(["identify", "-f", fname])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(fname)

    def test_charset_zero_exits_two(self):
        rc = main(["estimate", "--charset", "0",
                   "5f4dcc3b5aa765d61d8327deb882cf99"])
        self.assertEqual(rc, 2)

    def test_length_zero_exits_two(self):
        rc = main(["estimate", "--length", "0",
                   "5f4dcc3b5aa765d61d8327deb882cf99"])
        self.assertEqual(rc, 2)

    def test_charset_one_exits_two(self):
        rc = main(["estimate", "--charset", "1",
                   "5f4dcc3b5aa765d61d8327deb882cf99"])
        self.assertEqual(rc, 2)


class TestToolConstants(unittest.TestCase):
    """TOOL_NAME and TOOL_VERSION must be defined in core."""

    def test_tool_name_defined_in_core(self):
        self.assertEqual(TOOL_NAME, "hashid")

    def test_tool_version_non_empty(self):
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()
