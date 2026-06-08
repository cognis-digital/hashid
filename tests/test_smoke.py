"""Smoke tests for HASHID — no network, stdlib only."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hashid import TOOL_NAME, TOOL_VERSION, identify, estimate_crack, analyze
from hashid.cli import main


class TestIdentify(unittest.TestCase):
    def test_md5(self):
        c = identify("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual(c[0].name, "MD5")
        self.assertEqual(c[0].hashcat_mode, 0)
        self.assertEqual(c[0].category, "raw")

    def test_sha1(self):
        c = identify("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(c[0].name, "SHA-1")

    def test_sha256(self):
        c = identify("a" * 64)
        names = [x.name for x in c]
        self.assertIn("SHA-256", names)

    def test_bcrypt(self):
        h = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
        c = identify(h)
        self.assertEqual(c[0].name, "bcrypt")
        self.assertEqual(c[0].category, "kdf")

    def test_sha512crypt(self):
        c = identify("$6$saltsalt$0123456789abcdef")
        self.assertEqual(c[0].name, "sha512crypt")

    def test_unknown(self):
        c = identify("hello world not a hash!!!")
        self.assertEqual(c[0].name, "unknown")

    def test_empty(self):
        self.assertEqual(identify("   "), [])


class TestEstimate(unittest.TestCase):
    def test_fast_vs_slow(self):
        md5 = estimate_crack(identify("5f4dcc3b5aa765d61d8327deb882cf99")[0])
        bcr = estimate_crack(identify(
            "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi."
            "Ss7KIUgO2t0jWMUW")[0])
        # bcrypt (slow KDF) must be far harder than MD5 for same keyspace.
        self.assertGreater(bcr.seconds_avg, md5.seconds_avg)
        self.assertGreater(md5.ref_guesses_per_sec, bcr.ref_guesses_per_sec)

    def test_keyspace_grows(self):
        cand = identify("a" * 64)[0]
        short = estimate_crack(cand, password_len=6)
        longp = estimate_crack(cand, password_len=10)
        self.assertGreater(longp.seconds_avg, short.seconds_avg)

    def test_feasibility_labels(self):
        cand = identify("5f4dcc3b5aa765d61d8327deb882cf99")[0]
        est = estimate_crack(cand, charset_size=95, password_len=6)
        self.assertIn(est.feasibility,
                      {"trivial", "weak", "moderate", "strong", "infeasible"})


class TestAnalyze(unittest.TestCase):
    def test_pipeline(self):
        a = analyze("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual(a["best_guess"]["name"], "MD5")
        self.assertIsNotNone(a["crack_estimate"])
        self.assertEqual(a["input_length"], 32)


class TestCLI(unittest.TestCase):
    def test_meta(self):
        self.assertEqual(TOOL_NAME, "hashid")
        self.assertTrue(TOOL_VERSION)

    def test_identify_exit_one_on_finding(self):
        rc = main(["identify", "5f4dcc3b5aa765d61d8327deb882cf99"])
        self.assertEqual(rc, 1)

    def test_unknown_exit_zero(self):
        rc = main(["identify", "definitely not a hash here"])
        self.assertEqual(rc, 0)

    def test_no_input_exit_two(self):
        rc = main(["identify"])
        self.assertEqual(rc, 2)

    def test_json_format(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "estimate",
                       "5f4dcc3b5aa765d61d8327deb882cf99"])
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["tool"], "hashid")
        self.assertEqual(data["command"], "estimate")
        self.assertEqual(data["results"][0]["analysis"]["best_guess"]["name"],
                         "MD5")
        self.assertIsNotNone(
            data["results"][0]["analysis"]["crack_estimate"])


if __name__ == "__main__":
    unittest.main()
