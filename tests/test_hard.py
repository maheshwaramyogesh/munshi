"""
Consistency checks for the HARD dataset (data integrity, not detector quality).
We deliberately do NOT assert that the detectors catch or miss anything here:
the hard data exists to measure honestly, not to pass tests.

Run:  python -m unittest -v     (after: python generate_logs.py --hard)
"""
import json
import unittest
from pathlib import Path

from munshi.detectors import detect
from munshi.evaluate import score
from munshi.parsing import parse_file

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / "logs" / "auth_hard.log"
TRUTH = ROOT / "logs" / "ground_truth_hard.json"
BENIGN = ROOT / "logs" / "benign_hard.json"


@unittest.skipUnless(LOG.exists() and TRUTH.exists() and BENIGN.exists(),
                     "run 'python generate_logs.py --hard' first")
class TestHardData(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_file(str(LOG))
        self.truth = json.loads(TRUTH.read_text())
        self.benign = json.loads(BENIGN.read_text())

    def test_every_line_is_understood(self):
        self.assertEqual(self.parsed.skipped, [])

    def test_attacker_lines_match_answer_key(self):
        planted = sum(a["num_log_lines"] for a in self.truth)
        found = sum(1 for e in self.parsed.events if e.ip.startswith("203.0.113."))
        self.assertEqual(found, planted)

    def test_successful_attacker_logins_match_answer_key(self):
        compromises = sum(1 for a in self.truth if a["type"] == "brute_force_success")
        wins = sum(1 for e in self.parsed.events
                   if e.ip.startswith("203.0.113.") and e.success)
        self.assertEqual(wins, compromises)

    def test_innocent_lines_match_benign_file(self):
        innocent_ips = {ip for c in self.benign for ip in c["ips"]}
        expected = sum(c["num_log_lines"] for c in self.benign)
        # innocent cases use IPs that also carry normal traffic, so count by case window
        self.assertGreaterEqual(
            sum(1 for e in self.parsed.events if e.ip in innocent_ips), expected)

    def test_scorer_accounts_for_every_finding(self):
        findings = detect(self.parsed.events)
        r = score(findings, self.truth, self.benign)
        self.assertEqual(sum(r["false_alarm_causes"].values()), len(r["false_alarms"]))
        self.assertLessEqual(r["detected"], r["planted"])


if __name__ == "__main__":
    unittest.main()
