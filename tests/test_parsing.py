"""
Tests for the parser. Run from the project root with:
    python -m unittest -v
"""
import json
import unittest
from pathlib import Path

from munshi.parsing import parse_file, parse_line, parse_lines

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / "logs" / "auth.log"
TRUTH = ROOT / "logs" / "ground_truth.json"


class TestParseLine(unittest.TestCase):
    def test_failed_valid_user(self):
        e = parse_line("Oct  1 09:05:04 server01 sshd[3847]: Failed password for user04 "
                       "from 198.51.100.4 port 53919 ssh2", 7)
        self.assertEqual((e.user, e.ip, e.port), ("user04", "198.51.100.4", 53919))
        self.assertFalse(e.success)
        self.assertFalse(e.invalid_user)
        self.assertEqual(e.line_no, 7)

    def test_failed_invalid_user(self):
        e = parse_line("Oct 12 05:31:49 server01 sshd[51512]: Failed password for invalid "
                       "user svc12 from 203.0.113.32 port 45666 ssh2", 1)
        self.assertEqual(e.user, "svc12")
        self.assertTrue(e.invalid_user)
        self.assertFalse(e.success)

    def test_accepted(self):
        e = parse_line("Oct  2 22:51:30 server01 sshd[24690]: Accepted password for user09 "
                       "from 203.0.113.38 port 53039 ssh2", 1)
        self.assertTrue(e.success)
        self.assertEqual(e.user, "user09")

    def test_single_digit_day_has_double_space(self):
        e = parse_line("Oct  1 00:00:01 server01 sshd[1]: Failed password for a from 1.2.3.4 "
                       "port 22 ssh2", 1)
        self.assertEqual((e.time.month, e.time.day, e.time.hour), (10, 1, 0))

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_line("this is not a log line", 1))

    def test_impossible_date_returns_none(self):
        self.assertIsNone(parse_line("Feb 30 10:00:00 server01 sshd[1]: Failed password "
                                     "for a from 1.2.3.4 port 22 ssh2", 1))


class TestParseLines(unittest.TestCase):
    def test_bad_lines_are_reported_not_dropped(self):
        good = ("Oct  1 09:00:00 server01 sshd[1]: Accepted password for a from "
                "1.2.3.4 port 22 ssh2")
        result = parse_lines([good, "garbage", "", good])
        self.assertEqual(len(result.events), 2)
        self.assertEqual(result.skipped, [(2, "garbage")])   # blank line 3 is ignored
        self.assertEqual(result.events[1].line_no, 4)        # numbering stays correct


@unittest.skipUnless(LOG.exists() and TRUTH.exists(),
                     "run 'python generate_logs.py' first")
class TestAgainstGroundTruth(unittest.TestCase):
    """The strongest check: do parsed results match what we planted?"""

    def setUp(self):
        self.result = parse_file(str(LOG))
        self.truth = json.loads(TRUTH.read_text())

    def test_every_line_is_understood(self):
        self.assertEqual(self.result.skipped, [])

    def test_attacker_event_count_matches_planted_count(self):
        planted = sum(a["num_log_lines"] for a in self.truth)
        found = sum(1 for e in self.result.events if e.ip.startswith("203.0.113."))
        self.assertEqual(found, planted)

    def test_successful_attacker_logins_match_planted_compromises(self):
        compromises = sum(1 for a in self.truth if a["type"] == "brute_force_success")
        wins = sum(1 for e in self.result.events
                   if e.ip.startswith("203.0.113.") and e.success)
        self.assertEqual(wins, compromises)


if __name__ == "__main__":
    unittest.main()
