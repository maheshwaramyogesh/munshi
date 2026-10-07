"""
Tests for the detectors. Run from the project root:  python -m unittest -v
"""
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from munshi.detectors import detect
from munshi.evaluate import score
from munshi.parsing import Event, parse_file

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / "logs" / "auth.log"
TRUTH = ROOT / "logs" / "ground_truth.json"
T0 = datetime(2026, 10, 1, 12, 0, 0)


def ev(n, seconds, user, ip, success=False):
    """Build a fake Event quickly. n = line number, seconds = offset from T0."""
    return Event(line_no=n, time=T0 + timedelta(seconds=seconds), host="h", user=user,
                 ip=ip, port=1, success=success, invalid_user=False, raw="")


class TestRules(unittest.TestCase):
    def test_a_few_typos_are_not_flagged(self):
        events = [ev(1, 0, "bob", "1.1.1.1"), ev(2, 5, "bob", "1.1.1.1"),
                  ev(3, 12, "bob", "1.1.1.1", success=True)]
        self.assertEqual(detect(events), [])

    def test_brute_force_detected(self):
        events = [ev(i, i * 4, "root" if i % 2 else "admin", "9.9.9.9") for i in range(1, 31)]
        found = detect(events)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].label, "brute_force")
        self.assertFalse(found[0].compromised)

    def test_brute_force_then_success_is_compromise(self):
        events = [ev(i, i * 4, "carol", "9.9.9.9") for i in range(1, 31)]
        events.append(ev(31, 130, "carol", "9.9.9.9", success=True))
        f = detect(events)[0]
        self.assertEqual(f.label, "brute_force_success")
        self.assertEqual(f.compromised_user, "carol")
        self.assertIn(31, f.evidence)           # the winning login is cited as evidence

    def test_success_from_a_different_ip_is_not_compromise(self):
        events = [ev(i, i * 4, "carol", "9.9.9.9") for i in range(1, 31)]
        events.append(ev(31, 130, "carol", "1.1.1.1", success=True))
        self.assertFalse(detect(events)[0].compromised)

    def test_password_spray_detected(self):
        events = [ev(i, i * 30, f"svc{i}", "8.8.8.8") for i in range(1, 21)]
        self.assertEqual(detect(events)[0].label, "password_spray")

    def test_long_pause_splits_into_two_episodes(self):
        a = [ev(i, i * 3, "root", "7.7.7.7") for i in range(1, 16)]
        b = [ev(100 + i, 7200 + i * 3, "root", "7.7.7.7") for i in range(1, 16)]
        self.assertEqual(len(detect(a + b)), 2)

    def test_evidence_lists_the_failure_lines(self):
        events = [ev(i, i * 4, "root", "9.9.9.9") for i in range(1, 13)]
        self.assertEqual(detect(events)[0].evidence, list(range(1, 13)))


@unittest.skipUnless(LOG.exists() and TRUTH.exists(), "run 'python generate_logs.py' first")
class TestAgainstGroundTruth(unittest.TestCase):
    def setUp(self):
        events = parse_file(str(LOG)).events
        self.result = score(detect(events), json.loads(TRUTH.read_text()))

    def test_all_planted_attacks_found(self):
        self.assertEqual(self.result["detected"], self.result["planted"])

    def test_all_types_correct(self):
        self.assertEqual(self.result["correct_type"], self.result["planted"])

    def test_no_false_alarms(self):
        self.assertEqual(self.result["false_alarms"], [])


if __name__ == "__main__":
    unittest.main()
