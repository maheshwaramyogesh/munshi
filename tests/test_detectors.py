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
        self.assertEqual(f.episode_success_users, ["carol"])
        self.assertEqual(f.episode_success_lines, [31])
        self.assertIn(31, f.evidence)           # the successful login is cited as evidence

    def test_multiple_successes_during_episode_are_preserved_as_context(self):
        events = [ev(i, i * 4, "user1", "9.9.9.9") for i in range(1, 13)]
        events.extend([
            ev(20, 48, "user1", "9.9.9.9", success=True),
            ev(21, 60, "user2", "9.9.9.9", success=True),
            ev(22, 72, "user3", "9.9.9.9", success=True),
        ])
        f = detect(events)[0]
        self.assertFalse(f.compromised)
        self.assertIsNone(f.compromised_user)
        self.assertEqual(f.label, "brute_force")
        self.assertEqual(f.episode_success_users, ["user1", "user2", "user3"])
        self.assertEqual(f.episode_success_lines, [20, 21, 22])

    def test_success_from_a_different_ip_is_not_compromise(self):
        events = [ev(i, i * 4, "carol", "9.9.9.9") for i in range(1, 31)]
        events.append(ev(31, 130, "carol", "1.1.1.1", success=True))
        self.assertFalse(detect(events)[0].compromised)

    def test_password_spray_detected(self):
        events = [ev(i, i * 30, f"svc{i}", "8.8.8.8") for i in range(1, 21)]
        self.assertEqual(detect(events)[0].label, "password_spray")

    def test_several_tries_across_many_usernames_is_password_spray(self):
        events = []
        line_no = 1

        for user_index in range(40):
            for attempt in range(3):
                events.append(
                    ev(
                        line_no,
                        line_no * 4,
                        f"user{user_index}",
                        "8.8.8.8",
                    )
                )
                line_no += 1

        finding = detect(events)[0]

        self.assertEqual(finding.kind, "password_spray")
        self.assertEqual(finding.failures, 120)
        self.assertEqual(len(finding.users), 40)

    def test_many_tries_against_one_username_is_brute_force(self):
        events = [
            ev(i, i * 4, "root", "9.9.9.9")
            for i in range(1, 121)
        ]

        finding = detect(events)[0]

        self.assertEqual(finding.kind, "brute_force")
        self.assertEqual(finding.failures, 120)

    def test_ten_tries_each_against_twelve_usernames_is_brute_force(self):
        events = []
        line_no = 1

        for user_index in range(12):
            for attempt in range(10):
                events.append(
                    ev(
                        line_no,
                        line_no * 4,
                        f"user{user_index}",
                        "9.9.9.9",
                    )
                )
                line_no += 1

        finding = detect(events)[0]

        self.assertEqual(finding.kind, "brute_force")
        self.assertEqual(finding.failures, 120)

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
