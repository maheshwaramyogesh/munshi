
import unittest
from datetime import datetime, timedelta

from munshi.detectors import detect
from munshi.parsing import Event


T0 = datetime(2026, 10, 1, 12, 0, 0)
ATTACK_IP = "203.0.113.77"


def make_event(line_no, seconds, user="victim", success=False, ip=ATTACK_IP):
    return Event(
        line_no=line_no,
        time=T0 + timedelta(seconds=seconds),
        host="test-host",
        user=user,
        ip=ip,
        port=22,
        success=success,
        invalid_user=False,
        raw="",
    )


def make_threshold_dodger(with_success=False):
    """Six bursts of seven failures, separated by 25 minutes."""
    events = []
    line_no = 1

    for burst in range(6):
        burst_start = burst * 25 * 60

        for attempt in range(7):
            events.append(
                make_event(
                    line_no,
                    burst_start + attempt * 10,
                )
            )
            line_no += 1

    if with_success:
        last_failure = max(e.time for e in events)
        success_seconds = int((last_failure - T0).total_seconds()) + 10
        events.append(make_event(line_no, success_seconds, success=True))

    return events

def make_distributed_spray():
    """Twenty IPs, three failures per IP, across a short time window."""
    events = []
    line_no = 1
    usernames = [f"guess{i}" for i in range(54)]

    for source_index in range(20):
        ip = f"203.0.113.{50 + source_index}"

        for attempt in range(3):
            events.append(
                make_event(
                    line_no,
                    seconds=source_index * 90 + attempt * 10,
                    user=usernames[(source_index * 3 + attempt) % len(usernames)],
                    ip=ip,
                )
            )
            line_no += 1

    return events


def make_sparse_distributed_noise():
    """Many source IPs, but only two failures per IP before success."""
    events = []
    line_no = 1

    for source_index in range(20):
        ip = f"198.51.100.{source_index + 1}"
        start = source_index * 90
        user = f"staff{source_index}"

        events.append(make_event(line_no, start, user=user, ip=ip))
        line_no += 1
        events.append(make_event(line_no, start + 10, user=user, ip=ip))
        line_no += 1
        events.append(
            make_event(line_no, start + 20, user=user, success=True, ip=ip)
        )
        line_no += 1

    return events


def make_distributed_repeated_user():
    """Many source IPs retrying the same username is not a broad spray."""
    events = []
    line_no = 1

    for source_index in range(20):
        ip = f"198.51.100.{source_index + 1}"

        for attempt in range(3):
            events.append(
                make_event(
                    line_no,
                    seconds=source_index * 90 + attempt * 10,
                    user="backup",
                    ip=ip,
                )
            )
            line_no += 1

    return events


class TestThresholdDodgerDetection(unittest.TestCase):
    def test_repeated_subthreshold_bursts_are_correlated(self):
        findings = detect(make_threshold_dodger())

        self.assertEqual(len(findings), 1)
        finding = findings[0]

        self.assertEqual(finding.ip, ATTACK_IP)
        self.assertEqual(finding.label, "brute_force")
        self.assertEqual(finding.failures, 42)
        self.assertEqual(finding.evidence, list(range(1, 43)))
        self.assertFalse(finding.compromised)

    def test_success_after_correlated_bursts_is_preserved(self):
        findings = detect(make_threshold_dodger(with_success=True))

        self.assertEqual(len(findings), 1)
        finding = findings[0]

        self.assertEqual(finding.label, "brute_force_success")
        self.assertTrue(finding.compromised)
        self.assertEqual(finding.compromised_user, "victim")
        self.assertIn(43, finding.evidence)
        self.assertEqual(finding.episode_success_lines, [43])

    def test_low_and_slow_failures_are_correlated(self):
        events = [
            make_event(i, (i - 1) * 30 * 60, user="root")
            for i in range(1, 41)
        ]

        findings = detect(events)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.label, "brute_force")
        self.assertEqual(finding.failures, 40)
        self.assertEqual(finding.evidence, list(range(1, 41)))
        self.assertFalse(finding.compromised)

    def test_minute_by_minute_service_loop_is_not_duplicated(self):
        events = [
            make_event(i, (i - 1) * 60, user="backup")
            for i in range(1, 181)
        ]

        findings = detect(events)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].failures, 180)

class TestDistributedDetection(unittest.TestCase):
    def test_distributed_spray_is_detected_as_one_campaign(self):
        findings = detect(make_distributed_spray())

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.kind, "password_spray")
        self.assertEqual(len(finding.source_ips), 20)
        self.assertEqual(finding.failures, 60)
        self.assertEqual(len(finding.users), 54)
        self.assertEqual(finding.evidence, list(range(1, 61)))

    def test_sparse_failures_across_ips_do_not_trigger_campaign(self):
        findings = detect(make_sparse_distributed_noise())

        self.assertEqual(findings, [])

    def test_repeated_username_across_ips_is_not_a_spray(self):
        findings = detect(make_distributed_repeated_user())

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
