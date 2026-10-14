"""Small fixed stress regression covering the repaired edge cases."""
import unittest
from datetime import datetime, timedelta

from munshi.detectors import Config, detect
from munshi.parsing import parse_lines


def log_line(when, text):
    return (
        f"{when.strftime('%b ')}{when.day:>2}"
        f"{when.strftime(' %H:%M:%S')} server01 sshd[1]: {text}"
    )


def failed(when, user, ip):
    return log_line(
        when,
        f"Failed password for invalid user {user} from {ip} port 2222 ssh2",
    )


def accepted(when, user, ip):
    return log_line(
        when,
        f"Accepted password for {user} from {ip} port 2222 ssh2",
    )


class TestStressRegression(unittest.TestCase):
    def test_fixed_stress_cases_keep_expected_outcomes(self):
        lines = []

        spray_start = datetime(2026, 10, 4, 2, 40, 0)
        for user_index in range(40):
            for attempt in range(3):
                lines.append(
                    failed(
                        spray_start + timedelta(seconds=len(lines) * 4),
                        f"user{user_index}",
                        "203.0.113.52",
                    )
                )

        campaign_start = datetime(2026, 10, 6, 15, 0, 0)
        attack_ips = [
            f"192.0.2.{150 + source_index}"
            for source_index in range(13)
        ]
        benign_ips = [
            f"198.51.100.{80 + source_index}"
            for source_index in range(3)
        ]

        for source_index, ip in enumerate(attack_ips):
            for attempt in range(4):
                lines.append(
                    failed(
                        campaign_start
                        + timedelta(seconds=source_index * 40 + attempt * 8),
                        f"guess{source_index * 4 + attempt}",
                        ip,
                    )
                )

        for source_index, ip in enumerate(benign_ips):
            user = f"staff{source_index}"
            start = campaign_start + timedelta(seconds=60 + source_index * 45)

            for attempt in range(3):
                lines.append(
                    failed(
                        start + timedelta(seconds=attempt * 8),
                        user,
                        ip,
                    )
                )

            lines.append(accepted(start + timedelta(seconds=30), user, ip))

        parsed = parse_lines(line + "\n" for line in sorted(lines))
        findings = detect(parsed.events, Config())

        self.assertEqual(len(findings), 2)

        single_ip_sprays = [
            finding
            for finding in findings
            if finding.ip == "203.0.113.52"
        ]
        self.assertEqual(len(single_ip_sprays), 1)
        self.assertEqual(single_ip_sprays[0].kind, "password_spray")
        self.assertEqual(single_ip_sprays[0].failures, 120)
        self.assertEqual(len(single_ip_sprays[0].users), 40)

        distributed = [
            finding
            for finding in findings
            if len(finding.source_ips) > 1
        ]
        self.assertEqual(len(distributed), 1)
        self.assertEqual(distributed[0].kind, "password_spray")
        self.assertEqual(distributed[0].source_ips, attack_ips)
        self.assertEqual(distributed[0].failures, 52)
        self.assertFalse(set(distributed[0].source_ips) & set(benign_ips))


if __name__ == "__main__":
    unittest.main()
