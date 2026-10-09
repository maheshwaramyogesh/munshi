"""Focused tests for Munshi's deterministic, evidence-linked narrative module."""
from dataclasses import replace
from datetime import datetime, timedelta
import unittest

from munshi.detectors import Config, detect
from munshi.narrative import build_narrative, verify_claim
from munshi.parsing import Event


class TestNarrative(unittest.TestCase):
    def make_events(self, successes=()):
        base = datetime(2026, 10, 1, 9, 0, 0)
        ip = "203.0.113.7"
        events = []
        for i in range(12):
            when = base + timedelta(seconds=i * 10)
            events.append(Event(
                line_no=i + 1,
                time=when,
                host="server01",
                user="root",
                ip=ip,
                port=22,
                success=False,
                invalid_user=False,
                raw=(f"{when.strftime('%b %d %H:%M:%S')} server01 sshd[1]: "
                     f"Failed password for root from {ip} port 22 ssh2"),
            ))
        next_line = len(events) + 1
        for offset_seconds, user in successes:
            when = base + timedelta(seconds=offset_seconds)
            events.append(Event(
                line_no=next_line,
                time=when,
                host="server01",
                user=user,
                ip=ip,
                port=22,
                success=True,
                invalid_user=False,
                raw=(f"{when.strftime('%b %d %H:%M:%S')} server01 sshd[2]: "
                     f"Accepted password for {user} from {ip} port 22 ssh2"),
            ))
            next_line += 1
        return sorted(events, key=lambda event: (event.time, event.line_no))

    def test_builds_verified_claims_from_real_finding_fields(self):
        events = self.make_events(successes=[(180, "root")])
        finding = detect(events, Config())[0]
        narrative = build_narrative(finding, events)
        self.assertEqual(narrative["status"], "verified")
        self.assertEqual(narrative["verification"]["verified_claims"], 5)
        claims = {claim["kind"]: claim for claim in narrative["claims"]}
        self.assertEqual(claims["failure_count"]["value"], 12)
        self.assertTrue(claims["failure_count"]["verified"])
        self.assertIn("does not prove the same actor", claims["authentication_context"]["text"])

    def test_tampered_claim_text_is_rejected(self):
        events = self.make_events()
        finding = detect(events, Config())[0]
        narrative = build_narrative(finding, events)
        claim = next(c for c in narrative["claims"] if c["kind"] == "source_ip")
        claim["text"] = "The attacker definitely broke into the system."
        result = verify_claim(claim, finding, events)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "claim_does_not_match_source_facts")

    def test_multiple_successful_users_are_reported_as_ambiguous(self):
        events = self.make_events(successes=[(180, "alice"), (190, "bob")])
        finding = detect(events, Config())[0]
        narrative = build_narrative(finding, events)
        claims = {claim["kind"]: claim for claim in narrative["claims"]}
        auth_claim = claims["authentication_context"]
        self.assertFalse(finding.compromised)
        self.assertTrue(auth_claim["value"]["ambiguous"])
        self.assertIn("attribution remains ambiguous", auth_claim["text"])
        self.assertNotIn("definitely compromised", auth_claim["text"])

    def test_inconsistent_finding_evidence_rejects_narrative(self):
        events = self.make_events()
        finding = detect(events, Config())[0]
        altered = replace(finding, evidence=finding.evidence[:-1])
        narrative = build_narrative(altered, events)
        self.assertEqual(narrative["status"], "unavailable")
        self.assertEqual(narrative["claims"], [])

    def test_rejects_forged_attack_classification(self):
        events = self.make_events()
        finding = detect(events, Config())[0]

        # These events repeatedly target only one username.
        # Relabeling them as password spraying must be rejected.
        forged = replace(finding, kind="password_spray")
        narrative = build_narrative(forged, events)

        self.assertEqual(narrative["status"], "unavailable")
        self.assertEqual(narrative["claims"], [])
        self.assertEqual(
            narrative["verification"]["reason"],
            "finding_kind_does_not_match_failure_pattern",
        )

    def test_summary_contains_verified_evidence_references(self):
        events = self.make_events(successes=[(180, "root")])
        finding = detect(events, Config())[0]
        narrative = build_narrative(finding, events)

        summary = narrative["summary"]

        # The summary must be structured, verified, and traceable.
        self.assertIsInstance(summary, dict)
        self.assertTrue(summary["verified"])
        self.assertEqual(
            summary["supporting_claims"],
            ["classification", "source_ip", "failure_count"],
        )

        # Every referenced line must exist and support the summary.
        events_by_line = {event.line_no: event for event in events}
        evidence_lines = summary["evidence_lines"]

        self.assertTrue(evidence_lines)
        self.assertTrue(
            set(evidence_lines).issubset(events_by_line.keys())
        )
        self.assertTrue(
            all(
                not events_by_line[line].success
                and events_by_line[line].ip == finding.ip
                for line in evidence_lines
            )
        )

        self.assertEqual(
            summary["evidence_line_count"],
            finding.failures,
        )
        self.assertEqual(
            summary["evidence_truncated"],
            finding.failures > 25,
        )

    def test_no_success_is_a_scoped_absence_claim(self):
        events = self.make_events()
        finding = detect(events, Config())[0]
        narrative = build_narrative(finding, events)
        auth_claim = next(c for c in narrative["claims"] if c["kind"] == "authentication_context")
        self.assertFalse(auth_claim["value"]["observed"])
        self.assertEqual(auth_claim["evidence_lines"], [])
        self.assertEqual(auth_claim["verification_method"], "complete_parsed_event_window_check")


if __name__ == "__main__":
    unittest.main()
