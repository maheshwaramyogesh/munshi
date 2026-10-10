"""Deterministic, evidence-linked explanations for Munshi findings.

This module never infers a human attacker or causal compromise. It produces
small, typed claims from the parsed events and verifies each claim against the
finding and the complete parsed event set before returning it.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .detectors import Config, Finding
from .parsing import Event


_PATTERN_NAMES = {
    "brute_force": "brute-force pattern",
    "brute_force_success": "brute-force pattern with a subsequent successful authentication observed",
    "password_spray": "password-spray pattern",
}


def _ordered_events(events: Iterable[Event]) -> List[Event]:
    return sorted(events, key=lambda event: (event.time, event.line_no))


def _derive_facts(
    finding: Finding,
    events: Sequence[Event],
    config: Config,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Re-derive the finding's key facts and reject inconsistent provenance."""
    known_kinds = {"brute_force", "password_spray"}
    if finding.kind not in known_kinds:
        return None, "unknown_finding_kind"

    by_line: Dict[int, Event] = {}
    for event in events:
        if event.line_no in by_line:
            return None, "duplicate_source_line_number"
        by_line[event.line_no] = event

    evidence_lines = list(finding.evidence)
    if not evidence_lines or len(evidence_lines) != len(set(evidence_lines)):
        return None, "invalid_finding_evidence_references"
    if any(line not in by_line for line in evidence_lines):
        return None, "finding_references_missing_event"

    source_ips = sorted(
        set(getattr(finding, "source_ips", []) or [finding.ip])
    )

    if finding.ip not in source_ips:
        return None, "representative_source_ip_not_in_source_set"

    evidence_events = [by_line[line] for line in evidence_lines]

    if any(event.ip not in source_ips for event in evidence_events):
        return None, "evidence_source_ip_mismatch"

    is_distributed = len(source_ips) > 1

    failure_events = [event for event in evidence_events if not event.success]
    if len(failure_events) != finding.failures or not failure_events:
        return None, "failure_count_does_not_match_evidence"

    failure_events = _ordered_events(failure_events)
    failure_lines = [event.line_no for event in failure_events]
    failure_end = max(event.time for event in failure_events)
    failure_start = min(event.time for event in failure_events)
    if finding.start != failure_start or finding.start > failure_end:
        return None, "finding_time_range_does_not_match_failures"

    failed_users = sorted({event.user for event in failure_events})
    if failed_users != sorted(set(finding.users)):
        return None, "targeted_users_do_not_match_evidence"

            # Independently recalculate the attack type from failed events.
    looks_like_spray = (
        len(failed_users) >= config.spray_min_users
        and len(failed_users) / len(failure_events)
        >= config.spray_user_ratio
    )

    expected_kind = (
        "password_spray" if looks_like_spray else "brute_force"
    )

    if finding.kind != expected_kind:
        return None, "finding_kind_does_not_match_failure_pattern"

    # Distributed campaigns aggregate failures from multiple IPs. The
    # detector does not attribute successful logins to those campaigns.
    if is_distributed:
        contextual_lines = []
        contextual_users = []
        post_episode_successes = []

        ambiguous = None
        expected_compromised = False
        expected_compromised_user = None
        window_end = None

        if finding.episode_success_lines:
            return None, "distributed_finding_has_unexpected_success_context"

        if finding.episode_success_users:
            return None, "distributed_finding_has_unexpected_success_context"

        if finding.compromised or finding.compromised_user is not None:
            return None, "authentication_interpretation_mismatch"

        expected_evidence = failure_lines
        expected_end = failure_end

    else:
        # Recreate the detector's single-IP success window.
        window_end = failure_end + config.success_window

        same_ip_successes = _ordered_events(
            event for event in events
            if event.ip == finding.ip and event.success
        )

        contextual_successes = [
            event for event in same_ip_successes
            if finding.start <= event.time <= window_end
        ]

        contextual_lines = [
            event.line_no for event in contextual_successes
        ]
        contextual_users = sorted({
            event.user for event in contextual_successes
        })

        if contextual_lines != list(finding.episode_success_lines):
            return None, "authentication_context_lines_do_not_match_events"

        if contextual_users != sorted(set(finding.episode_success_users)):
            return None, "authentication_context_users_do_not_match_events"

        post_episode_successes = [
            event for event in same_ip_successes
            if failure_end <= event.time <= window_end
        ]

        expected_evidence = failure_lines + [
            event.line_no for event in post_episode_successes
        ]

        ambiguous = len(contextual_users) > 1
        expected_compromised = bool(post_episode_successes) and not ambiguous

        expected_compromised_user = (
            post_episode_successes[0].user
            if expected_compromised else None
        )

        if finding.compromised != expected_compromised:
            return None, "authentication_interpretation_mismatch"

        if finding.compromised_user != expected_compromised_user:
            return None, "authentication_user_mismatch"

        expected_end = (
            post_episode_successes[0].time
            if post_episode_successes else failure_end
        )

    if evidence_lines != expected_evidence:
        return None, "finding_evidence_does_not_match_detector_window"

    if finding.end != expected_end:
        return None, "finding_end_time_mismatch"


    expected_label = (
        "brute_force_success"
        if finding.kind == "brute_force" and finding.compromised
        else finding.kind
    )
    if finding.label != expected_label or expected_label not in _PATTERN_NAMES:
        return None, "finding_label_mismatch"

    return {
        "ip": finding.ip,
        "source_ips": source_ips,
        "is_distributed": is_distributed,
        "kind": finding.kind,
        "label": expected_label,
        "failure_count": len(failure_events),
        "failure_lines": failure_lines,
        "representative_failure_lines": [
            event.line_no
            for event in failure_events
            if event.ip == finding.ip
        ],
        "users": failed_users,
        "contextual_success_lines": contextual_lines,
        "contextual_success_users": contextual_users,
        "authentication_ambiguous": ambiguous,
        "compromised": expected_compromised,
        "compromised_user": expected_compromised_user,
        "window_start": finding.start,
        "window_end": window_end,
    }, None


def _limited_lines(lines: Sequence[int], limit: int) -> List[int]:
    return list(lines[:limit])


def _draft_claims(facts: Mapping[str, Any], max_evidence_lines: int) -> List[Dict[str, Any]]:
    failure_lines = facts["failure_lines"]
    representative_lines = facts.get(
        "representative_failure_lines", failure_lines
    )
    context_lines = facts["contextual_success_lines"]
    context_users = facts["contextual_success_users"]
    failure_count = facts["failure_count"]
    ip = facts["ip"]
    label = facts["label"]
    users = facts["users"]

    claims: List[Dict[str, Any]] = [
        {
            "kind": "classification",
            "value": label,
            "text": f"Munshi classified this as a { _PATTERN_NAMES[label] }.",
            "evidence_lines": _limited_lines(failure_lines, min(5, max_evidence_lines)),
            "evidence_line_count": len(failure_lines),
            "evidence_truncated": len(failure_lines) > min(5, max_evidence_lines),
            "verification_method": "detector_result_and_parsed_failures",
        },
                {
            "kind": "source_ip",
            "value": ip,
            "text": (
                f"Representative source IP {ip} participated in the "
                "distributed campaign."
                if facts.get("is_distributed", False)
                else f"Repeated failed authentication attempts were recorded from source IP {ip}."
            ),
            "evidence_lines": _limited_lines(
                representative_lines, min(5, max_evidence_lines)
            ),
            "evidence_line_count": len(representative_lines),
            "evidence_truncated": (
                len(representative_lines) > min(5, max_evidence_lines)
            ),
            "verification_method": "source_ip_match_on_parsed_events",
        },
        {
            "kind": "failure_count",
            "value": failure_count,
            "text": f"The detected episode contains {failure_count} failed authentication attempts.",
            "evidence_lines": _limited_lines(failure_lines, max_evidence_lines),
            "evidence_line_count": len(failure_lines),
            "evidence_truncated": len(failure_lines) > max_evidence_lines,
            "verification_method": "full_parsed_failure_event_count",
        },
        {
            "kind": "targeted_username_count",
            "value": len(users),
            "text": f"The failed attempts targeted {len(users)} distinct username(s).",
            "evidence_lines": _limited_lines(failure_lines, max_evidence_lines),
            "evidence_line_count": len(failure_lines),
            "evidence_truncated": len(failure_lines) > max_evidence_lines,
            "verification_method": "distinct_usernames_in_failed_events",
        },
    ]

    if facts.get("is_distributed", False):
        auth_text = (
            "Successful-login attribution was not assessed for this "
            "distributed campaign. The finding aggregates failed "
            "authentication attempts from multiple source IPs and "
            "does not establish compromise."
        )
        auth_value = {
            "assessed": False,
            "observed": None,
            "users": [],
            "ambiguous": None,
            "compromised": None,
        }

    elif len(context_users) > 1:
        auth_text = (
            "Successful authentication activity was observed for "
            f"{len(context_users)} distinct usernames in this source-IP context; "
            "attribution remains ambiguous and this does not by itself establish compromise."
        )
        auth_value = {
            "observed": True,
            "users": list(context_users),
            "ambiguous": True,
            "compromised": False,
        }

    elif len(context_users) == 1:
        auth_text = (
            "A successful authentication was observed for username "
            f"{context_users[0]} in the detector's episode/context window; "
            "this does not prove the same actor caused the failures."
        )
        auth_value = {
            "observed": True,
            "users": list(context_users),
            "ambiguous": False,
            "compromised": bool(facts["compromised"]),
        }

    else:
        auth_text = (
            "No successful authentication was observed for this source IP "
            "within the detector's episode/context window."
        )
        auth_value = {
            "observed": False,
            "users": [],
            "ambiguous": False,
            "compromised": False,
        }

    claims.append({
        "kind": "authentication_context",
        "value": auth_value,
        "text": auth_text,
        "evidence_lines": _limited_lines(context_lines, max_evidence_lines),
        "evidence_line_count": len(context_lines),
        "evidence_truncated": len(context_lines) > max_evidence_lines,
                "verification_method": (
            "distributed_success_context_not_assessed"
            if facts.get("is_distributed", False)
            else (
                "successful_event_line_references"
                if context_lines
                else "complete_parsed_event_window_check"
            )
        ),
    })
    return claims


def verify_claim(
    claim: Mapping[str, Any],
    finding: Finding,
    events: Iterable[Event],
    config: Config = Config(),
    max_evidence_lines: int = 25,
) -> Dict[str, Any]:
    """Verify a typed claim by rebuilding its canonical value from source data.

    This verifies structured claims and exact template text; it is not an NLP
    detector for arbitrary free-form prose. Unknown claim kinds are rejected.
    """
    if max_evidence_lines < 0:
        return {"verified": False, "reason": "invalid_evidence_preview_limit"}
    ordered = _ordered_events(events)
    facts, error = _derive_facts(finding, ordered, config)
    if error or facts is None:
        return {"verified": False, "reason": error or "source_facts_unavailable"}

    expected_claims = {
        item["kind"]: item for item in _draft_claims(facts, max_evidence_lines)
    }
    kind = claim.get("kind")
    if not isinstance(kind, str) or kind not in expected_claims:
        return {"verified": False, "reason": "unknown_claim_kind"}

    expected = expected_claims[kind]
    fields = (
        "kind", "value", "text", "evidence_lines", "evidence_line_count",
        "evidence_truncated", "verification_method",
    )
    if any(claim.get(field) != expected.get(field) for field in fields):
        return {"verified": False, "reason": "claim_does_not_match_source_facts"}

    # Check that each quoted line is present and semantically relevant.
    by_line = {event.line_no: event for event in ordered}
    claim_lines = claim.get("evidence_lines")
    if not isinstance(claim_lines, list):
        return {"verified": False, "reason": "invalid_evidence_line_list"}
    if any(line not in by_line for line in claim_lines):
        return {"verified": False, "reason": "claim_references_missing_event"}

    source_ips = set(
        getattr(finding, "source_ips", None) or [finding.ip]
    )

    if kind == "source_ip":
        if any(
            by_line[line].success or by_line[line].ip != finding.ip
            for line in claim_lines
        ):
            return {
                "verified": False,
                "reason": "claim_evidence_is_not_a_matching_failure",
            }

    elif kind in {
        "classification",
        "failure_count",
        "targeted_username_count",
    }:
        if any(
            by_line[line].success or by_line[line].ip not in source_ips
            for line in claim_lines
        ):
            return {
                "verified": False,
                "reason": "claim_evidence_is_not_a_matching_failure",
            }

    elif kind == "authentication_context":
        if any(
            not by_line[line].success or by_line[line].ip not in source_ips
            for line in claim_lines
        ):
            return {
                "verified": False,
                "reason": "claim_evidence_is_not_a_matching_success",
            }

    return {"verified": True, "reason": "verified_against_parsed_events"}


def build_narrative(
    finding: Finding,
    events: Iterable[Event],
    config: Config = Config(),
    max_evidence_lines: int = 25,
) -> Dict[str, Any]:
    """Build a JSON-safe narrative containing only verified deterministic claims."""
    if max_evidence_lines < 0:
        raise ValueError("max_evidence_lines must be zero or greater")

    ordered = _ordered_events(events)
    facts, error = _derive_facts(finding, ordered, config)
    if error or facts is None:
        return {
            "version": 1,
            "status": "unavailable",
            "summary": None,
            "claims": [],
            "verification": {
                "verified_claims": 0,
                "rejected_claims": 1,
                "reason": error or "source_facts_unavailable",
            },
        }

    verified_claims: List[Dict[str, Any]] = []
    rejected = 0
    for candidate in _draft_claims(facts, max_evidence_lines):
        result = verify_claim(candidate, finding, ordered, config, max_evidence_lines)
        if result["verified"]:
            verified_claims.append({**candidate, "verified": True})
        else:
            rejected += 1

        by_kind = {claim["kind"]: claim for claim in verified_claims}
    summary = None

    supporting_claims = [
        "classification",
        "source_ip",
        "failure_count",
    ]

    if all(key in by_kind for key in supporting_claims):
        failure_lines = facts["failure_lines"]

        summary = {
                  "text": (
            (
                f"Munshi classified a distributed "
                f"{_PATTERN_NAMES[facts['label']]} campaign involving "
                f"{len(facts['source_ips'])} source IPs, with "
                f"{facts['failure_count']} failed authentication attempts."
            )
            if facts.get("is_distributed", False)
            else (
                f"Munshi classified a {_PATTERN_NAMES[facts['label']]} "
                f"from {facts['ip']}, with "
                f"{facts['failure_count']} failed authentication attempts."
            )
        ),
            "verified": True,
            "supporting_claims": supporting_claims,
            "evidence_lines": _limited_lines(
                failure_lines, max_evidence_lines
            ),
            "evidence_line_count": len(failure_lines),
            "evidence_truncated": (
                len(failure_lines) > max_evidence_lines
            ),
        }

    return {
        "version": 1,
        "status": "verified" if rejected == 0 else "partial",
        "summary": summary,
        "claims": verified_claims,
        "verification": {
            "verified_claims": len(verified_claims),
            "rejected_claims": rejected,
        },
    }
