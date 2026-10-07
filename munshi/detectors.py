"""
detectors.py - Finds attack episodes in parsed login events using simple rules.

HOW IT WORKS (plain English)
1. Group events by source IP address.
2. For each IP, collect its FAILED logins and cut them into "episodes":
   a pause longer than 15 minutes starts a new episode.
3. Ignore tiny episodes (a typo or two is normal human behavior).
4. Classify each remaining episode:
   - password_spray : many DIFFERENT usernames, about one try each
   - brute_force    : few usernames, hammered many times
5. If the same IP then logs in SUCCESSFULLY soon after, mark it compromised.

Every finding keeps the line numbers of its evidence. Phase 3 depends on this.

HONEST LIMITS (put these in the report)
- Works per IP only. An attack spread over many IPs is invisible to these rules.
- Many users behind one shared IP (an office) could cause false alarms.
- The thresholds below are reasoned guesses, not proven values.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from .parsing import Event


@dataclass(frozen=True)
class Config:
    """All the tunable numbers live here, in one place."""
    min_failures: int = 10                          # fewer failures than this = normal noise
    episode_gap: timedelta = timedelta(minutes=15)  # a longer pause starts a new episode
    spray_min_users: int = 8                        # spray needs at least this many usernames...
    spray_user_ratio: float = 0.6                   # ...and distinct users / failures >= this
    success_window: timedelta = timedelta(minutes=10)  # a login this soon after = "got in"


@dataclass
class Finding:
    kind: str                       # "brute_force" or "password_spray"
    ip: str
    start: datetime
    end: datetime
    failures: int
    users: List[str]                # distinct usernames targeted
    compromised: bool
    compromised_user: Optional[str]
    evidence: List[int]             # log line numbers that prove this finding

    @property
    def label(self) -> str:
        """The name we compare against the answer key."""
        if self.kind == "brute_force" and self.compromised:
            return "brute_force_success"
        return self.kind


def _split_episodes(failures: List[Event], gap: timedelta) -> List[List[Event]]:
    """Cut a time-ordered list of failures wherever the pause is longer than 'gap'."""
    episodes, current = [], []
    for ev in failures:
        if current and ev.time - current[-1].time > gap:
            episodes.append(current)
            current = []
        current.append(ev)
    if current:
        episodes.append(current)
    return episodes


def detect(events: List[Event], config: Config = Config()) -> List[Finding]:
    """Run all rules over the events and return a list of Findings."""
    by_ip = defaultdict(list)
    for ev in sorted(events, key=lambda e: (e.time, e.line_no)):
        by_ip[ev.ip].append(ev)

    findings = []
    for ip, evs in by_ip.items():
        failures = [e for e in evs if not e.success]
        successes = [e for e in evs if e.success]

        for ep in _split_episodes(failures, config.episode_gap):
            if len(ep) < config.min_failures:
                continue                                  # just noise

            users = sorted({e.user for e in ep})
            looks_like_spray = (len(users) >= config.spray_min_users and
                                len(users) / len(ep) >= config.spray_user_ratio)
            kind = "password_spray" if looks_like_spray else "brute_force"

            start, end = ep[0].time, ep[-1].time
            win = next((s for s in successes
                        if end <= s.time <= end + config.success_window), None)

            evidence = [e.line_no for e in ep] + ([win.line_no] if win else [])
            findings.append(Finding(
                kind=kind, ip=ip, start=start,
                end=win.time if win else end,
                failures=len(ep), users=users,
                compromised=win is not None,
                compromised_user=win.user if win else None,
                evidence=evidence,
            ))
    return sorted(findings, key=lambda f: f.start)
