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
    episode_success_users: List[str]  # successful auth during/after the episode (context only)
    episode_success_lines: List[int]  # line numbers for those contextual successes
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
            post_episode_wins = [s for s in successes
                                 if end <= s.time <= end + config.success_window]
            win = post_episode_wins[0] if post_episode_wins else None

            # Context: successful authentications that happened during the
            # suspicious episode or shortly after it. This is intentionally
            # separate from the scoring signal above: a shared office IP can
            # have many legitimate successes during the same episode.
            context_wins = [s for s in successes
                            if start <= s.time <= end + config.success_window]
            context_users = sorted({s.user for s in context_wins})
            context_lines = [s.line_no for s in context_wins]

                        # A single successful user is compatible with the detector's
            # existing brute-force-success classification. Multiple distinct
            # successful users from the same source make the interpretation
            # ambiguous (for example, a shared office IP).
            authentication_ambiguous = len(context_users) > 1
            confirmed_success = bool(post_episode_wins) and not authentication_ambiguous


            evidence = [e.line_no for e in ep] + [s.line_no for s in post_episode_wins]
            findings.append(Finding(
                kind=kind, ip=ip, start=start,
                end=win.time if win else end,
                failures=len(ep), users=users,
                                compromised=confirmed_success,
                compromised_user=win.user if confirmed_success else None,
                episode_success_users=context_users,
                episode_success_lines=context_lines,
                evidence=evidence,
            ))
    return sorted(findings, key=lambda f: f.start)
