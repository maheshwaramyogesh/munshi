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

from collections import Counter, defaultdict
from dataclasses import dataclass, field
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

        # Correlate repeated short bursts without lowering min_failures.
    burst_gap: timedelta = timedelta(minutes=5)
    burst_min_failures: int = 6
    burst_min_count: int = 4
    burst_min_total_failures: int = 30
    burst_max_gap: timedelta = timedelta(minutes=45)
    burst_max_duration: timedelta = timedelta(hours=4)

        # Correlate sustained, widely spaced failures for one account.
    slow_min_interval: timedelta = timedelta(minutes=15)
    slow_max_interval: timedelta = timedelta(minutes=45)
    slow_min_failures: int = 20
    slow_min_duration: timedelta = timedelta(hours=8)

        # Correlate password-spray-like activity across source IPs.
    distributed_window: timedelta = timedelta(minutes=90)
    distributed_min_ips: int = 10
    distributed_min_total_failures: int = 50
    distributed_min_users: int = 20
    distributed_min_user_ratio: float = 0.45
    distributed_min_failures_per_ip: int = 2
    distributed_max_failures_per_ip: int = 5


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
    evidence: List[int]
    source_ips: List[str] = field(default_factory=list)
    def __post_init__(self):
        if not self.source_ips:
            self.source_ips = [self.ip]
        else:
            self.source_ips = list(dict.fromkeys(self.source_ips))
            if self.ip not in self.source_ips:
                self.source_ips.insert(0, self.ip)            # log line numbers that prove this finding

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

def _detect_threshold_dodgers(events: List[Event], config: Config):
    """Correlate repeated short failure bursts for the same IP and username."""
    failures_by_target = defaultdict(list)
    successes_by_ip = defaultdict(list)

    for ev in events:
        if ev.success:
            successes_by_ip[ev.ip].append(ev)
        else:
            failures_by_target[(ev.ip, ev.user)].append(ev)

    findings = []
    covered_lines = set()

    for (ip, user), target_failures in failures_by_target.items():
        target_failures.sort(key=lambda e: (e.time, e.line_no))

        # Split into short bursts. Slow individual attempts won't qualify.
        bursts = []
        current = []

        for ev in target_failures:
            if (
                current
                and ev.time - current[-1].time > config.burst_gap
            ):
                bursts.append(current)
                current = []
            current.append(ev)

        if current:
            bursts.append(current)

        bursts = [
            burst for burst in bursts
            if len(burst) >= config.burst_min_failures
        ]
        if not bursts:
            continue

        # Group nearby bursts into correlation windows.
        clusters = []
        cluster = []

        for burst in bursts:
            if cluster:
                gap = burst[0].time - cluster[-1][-1].time
                duration = burst[-1].time - cluster[0][0].time

                if (
                    gap > config.burst_max_gap
                    or duration > config.burst_max_duration
                ):
                    clusters.append(cluster)
                    cluster = []

            cluster.append(burst)

        if cluster:
            clusters.append(cluster)

        for cluster in clusters:
            cluster_failures = [
                ev for burst in cluster for ev in burst
            ]

            if len(cluster) < config.burst_min_count:
                continue

            if len(cluster_failures) < config.burst_min_total_failures:
                continue

            cluster_failures.sort(key=lambda e: (e.time, e.line_no))
            first = cluster_failures[0]
            last = cluster_failures[-1]

            ip_successes = sorted(
                successes_by_ip[ip],
                key=lambda e: (e.time, e.line_no),
            )

            post_episode_wins = [
                s for s in ip_successes
                if last.time <= s.time <= last.time + config.success_window
            ]

            context_wins = [
                s for s in ip_successes
                if first.time <= s.time <= last.time + config.success_window
            ]

            context_users = sorted({s.user for s in context_wins})
            win = post_episode_wins[0] if post_episode_wins else None

            # Keep the existing conservative compromise interpretation.
            confirmed_success = bool(post_episode_wins) and len(context_users) <= 1

            evidence = [e.line_no for e in cluster_failures]
            evidence.extend(s.line_no for s in post_episode_wins)

            findings.append(
                Finding(
                    kind="brute_force",
                    ip=ip,
                    start=first.time,
                    end=win.time if win else last.time,
                    failures=len(cluster_failures),
                    users=[user],
                    compromised=confirmed_success,
                    compromised_user=win.user if confirmed_success else None,
                    episode_success_users=context_users,
                    episode_success_lines=[s.line_no for s in context_wins],
                    evidence=evidence,
                )
            )

            covered_lines.update(e.line_no for e in cluster_failures)

    return findings, covered_lines

def _detect_low_and_slow(events: List[Event], config: Config):
    """Detect sustained failures spaced at low-and-slow intervals."""
    failures_by_target = defaultdict(list)
    successes_by_ip = defaultdict(list)

    for ev in events:
        if ev.success:
            successes_by_ip[ev.ip].append(ev)
        else:
            failures_by_target[(ev.ip, ev.user)].append(ev)

    findings = []
    covered_lines = set()

    for (ip, user), target_failures in failures_by_target.items():
        target_failures.sort(key=lambda e: (e.time, e.line_no))
        runs = []
        current = []

        for ev in target_failures:
            if current:
                gap = ev.time - current[-1].time

                if (
                    gap < config.slow_min_interval
                    or gap > config.slow_max_interval
                ):
                    runs.append(current)
                    current = []

            current.append(ev)

        if current:
            runs.append(current)

        for run in runs:
            if len(run) < config.slow_min_failures:
                continue

            start = run[0].time
            last_failure = run[-1].time

            if last_failure - start < config.slow_min_duration:
                continue

            ip_successes = sorted(
                successes_by_ip[ip],
                key=lambda e: (e.time, e.line_no),
            )

            post_episode_wins = [
                s for s in ip_successes
                if last_failure <= s.time
                <= last_failure + config.success_window
            ]

            context_wins = [
                s for s in ip_successes
                if start <= s.time
                <= last_failure + config.success_window
            ]

            context_users = sorted({s.user for s in context_wins})
            win = post_episode_wins[0] if post_episode_wins else None
            confirmed_success = (
                bool(post_episode_wins) and len(context_users) <= 1
            )

            evidence = [e.line_no for e in run]
            evidence.extend(s.line_no for s in post_episode_wins)

            findings.append(
                Finding(
                    kind="brute_force",
                    ip=ip,
                    start=start,
                    end=win.time if win else last_failure,
                    failures=len(run),
                    users=[user],
                    compromised=confirmed_success,
                    compromised_user=(
                        win.user if confirmed_success else None
                    ),
                    episode_success_users=context_users,
                    episode_success_lines=[
                        s.line_no for s in context_wins
                    ],
                    evidence=evidence,
                )
            )

            covered_lines.update(e.line_no for e in run)

    return findings, covered_lines

def _detect_distributed_sprays(events: List[Event], config: Config):
    """Correlate password-spray-like failures across many source IPs."""
    failures = sorted(
        (event for event in events if not event.success),
        key=lambda event: (event.time, event.line_no),
    )

    candidates = []

    for start_index, first_event in enumerate(failures):
        window_end = first_event.time + config.distributed_window
        window_events = []

        for event in failures[start_index:]:
            if event.time > window_end:
                break
            window_events.append(event)

        counts_by_ip = Counter(event.ip for event in window_events)

        participating_ips = {
            ip
            for ip, count in counts_by_ip.items()
            if config.distributed_min_failures_per_ip
            <= count
            <= config.distributed_max_failures_per_ip
        }

        campaign_events = [
            event for event in window_events
            if event.ip in participating_ips
        ]

        source_ips = sorted(participating_ips)
        usernames = sorted({event.user for event in campaign_events})
        failure_count = len(campaign_events)

        if len(source_ips) < config.distributed_min_ips:
            continue

        if failure_count < config.distributed_min_total_failures:
            continue

        if len(usernames) < config.distributed_min_users:
            continue

        if not failure_count or len(usernames) / failure_count < (
            config.distributed_min_user_ratio
        ):
            continue

        candidates.append({
            "events": campaign_events,
            "source_ips": source_ips,
            "users": usernames,
            "lines": {event.line_no for event in campaign_events},
        })

    # Prefer the broadest candidate and suppress heavily overlapping
    # windows for the same campaign.
    candidates.sort(
        key=lambda item: len(item["events"]),
        reverse=True,
    )

    selected = []

    for candidate in candidates:
        lines = candidate["lines"]

        duplicate = False
        for existing in selected:
            existing_lines = existing["lines"]
            shared = len(lines & existing_lines)
            smaller = min(len(lines), len(existing_lines))

            if smaller and shared / smaller >= 0.70:
                duplicate = True
                break

        if not duplicate:
            selected.append(candidate)

    findings = []
    covered_lines = set()

    for candidate in selected:
        campaign_events = candidate["events"]
        source_ips = candidate["source_ips"]
        users = candidate["users"]

        campaign_events.sort(key=lambda event: (event.time, event.line_no))

        findings.append(
            Finding(
                kind="password_spray",
                ip=source_ips[0],
                start=campaign_events[0].time,
                end=campaign_events[-1].time,
                failures=len(campaign_events),
                users=users,
                compromised=False,
                compromised_user=None,
                episode_success_users=[],
                episode_success_lines=[],
                evidence=[event.line_no for event in campaign_events],
                source_ips=source_ips,
            )
        )

        covered_lines.update(candidate["lines"])

    return findings, covered_lines


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
    advanced_findings, burst_lines = _detect_threshold_dodgers(
        events, config
    )
    slow_findings, slow_lines = _detect_low_and_slow(
        events, config
    )
    distributed_findings, distributed_lines = _detect_distributed_sprays(
        events, config
    )

    covered_lines = burst_lines | slow_lines | distributed_lines

    # Suppress a basic finding only when advanced detections cover most
    # of its failed-authentication evidence. A handful of overlapping
    # tail events must not erase a much larger brute-force episode.
    failure_line_numbers = {
        event.line_no for event in events if not event.success
    }

    if covered_lines:
        retained_findings = []

        for finding in findings:
            failure_evidence = [
                line for line in finding.evidence
                if line in failure_line_numbers
            ]
            covered_failure_evidence = [
                line for line in failure_evidence
                if line in covered_lines
            ]

            overlap_ratio = (
                len(covered_failure_evidence) / len(failure_evidence)
                if failure_evidence else 0.0
            )

            if overlap_ratio < 0.70:
                retained_findings.append(finding)

        findings = retained_findings

    findings.extend(advanced_findings)
    findings.extend(slow_findings)
    findings.extend(distributed_findings)

    return sorted(findings, key=lambda f: f.start)