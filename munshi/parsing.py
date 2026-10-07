"""
parsing.py - Turns raw SSH log lines into structured Event objects.

WHY THIS EXISTS
Every later step (detection, story, verifier) needs facts like "which IP, which
user, success or failure, when". Text is hard to analyze; structured data is easy.

KEY DESIGN RULES
1. We keep each line's NUMBER. Later, every claim in a story will point back to
   exact log lines (the "evidence link").
2. We never silently drop lines. Anything we can't read goes into 'skipped',
   so we can always see what the parser did not understand.

KNOWN LIMITS (say these honestly in the report)
- Only supports OpenSSH password lines ("Failed/Accepted password for ...").
- Linux logs have no year, so we assume one (default 2026). Logs that cross a
  new year are not handled.
"""

import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

# One pattern that describes a whole log line. The (?P<name>...) parts are the
# pieces we want to pull out.
LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<result>Failed|Accepted) password for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+) ssh2\s*$"
)


@dataclass(frozen=True)
class Event:
    """One login attempt, as structured data."""
    line_no: int          # line number in the file (1-based): our evidence pointer
    time: datetime
    host: str
    user: str
    ip: str
    port: int
    success: bool         # True = "Accepted", False = "Failed"
    invalid_user: bool    # True if the account does not exist on the server
    raw: str              # the original line, kept for evidence


@dataclass
class ParseResult:
    events: List[Event]
    skipped: List[Tuple[int, str]]   # (line number, text) of lines we couldn't read


def parse_line(line: str, line_no: int, year: int = 2026) -> Optional[Event]:
    """Parse one line. Returns an Event, or None if the line isn't understood."""
    m = LINE_RE.match(line)
    if not m:
        return None
    try:
        when = datetime.strptime(
            f"{year} {m['month']} {m['day']} {m['clock']}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:  # e.g. an impossible date like Feb 30
        return None
    return Event(
        line_no=line_no,
        time=when,
        host=m["host"],
        user=m["user"],
        ip=m["ip"],
        port=int(m["port"]),
        success=(m["result"] == "Accepted"),
        invalid_user=m["invalid"] is not None,
        raw=line.rstrip("\n"),
    )


def parse_lines(lines: Iterable[str], year: int = 2026) -> ParseResult:
    """Parse many lines, keeping track of anything we could not read."""
    events, skipped = [], []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():          # ignore truly empty lines
            continue
        event = parse_line(line, line_no, year)
        if event is None:
            skipped.append((line_no, line.rstrip("\n")))
        else:
            events.append(event)
    return ParseResult(events, skipped)


def parse_file(path: str, year: int = 2026) -> ParseResult:
    """Read a log file from disk and parse it."""
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse_lines(f, year)


if __name__ == "__main__":
    # Quick demo:  python -m munshi.parsing logs/auth.log
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/auth.log"
    result = parse_file(path)
    ev = result.events
    print(f"Parsed  : {len(ev)} events")
    print(f"Skipped : {len(result.skipped)} lines")
    if ev:
        print(f"Failed  : {sum(1 for e in ev if not e.success)}")
        print(f"Accepted: {sum(1 for e in ev if e.success)}")
        print(f"Distinct IPs: {len({e.ip for e in ev})}")
        print(f"Time range  : {ev[0].time} -> {ev[-1].time}")
