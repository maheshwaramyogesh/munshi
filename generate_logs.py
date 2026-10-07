"""
generate_logs.py - Makes FAKE SSH login logs with attacks hidden inside.

WHY THIS EXISTS
We need test data where we KNOW exactly which attacks are hidden.
Then we can measure how many our detector finds (and how many false alarms it raises).

SAFETY
Every IP address here is from ranges reserved for documentation (RFC 5737).
They never belong to real machines. No real data or real people are involved.

HOW TO RUN
    python generate_logs.py
It creates two files in a folder called "logs":
    auth.log          the fake log (what the detector will read)
    ground_truth.json the answer key (which attacks we planted)
"""

import json
import os
import random
from datetime import datetime, timedelta

# A fixed seed means every run makes the SAME data. This makes results repeatable.
SEED = 42
random.seed(SEED)

START = datetime(2026, 10, 1, 0, 0, 0)  # first moment of the log
DAYS = 7                                # how many days of normal activity
HOSTNAME = "server01"

# Real attacks are RARE compared to normal activity, so we make a big normal crowd:
# 60 staff members, each with their own usual (fake) IP address.
LEGIT_USERS = [f"user{i:02d}" for i in range(1, 61)]
USER_IP = {u: f"198.51.100.{i}" for i, u in enumerate(LEGIT_USERS, start=1)}  # "good" IPs

# Attacker IPs: a different documentation-only range, so they never overlap with staff.
ATTACKER_IPS = [f"203.0.113.{i}" for i in range(1, 40)]

# Usernames that real attackers commonly try.
COMMON_GUESSES = ["root", "admin", "test", "oracle", "ubuntu", "user", "guest",
                  "postgres", "ftp", "pi", "git", "mysql", "support", "dev", "backup"]
# More made-up names, so password spraying can try many different usernames.
EXTRA_GUESSES = [f"svc{i}" for i in range(1, 40)]


def format_time(ts):
    """Format a time like a real Linux log: 'Oct  1 09:15:32' (day padded to 2 chars)."""
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"


def make_line(ts, message):
    """Return (time, full log line). We keep the time so we can sort everything later."""
    pid = random.randint(1000, 60000)  # fake process id
    return (ts, f"{format_time(ts)} {HOSTNAME} sshd[{pid}]: {message}")


def failed_login(ts, user, ip):
    """A failed password attempt. Real logs say 'invalid user' if the account doesn't exist."""
    who = user if user in LEGIT_USERS else f"invalid user {user}"
    port = random.randint(1024, 65535)
    return make_line(ts, f"Failed password for {who} from {ip} port {port} ssh2")


def accepted_login(ts, user, ip):
    """A successful login."""
    port = random.randint(1024, 65535)
    return make_line(ts, f"Accepted password for {user} from {ip} port {port} ssh2")


def random_times(start, duration_seconds, count):
    """Pick 'count' random moments inside a time window, sorted in order."""
    offsets = sorted(random.uniform(0, duration_seconds) for _ in range(count))
    return [start + timedelta(seconds=o) for o in offsets]


def normal_traffic():
    """Everyday behavior: staff log in during work hours from their usual IP.
    Sometimes they mistype their password once or twice. These are NOT attacks,
    so they let us measure FALSE ALARMS (a good detector should ignore them)."""
    events = []
    for day in range(DAYS):
        for user in LEGIT_USERS:
            for _ in range(random.randint(1, 3)):        # 1-3 logins per day
                hour = random.randint(8, 17)             # 08:00 - 17:59
                ts = START + timedelta(days=day, hours=hour,
                                       minutes=random.randint(0, 59),
                                       seconds=random.randint(0, 59))
                ip = USER_IP[user]
                if random.random() < 0.10:               # 10% chance of a typo first
                    for k in range(random.randint(1, 2)):
                        events.append(failed_login(ts - timedelta(seconds=10 * (k + 1)), user, ip))
                events.append(accepted_login(ts, user, ip))
    return events


def random_start():
    """A random moment anywhere in the week (attacks happen at any hour)."""
    return START + timedelta(seconds=random.randint(0, DAYS * 86400 - 3600))


def plant_attacks():
    """Hide 10 attacks in the log. Returns the events AND the answer key."""
    events, truth = [], []
    ips = random.sample(ATTACKER_IPS, 10)  # a different attacker IP for each attack
    plan = ["brute_force"] * 4 + ["brute_force_success"] * 3 + ["password_spray"] * 3

    for i, (attack_type, ip) in enumerate(zip(plan, ips), start=1):
        start = random_start()
        attack_events = []
        target = None

        if attack_type == "brute_force":
            # Hammer a couple of usernames, many times, never succeed.
            count = random.randint(40, 150)
            duration = random.randint(120, 600)           # 2-10 minutes
            names = random.sample(COMMON_GUESSES, 2)
            for ts in random_times(start, duration, count):
                attack_events.append(failed_login(ts, random.choice(names), ip))

        elif attack_type == "brute_force_success":
            # Hammer ONE real account, then finally get in. This is the dangerous one.
            target = random.choice(LEGIT_USERS)
            count = random.randint(30, 100)
            duration = random.randint(120, 600)
            for ts in random_times(start, duration, count):
                attack_events.append(failed_login(ts, target, ip))
            win_time = start + timedelta(seconds=duration + random.randint(3, 20))
            attack_events.append(accepted_login(win_time, target, ip))

        else:  # password_spray
            # Try MANY different usernames, once each, slowly, to stay quiet.
            count = random.randint(25, 40)
            duration = random.randint(600, 1800)          # 10-30 minutes
            names = random.sample(COMMON_GUESSES + EXTRA_GUESSES, count)
            for ts, name in zip(random_times(start, duration, count), names):
                attack_events.append(failed_login(ts, name, ip))

        events.extend(attack_events)
        times = [t for t, _ in attack_events]
        truth.append({
            "id": i,
            "type": attack_type,
            "source_ip": ip,
            "target_user": target,
            "start": min(times).isoformat(),
            "end": max(times).isoformat(),
            "num_log_lines": len(attack_events),
        })
    return events, truth


def main():
    normal = normal_traffic()
    attacks, truth = plant_attacks()

    all_events = sorted(normal + attacks, key=lambda e: e[0])  # sort by time

    os.makedirs("logs", exist_ok=True)
    with open("logs/auth.log", "w") as f:
        for _, text in all_events:
            f.write(text + "\n")
    with open("logs/ground_truth.json", "w") as f:
        json.dump(truth, f, indent=2)

    print(f"Wrote logs/auth.log          : {len(all_events)} lines "
          f"({len(normal)} normal, {len(attacks)} attack)")
    print(f"Wrote logs/ground_truth.json : {len(truth)} planted attacks")


if __name__ == "__main__":
    main()
