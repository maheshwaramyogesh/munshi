"""
generate_logs.py - Makes FAKE SSH login logs with attacks hidden inside.

WHY THIS EXISTS
We need test data where we KNOW exactly which attacks are hidden.
Then we can measure how many our detector finds (and how many false alarms it raises).

SAFETY
Every IP address here is from ranges reserved for documentation (RFC 5737).
They never belong to real machines. No real data or real people are involved.

HOW TO RUN
    python generate_logs.py          EASY data (loud attacks, simple normal users)
    python generate_logs.py --hard   EASY data + HARD cases (see below)

Easy mode writes into the folder "logs":
    auth.log, ground_truth.json
Hard mode writes (the easy files are never touched):
    auth_hard.log, ground_truth_hard.json, benign_hard.json

HARD CASES (designed from realistic behavior BEFORE looking at any results)
  Hard innocents (NOT attacks - a good detector should stay quiet):
    forgotten_password   a real user fails 5-14 times, then gets in
    shared_office_ip     12 staff behind ONE shared IP all mistype in the morning
    service_loop         a misconfigured script retrying a wrong password for 3 hours
  Stealthy attacks (a good detector should catch these):
    low_and_slow         one try every 20-40 minutes for 40 hours
    threshold_dodger     short bursts just under the alert threshold (one ends in a break-in)
    distributed          the same attack spread over 20 different IPs
NOTE: the stealth attacks model an attacker who knows typical detection settings.
That is a worst case, and the report should say so.
"""

import argparse
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


def failed_login(ts, user, ip, valid=None):
    """A failed password attempt. Real logs say 'invalid user' if the account doesn't exist.
    'valid' lets us force a real account that isn't in LEGIT_USERS (e.g. a service account)."""
    is_valid = (user in LEGIT_USERS) if valid is None else valid
    who = user if is_valid else f"invalid user {user}"
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


def _record(events_out, truth_out, first_id, variant, atype, ips, target, ev):
    """Add one attack's events to the log and its entry to the answer key."""
    times = [t for t, _ in ev]
    truth_out.append({
        "id": first_id + len(truth_out), "type": atype, "variant": variant,
        "source_ip": ips[0], "source_ips": ips, "target_user": target,
        "start": min(times).isoformat(), "end": max(times).isoformat(),
        "num_log_lines": len(ev),
    })
    events_out.extend(ev)


def hard_innocents():
    """Innocent behavior that LOOKS suspicious. Returns (events, list of cases)."""
    events, cases = [], []

    def add_case(kind, ips, ev):
        times = [t for t, _ in ev]
        cases.append({"id": len(cases) + 1, "type": kind, "ips": ips,
                      "start": min(times).isoformat(), "end": max(times).isoformat(),
                      "num_log_lines": len(ev)})
        events.extend(ev)

    # 1) Forgotten password: 5-14 failures in a row, then success, from the usual IP.
    for user in random.sample(LEGIT_USERS, 6):
        ip = USER_IP[user]
        t = START + timedelta(days=random.randint(0, DAYS - 1),
                              hours=random.randint(8, 16), minutes=random.randint(0, 59))
        ev = []
        for _ in range(random.randint(5, 14)):
            ev.append(failed_login(t, user, ip))
            t += timedelta(seconds=random.randint(5, 20))
        ev.append(accepted_login(t, user, ip))
        add_case("forgotten_password", [ip], ev)

    # 2) Shared office IP: 12 staff behind one address mistype 1-3 times each, then get in.
    nat_ip = "198.51.100.200"
    window = START + timedelta(days=random.randint(0, DAYS - 1), hours=9)
    ev = []
    for user in random.sample(LEGIT_USERS, 12):
        t = window + timedelta(seconds=random.randint(0, 1800))
        for _ in range(random.randint(1, 3)):
            ev.append(failed_login(t, user, nat_ip))
            t += timedelta(seconds=random.randint(5, 15))
        ev.append(accepted_login(t, user, nat_ip))
    add_case("shared_office_ip", [nat_ip], ev)

    # 3) Service loop: a script with a wrong password retries every minute for 3 hours.
    ip = "198.51.100.210"
    t = START + timedelta(days=random.randint(0, DAYS - 1), hours=random.randint(8, 12))
    ev = [failed_login(t + timedelta(minutes=m), "backup", ip, valid=True) for m in range(180)]
    add_case("service_loop", [ip], ev)

    return events, cases


def hard_attacks(first_id):
    """Stealthy attacks built to slip past simple per-IP rules. Returns (events, truth)."""
    events, truth = [], []
    pool = [f"203.0.113.{i}" for i in range(50, 255)]   # kept apart from the easy attackers
    random.shuffle(pool)

    def take(n):
        return [pool.pop() for _ in range(n)]

    def record(variant, atype, ips, target, ev):
        _record(events, truth, first_id, variant, atype, ips, target, ev)

    # Low and slow: one try every 20-40 minutes for 40 hours (pauses longer than 15 min).
    for _ in range(2):
        ip = take(1)[0]
        start = START + timedelta(seconds=random.randint(0, 3 * 86400))
        t, ev = start, []
        while t < start + timedelta(hours=40):
            ev.append(failed_login(t, "root", ip))
            t += timedelta(minutes=random.uniform(20, 40))
        record("low_and_slow", "brute_force", [ip], None, ev)

    # Threshold dodger: 6-8 bursts of 6-9 failures, 20-30 minutes apart.
    for with_success in (False, True):
        ip = take(1)[0]
        target = random.choice(LEGIT_USERS) if with_success else "root"
        t = START + timedelta(seconds=random.randint(0, 4 * 86400))
        ev = []
        for _ in range(random.randint(6, 8)):
            for ts in random_times(t, random.randint(30, 60), random.randint(6, 9)):
                ev.append(failed_login(ts, target, ip))
            t += timedelta(minutes=random.uniform(20, 30))
        if with_success:
            last = max(e[0] for e in ev)
            ev.append(accepted_login(last + timedelta(seconds=random.randint(3, 20)), target, ip))
        record("threshold_dodger", "brute_force_success" if with_success else "brute_force",
               [ip], target if with_success else None, ev)

    # Distributed: 20 IPs, each only 3-4 tries, all within about an hour.
    for _ in range(2):
        ips = take(20)
        start = START + timedelta(seconds=random.randint(0, 5 * 86400))
        ev = []
        for ip in ips:
            s0 = start + timedelta(seconds=random.randint(0, 3600))
            names = random.sample(COMMON_GUESSES + EXTRA_GUESSES, random.randint(3, 4))
            for ts, name in zip(random_times(s0, random.randint(120, 300), len(names)), names):
                ev.append(failed_login(ts, name, ip))
        record("distributed", "password_spray", ips, None, ev)

    return events, truth


def write_log(events, path):
    with open(path, "w") as f:
        for _, text in sorted(events, key=lambda e: e[0]):
            f.write(text + "\n")


def main():
    ap = argparse.ArgumentParser(
        description="Generate fake SSH logs with planted attacks."
    )
    ap.add_argument(
        "--hard",
        action="store_true",
        help="add hard innocents and stealth attacks",
    )
    ap.add_argument(
        "--seed",
        type=int,
        default=SEED,
        help=f"random seed for reproducible data (default: {SEED})",
    )

    ap.add_argument(
        "--out-dir",
        default="logs",
        help="directory for generated files (default: logs)",
    )
    args = ap.parse_args()

    # Reset the random generator before creating any events.
    random.seed(args.seed)

    # The easy part runs first and uses the random generator exactly as before,
    # so the easy data is identical whether or not --hard is used.
    normal = normal_traffic()
    attacks, truth = plant_attacks()
    os.makedirs(args.out_dir, exist_ok=True)

    if not args.hard:
        all_events = sorted(normal + attacks, key=lambda e: e[0])

        auth_path = os.path.join(args.out_dir, "auth.log")
        truth_path = os.path.join(args.out_dir, "ground_truth.json")

        write_log(all_events, auth_path)
        with open(truth_path, "w") as f:
            json.dump(truth, f, indent=2)

        print(f"Wrote {auth_path}: {len(all_events)} lines "
              f"({len(normal)} normal, {len(attacks)} attack)")
        print(f"Wrote {truth_path}: {len(truth)} planted attacks")
        return

    for a in truth:                       # label the original 10 as "loud"
        a["variant"] = "loud"
        a["source_ips"] = [a["source_ip"]]
    inn_events, benign = hard_innocents()
    atk_events, hard_truth = hard_attacks(first_id=len(truth) + 1)
    all_truth = truth + hard_truth
    all_events = normal + attacks + inn_events + atk_events

    auth_path = os.path.join(args.out_dir, "auth_hard.log")
    truth_path = os.path.join(args.out_dir, "ground_truth_hard.json")
    benign_path = os.path.join(args.out_dir, "benign_hard.json")

    write_log(all_events, auth_path)

    with open(truth_path, "w") as f:
        json.dump(all_truth, f, indent=2)

    with open(benign_path, "w") as f:
        json.dump(benign, f, indent=2)

    print(f"Wrote {auth_path}: {len(all_events)} lines")
    print(
        f"Wrote {truth_path}: {len(all_truth)} attacks "
        f"({len(truth)} loud + {len(hard_truth)} stealthy)"
    )
    print(f"Wrote {benign_path}: {len(benign)} hard innocent cases")


if __name__ == "__main__":
    main()
