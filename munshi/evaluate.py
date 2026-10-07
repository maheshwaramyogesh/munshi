"""
evaluate.py - Scores the detectors against the answer key.

A finding "matches" a planted attack if its source IP is one of the attack's
IPs and the time ranges overlap. We report:
  - how many planted attacks were found, and with the right type
  - results split by attack variant (loud, low_and_slow, ...)
  - false alarms, and (if a benign file is given) WHICH innocent behavior caused each

Run:
    python -m munshi.evaluate            easy data
    python -m munshi.evaluate --hard     hard data
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from .detectors import Config, Finding, detect
from .parsing import parse_file


def _overlap(a_start, a_end, b_start, b_end) -> bool:
    return a_start <= b_end and b_start <= a_end


def score(findings: List[Finding], truth: List[Dict],
          benign: Optional[List[Dict]] = None) -> Dict:
    rows, matched_ids = [], set()
    for attack in truth:
        ips = attack.get("source_ips") or [attack["source_ip"]]
        t_start = datetime.fromisoformat(attack["start"])
        t_end = datetime.fromisoformat(attack["end"])
        hits = [f for f in findings
                if f.ip in ips and _overlap(f.start, f.end, t_start, t_end)]
        matched_ids.update(id(f) for f in hits)
        predicted = hits[0].label if hits else None
        rows.append({
            "id": attack["id"], "ip": ips[0], "n_ips": len(ips),
            "variant": attack.get("variant", "loud"),
            "planted": attack["type"], "found": bool(hits), "predicted": predicted,
            "correct_type": predicted == attack["type"],
        })

    false_alarms = [f for f in findings if id(f) not in matched_ids]
    causes = Counter()
    for f in false_alarms:
        cause = "unexplained"
        for case in benign or []:
            if f.ip in case["ips"] and _overlap(f.start, f.end,
                                                datetime.fromisoformat(case["start"]),
                                                datetime.fromisoformat(case["end"])):
                cause = case["type"]
                break
        causes[cause] += 1

    by_variant = defaultdict(lambda: [0, 0, 0])      # [planted, detected, correct_type]
    for r in rows:
        v = by_variant[r["variant"]]
        v[0] += 1
        v[1] += r["found"]
        v[2] += r["correct_type"]

    return {
        "rows": rows,
        "planted": len(truth),
        "detected": sum(r["found"] for r in rows),
        "correct_type": sum(r["correct_type"] for r in rows),
        "false_alarms": false_alarms,
        "false_alarm_causes": dict(causes),
        "by_variant": dict(by_variant),
    }


def print_report(r: Dict) -> None:
    print(f"{'id':>2}  {'variant':<17} {'IPs':>3}  {'planted':<20} {'predicted':<20} ok")
    for row in r["rows"]:
        print(f"{row['id']:>2}  {row['variant']:<17} {row['n_ips']:>3}  {row['planted']:<20} "
              f"{str(row['predicted']):<20} {'yes' if row['correct_type'] else 'NO'}")
    print()
    print("By variant (planted / detected / correct type):")
    for name, (n, d, c) in r["by_variant"].items():
        print(f"  {name:<17} {n:>2} / {d:>2} / {c:>2}")
    print()
    print(f"Detected     : {r['detected']}/{r['planted']}")
    print(f"Correct type : {r['correct_type']}/{r['planted']}")
    print(f"False alarms : {len(r['false_alarms'])}")
    for cause, n in sorted(r["false_alarm_causes"].items()):
        print(f"   {cause:<20} {n}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hard", action="store_true", help="use the hard dataset")
    args = ap.parse_args()
    if args.hard:
        log, truth_path, benign_path = ("logs/auth_hard.log", "logs/ground_truth_hard.json",
                                        "logs/benign_hard.json")
    else:
        log, truth_path, benign_path = "logs/auth.log", "logs/ground_truth.json", None

    findings = detect(parse_file(log).events, Config())
    with open(truth_path) as f:
        truth = json.load(f)
    benign = json.load(open(benign_path)) if benign_path else None
    print_report(score(findings, truth, benign))


if __name__ == "__main__":
    main()
