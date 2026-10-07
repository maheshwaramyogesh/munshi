"""
evaluate.py - Scores the detectors against the answer key (ground_truth.json).

A finding "matches" a planted attack if it has the same source IP and the
time ranges overlap. We then report:
  - how many planted attacks were found
  - how many were labeled with the right type
  - how many findings matched nothing (false alarms)

Run:  python -m munshi.evaluate
"""

import json
import sys
from datetime import datetime
from typing import Dict, List

from .detectors import Finding, detect
from .parsing import parse_file


def _overlap(a_start, a_end, b_start, b_end) -> bool:
    return a_start <= b_end and b_start <= a_end


def score(findings: List[Finding], truth: List[Dict]) -> Dict:
    rows, matched_ids = [], set()
    for attack in truth:
        t_start = datetime.fromisoformat(attack["start"])
        t_end = datetime.fromisoformat(attack["end"])
        hits = [f for f in findings
                if f.ip == attack["source_ip"] and _overlap(f.start, f.end, t_start, t_end)]
        matched_ids.update(id(f) for f in hits)
        predicted = hits[0].label if hits else None
        rows.append({
            "id": attack["id"], "ip": attack["source_ip"], "planted": attack["type"],
            "found": bool(hits), "predicted": predicted,
            "correct_type": predicted == attack["type"],
            "findings_for_it": len(hits),
        })
    false_alarms = [f for f in findings if id(f) not in matched_ids]
    return {
        "rows": rows,
        "planted": len(truth),
        "detected": sum(r["found"] for r in rows),
        "correct_type": sum(r["correct_type"] for r in rows),
        "false_alarms": false_alarms,
    }


def main():
    log = sys.argv[1] if len(sys.argv) > 1 else "logs/auth.log"
    truth_path = sys.argv[2] if len(sys.argv) > 2 else "logs/ground_truth.json"
    parsed = parse_file(log)
    findings = detect(parsed.events)
    with open(truth_path) as f:
        truth = json.load(f)
    r = score(findings, truth)

    print(f"{'id':>2}  {'attacker IP':<14} {'planted':<20} {'predicted':<20} ok")
    for row in r["rows"]:
        print(f"{row['id']:>2}  {row['ip']:<14} {row['planted']:<20} "
              f"{str(row['predicted']):<20} {'yes' if row['correct_type'] else 'NO'}")
    print()
    print(f"Detected     : {r['detected']}/{r['planted']}")
    print(f"Correct type : {r['correct_type']}/{r['planted']}")
    print(f"False alarms : {len(r['false_alarms'])}")
    for f in r["false_alarms"]:
        print(f"   {f.ip} {f.label} {f.start} ({f.failures} failures)")


if __name__ == "__main__":
    main()
