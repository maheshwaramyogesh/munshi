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
    """Score findings against planted attacks using one-to-one matching."""
    candidates_by_attack = []
    attack_ips_list = []

    # Build possible matches using time overlap and any shared source IP.
    for attack in truth:
        ips = attack.get("source_ips") or [attack["source_ip"]]
        attack_ips = set(ips)
        attack_ips_list.append(ips)

        t_start = datetime.fromisoformat(attack["start"])
        t_end = datetime.fromisoformat(attack["end"])

        candidates = []

        for finding_index, finding in enumerate(findings):
            if not _overlap(
                finding.start, finding.end, t_start, t_end
            ):
                continue

            finding_ips = set(
                getattr(finding, "source_ips", []) or [finding.ip]
            )
            shared_ips = len(attack_ips & finding_ips)

            if shared_ips:
                candidates.append((
                    finding_index,
                    shared_ips,
                    finding.ip in attack_ips,
                ))

        # Prefer findings covering more planted IPs. The representative
        # IP is only a tie-breaker, not the sole matching criterion.
        candidates.sort(
            key=lambda item: (item[1], item[2]),
            reverse=True,
        )
        candidates_by_attack.append(
            [item[0] for item in candidates]
        )

    # Assign each finding to at most one planted attack.
    finding_to_attack = {}

    def assign(attack_index, seen_findings):
        for finding_index in candidates_by_attack[attack_index]:
            if finding_index in seen_findings:
                continue

            seen_findings.add(finding_index)
            previous_attack = finding_to_attack.get(finding_index)

            if (
                previous_attack is None
                or assign(previous_attack, seen_findings)
            ):
                finding_to_attack[finding_index] = attack_index
                return True

        return False

    # Give attacks with fewer possible matches priority. Prefer matching
    # campaigns with more source IPs first when candidate counts tie.
    attack_order = sorted(
        range(len(truth)),
        key=lambda i: (
            len(candidates_by_attack[i]),
            -len(set(attack_ips_list[i])),
        ),
    )

    for attack_index in attack_order:
        assign(attack_index, set())

    attack_to_finding = {
        attack_index: finding_index
        for finding_index, attack_index in finding_to_attack.items()
    }

    rows = []

    for attack_index, attack in enumerate(truth):
        ips = attack_ips_list[attack_index]
        finding_index = attack_to_finding.get(attack_index)
        finding = (
            findings[finding_index]
            if finding_index is not None
            else None
        )

        predicted = finding.label if finding is not None else None
        found = finding is not None

        rows.append({
            "id": attack["id"],
            "ip": ips[0],
            "n_ips": len(ips),
            "variant": attack.get("variant", "loud"),
            "planted": attack["type"],
            "found": found,
            "predicted": predicted,
            "correct_type": found and predicted == attack["type"],
        })

    matched_indices = set(finding_to_attack)
    false_alarms = [
        finding
        for index, finding in enumerate(findings)
        if index not in matched_indices
    ]

    causes = Counter()

    for finding in false_alarms:
        finding_ips = set(
            getattr(finding, "source_ips", []) or [finding.ip]
        )
        cause = "unexplained"

        for case in benign or []:
            case_start = datetime.fromisoformat(case["start"])
            case_end = datetime.fromisoformat(case["end"])

            if (
                finding_ips.intersection(case["ips"])
                and _overlap(
                    finding.start, finding.end, case_start, case_end
                )
            ):
                cause = case["type"]
                break

        causes[cause] += 1

    by_variant = defaultdict(lambda: [0, 0, 0])

    for row in rows:
        variant = by_variant[row["variant"]]
        variant[0] += 1
        variant[1] += row["found"]
        variant[2] += row["correct_type"]

    return {
        "rows": rows,
        "planted": len(truth),
        "detected": sum(row["found"] for row in rows),
        "correct_type": sum(row["correct_type"] for row in rows),
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
