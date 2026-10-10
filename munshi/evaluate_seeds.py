"""Evaluate Munshi across multiple reproducible synthetic datasets."""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from .detectors import Config, detect
from .evaluate import score
from .parsing import parse_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def evaluate_seed(seed: int, hard: bool, mode_root: Path) -> dict:
    """Generate and evaluate one seed without touching baseline logs."""
    out_dir = mode_root / f"seed-{seed}"

    command = [
        sys.executable,
        str(PROJECT_ROOT / "generate_logs.py"),
        "--seed",
        str(seed),
        "--out-dir",
        str(out_dir),
    ]

    if hard:
        command.append("--hard")

    subprocess.run(command, cwd=PROJECT_ROOT, check=True)

    if hard:
        log_path = out_dir / "auth_hard.log"
        truth_path = out_dir / "ground_truth_hard.json"
        benign_path = out_dir / "benign_hard.json"
    else:
        log_path = out_dir / "auth.log"
        truth_path = out_dir / "ground_truth.json"
        benign_path = None

    parsed = parse_file(str(log_path))

    with truth_path.open(encoding="utf-8") as f:
        truth = json.load(f)

    benign = None
    if benign_path is not None:
        with benign_path.open(encoding="utf-8") as f:
            benign = json.load(f)

    findings = detect(parsed.events, Config())
    result = score(findings, truth, benign)

    return {
        "seed": seed,
        "events": len(parsed.events),
        "skipped": len(parsed.skipped),
        "findings": len(findings),
        "planted": result["planted"],
        "detected": result["detected"],
        "correct_type": result["correct_type"],
        "false_alarms": len(result["false_alarms"]),
        "false_alarm_causes": result["false_alarm_causes"],
        "by_variant": {
            name: {
                "planted": counts[0],
                "detected": counts[1],
                "correct_type": counts[2],
            }
            for name, counts in result["by_variant"].items()
        },
        "attack_results": result["rows"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate Munshi over multiple random seeds."
    )
    parser.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=list(range(42, 52)),
        help="unique integer seeds (default: 42 through 51)",
    )
    parser.add_argument(
        "--hard",
        action="store_true",
        help="evaluate hard datasets instead of easy datasets",
    )
    parser.add_argument(
        "--out-root",
        default="logs/multiseed",
        help="output directory for generated datasets and results",
    )
    args = parser.parse_args()

    if len(set(args.seeds)) != len(args.seeds):
        parser.error("--seeds values must be unique")

    out_root = Path(args.out_root)
    if not out_root.is_absolute():
        out_root = PROJECT_ROOT / out_root

    mode = "hard" if args.hard else "easy"
    mode_root = out_root / mode
    mode_root.mkdir(parents=True, exist_ok=True)

    reports = [
        evaluate_seed(seed, args.hard, mode_root)
        for seed in args.seeds
    ]

    total_planted = sum(r["planted"] for r in reports)
    total_detected = sum(r["detected"] for r in reports)
    total_correct = sum(r["correct_type"] for r in reports)
    total_false_alarms = sum(r["false_alarms"] for r in reports)
    total_findings = sum(r["findings"] for r in reports)

    aggregate_variants = defaultdict(lambda: [0, 0, 0])
    for report in reports:
        for name, counts in report["by_variant"].items():
            aggregate_variants[name][0] += counts["planted"]
            aggregate_variants[name][1] += counts["detected"]
            aggregate_variants[name][2] += counts["correct_type"]

    aggregate = {
        "datasets": len(reports),
        "total_planted": total_planted,
        "total_detected": total_detected,
        "detection_rate": (
            total_detected / total_planted if total_planted else 0
        ),
        "total_correct_type": total_correct,
        "correct_type_rate": (
            total_correct / total_planted if total_planted else 0
        ),
        "total_findings": total_findings,
        "total_false_alarms": total_false_alarms,
        "mean_false_alarms_per_dataset": (
            total_false_alarms / len(reports) if reports else 0
        ),
        "by_variant": {
            name: {
                "planted": counts[0],
                "detected": counts[1],
                "correct_type": counts[2],
            }
            for name, counts in aggregate_variants.items()
        },
    }

    summary = {
        "mode": mode,
        "seeds": args.seeds,
        "aggregate": aggregate,
        "per_seed": reports,
    }

    summary_path = mode_root / "summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print()
    print(f"Munshi multi-seed evaluation ({mode} mode)")
    print("-" * 76)
    print(
        f"{'Seed':>5} {'Events':>7} {'Findings':>9} "
        f"{'Planted':>8} {'Detected':>9} {'Correct':>8} {'False alarms':>13}"
    )

    for r in reports:
        print(
            f"{r['seed']:>5} {r['events']:>7} {r['findings']:>9} "
            f"{r['planted']:>8} {r['detected']:>9} "
            f"{r['correct_type']:>8} {r['false_alarms']:>13}"
        )

    print("-" * 76)
    print(f"Datasets evaluated   : {aggregate['datasets']}")
    print(f"Planted attacks      : {total_planted}")
    print(
        f"Detected attacks     : {total_detected} "
        f"({aggregate['detection_rate']:.1%})"
    )
    print(
        f"Correct classifications: {total_correct} "
        f"({aggregate['correct_type_rate']:.1%} of planted attacks)"
    )
    print(f"Total findings       : {total_findings}")
    print(f"Total false alarms   : {total_false_alarms}")
    print(
        f"Mean false alarms/run: "
        f"{aggregate['mean_false_alarms_per_dataset']:.2f}"
    )
    print(f"Detailed results     : {summary_path}")


if __name__ == "__main__":
    main()