from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .canonical import digest
from .registry import ATTACK_REGISTER_PATH, evidence_class_counts, load_attack_register
from .scenarios import run_attack, run_checker_disabled_control, run_positive_control
from .types import evaluate_oracle


def run(output: Path) -> int:
    attacks = load_attack_register()
    rows = []
    for spec in attacks:
        outcome = run_attack(spec.attack_id)
        evaluation = evaluate_oracle(spec, outcome)
        rows.append({
            "attack_id": spec.attack_id,
            "title": spec.title,
            "evidence_class": spec.evidence_class,
            "passed": evaluation.passed,
            "mismatches": list(evaluation.mismatches),
            "admission": outcome.admission.value,
            "operational": outcome.operational.value,
            "reason": outcome.reason,
            "failed_predicate": outcome.failed_predicate,
            "activated": outcome.activated,
            "committed": outcome.committed,
            "consequence_count": outcome.consequence_count,
            "engine_mode": outcome.engine_mode.value,
            "evidence": outcome.evidence,
        })
    positive = run_positive_control()
    disabled = run_checker_disabled_control()
    positive_ok = positive.committed and positive.consequence_count == 1
    disabled_ok = disabled.reason == "CHECKER_DISABLED" and disabled.engine_mode.value == "HALTED"
    report = {
        "schema_version": "1.0",
        "candidate": "v0.7-successor-candidate",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "python": platform.python_version(),
        "attack_register_digest": digest(json.loads(ATTACK_REGISTER_PATH.read_text(encoding="utf-8"))),
        "summary": {
            "attacks_total": len(attacks),
            "attacks_passed": sum(row["passed"] for row in rows),
            "attacks_failed": sum(not row["passed"] for row in rows),
            "positive_control_passed": positive_ok,
            "checker_disabled_control_passed": disabled_ok,
            "evidence_classes": evidence_class_counts(attacks),
        },
        "claim_ceiling": "Bounded harness evidence only; no safety, legitimacy, global non-bypassability, production-readiness or substantive-correctness claim.",
        "attacks": rows,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if report["summary"]["attacks_failed"] == 0 and positive_ok and disabled_ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the v0.7 OBPA Lab successor-candidate register")
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "run":
        return run(args.output)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
