from __future__ import annotations

import re
import unittest

from obpa_lab.registry import load_attack_register
from obpa_lab.scenarios import run_attack
from obpa_lab.types import OperationalResult, evaluate_oracle


ATTACKS = load_attack_register()


class AttackRegisterTests(unittest.TestCase):
    maxDiff = None


def _method_name(attack_id: int, title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")
    return f"test_attack_{attack_id:02d}_{slug}"


def _make_test(spec):
    def test(self):
        outcome = run_attack(spec.attack_id)
        evaluation = evaluate_oracle(spec, outcome)
        self.assertTrue(
            evaluation.passed,
            msg=(
                f"attack {spec.attack_id} failed its typed oracle: {evaluation.mismatches}; "
                f"outcome={outcome}"
            ),
        )
        self.assertEqual(outcome.consequence_count, 0, "an attack fixture committed a governed consequence")
        if spec.attack_id == 6:
            self.assertEqual(
                outcome.sequence,
                ["HOLD:SOURCE_STATUS_PENDING", "DENY:SOURCE_OBLIGATION_SUPERSEDED"],
            )
        if spec.attack_id == 49:
            self.assertEqual(
                outcome.operation_results,
                [OperationalResult.COMMITTED, OperationalResult.TRANSACTION_CONFLICT],
            )
            self.assertEqual(outcome.evidence.get("winner_count"), 1)
        if spec.attack_id == 53:
            self.assertIs(outcome.evidence.get("runtime_state_unchanged"), True)
        if spec.attack_id == 59:
            self.assertEqual(outcome.operational, OperationalResult.COMMIT_PRECONDITION_CONFLICT)
            self.assertFalse(outcome.committed)

    return test


for _spec in ATTACKS:
    setattr(AttackRegisterTests, _method_name(_spec.attack_id, _spec.title), _make_test(_spec))


class RegisterIntegrityTests(unittest.TestCase):
    def test_register_is_exactly_1_through_59(self):
        self.assertEqual([spec.attack_id for spec in ATTACKS], list(range(1, 60)))


if __name__ == "__main__":
    unittest.main()
