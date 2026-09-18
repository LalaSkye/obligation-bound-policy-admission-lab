from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from obpa_lab.registry import evidence_class_counts, load_attack_register
from obpa_lab.scenarios import run_attack
from obpa_lab.types import AdmissionVerdict, EngineMode, Outcome, OperationalResult


class SuccessorIntegrityTests(unittest.TestCase):
    def test_outcome_labels_are_immutable(self):
        outcome = Outcome(AdmissionVerdict.HOLD, reason="ORIGINAL", failed_predicate="standing")
        with self.assertRaises(FrozenInstanceError):
            outcome.reason = "PAINTED"
        with self.assertRaises(FrozenInstanceError):
            outcome.failed_predicate = "painted_predicate"

    def test_attack_19_is_engine_derived_activation_integrity(self):
        outcome = run_attack(19)
        self.assertEqual(outcome.admission, AdmissionVerdict.DENY)
        self.assertEqual(outcome.operational, OperationalResult.HALTED)
        self.assertEqual(outcome.reason, "UNADMITTED_ACTIVE_POLICY")
        self.assertEqual(outcome.failed_predicate, "declared_activation_surface")
        self.assertEqual(outcome.engine_mode, EngineMode.HALTED)

    def test_attack_22_preserves_unknown_incumbent_without_fallback(self):
        outcome = run_attack(22)
        self.assertEqual(outcome.admission, AdmissionVerdict.HOLD)
        self.assertEqual(outcome.reason, "INCUMBENT_STANDING_UNKNOWN")
        self.assertEqual(outcome.failed_predicate, "incumbent_current_standing")

    def test_attack_33_derives_no_policy_standing_from_fallback(self):
        outcome = run_attack(33)
        self.assertEqual(outcome.admission, AdmissionVerdict.HOLD)
        self.assertEqual(outcome.reason, "NO_POLICY_STANDING")
        self.assertEqual(outcome.failed_predicate, "fallback_current_standing")

    def test_register_classifies_non_engine_cases_and_derives_counts(self):
        attacks = load_attack_register()
        by_id = {spec.attack_id: spec for spec in attacks}

        self.assertEqual(by_id[19].evidence_class, "ENGINE_DERIVED")
        self.assertEqual(by_id[33].evidence_class, "ENGINE_DERIVED")
        self.assertEqual(by_id[50].evidence_class, "META_TEST")
        for attack_id in (18, 20, 54):
            self.assertEqual(by_id[attack_id].evidence_class, "OUT_OF_SCOPE")
            self.assertEqual(run_attack(attack_id).evidence.get("evidence_class"), "OUT_OF_SCOPE")

        self.assertEqual(
            evidence_class_counts(attacks),
            {
                "ENGINE_DERIVED": 55,
                "META_TEST": 1,
                "OUT_OF_SCOPE": 3,
                "UNIMPLEMENTED_CANDIDATE": 0,
            },
        )


if __name__ == "__main__":
    unittest.main()
