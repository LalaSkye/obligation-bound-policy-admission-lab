from __future__ import annotations

import unittest

from obpa_lab.scenarios import run_checker_disabled_control, run_positive_control
from obpa_lab.types import AdmissionVerdict, EngineMode, OperationalResult


class HarnessControls(unittest.TestCase):
    def test_c1_fully_valid_record_commits_once(self):
        outcome = run_positive_control()
        self.assertEqual(outcome.admission, AdmissionVerdict.ALLOW)
        self.assertEqual(outcome.operational, OperationalResult.COMMITTED)
        self.assertTrue(outcome.committed)
        self.assertEqual(outcome.consequence_count, 1)

    def test_c2_checker_disabled_halts_build_path(self):
        outcome = run_checker_disabled_control()
        self.assertEqual(outcome.admission, AdmissionVerdict.DENY)
        self.assertEqual(outcome.reason, "CHECKER_DISABLED")
        self.assertEqual(outcome.engine_mode, EngineMode.HALTED)


if __name__ == "__main__":
    unittest.main()
