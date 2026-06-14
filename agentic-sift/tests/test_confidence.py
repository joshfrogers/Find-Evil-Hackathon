# pyre-strict
"""Tests for deterministic confidence recalibration."""

import sys
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from verification.confidence import recalibrate


class ConfidenceRecalibrationTest(unittest.TestCase):
    def test_recalibrate_matrix(self):
        # (base_confidence, verdict, corroboration_count, expected_final)
        cases = [
            # Confirmed verdict: corroboration can raise, capped at confirmed.
            ("confirmed", "confirmed", 0, "confirmed"),
            ("confirmed", "confirmed", 3, "confirmed"),
            ("inferred", "confirmed", 1, "confirmed"),
            ("possible", "confirmed", 2, "inferred"),
            ("possible", "confirmed", 0, "possible"),
            # Downgraded verdict: one level down, floored, ignores corroboration.
            ("confirmed", "downgraded", 0, "inferred"),
            ("inferred", "downgraded", 0, "possible"),
            ("possible", "downgraded", 0, "possible"),
            ("confirmed", "downgraded", 5, "inferred"),
        ]
        for base, verdict, corro, expected in cases:
            with self.subTest(base=base, verdict=verdict, corro=corro):
                final, reason = recalibrate(base, verdict, corro)
                self.assertEqual(final, expected)
                self.assertTrue(reason)

    def test_refuted_preserves_base_and_flags_drop(self):
        final, reason = recalibrate("confirmed", "refuted", 0)
        self.assertEqual(final, "confirmed")
        self.assertIn("dropped", reason)

    def test_corroboration_never_exceeds_confirmed(self):
        final, _ = recalibrate("confirmed", "confirmed", 10)
        self.assertEqual(final, "confirmed")

    def test_unknown_base_treated_as_weakest(self):
        final, _ = recalibrate("bogus", "downgraded", 0)
        self.assertEqual(final, "possible")
