# pyre-strict
"""Tests for the head-to-head baseline comparator (accuracy & scoring vs Protocol SIFT)."""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from accuracy.baseline_comparator import compare_against_baseline
from accuracy.scorer import AccuracyScore


def _score(
    baseline_id: str = "case-1",
    precision: float = 1.0,
    recall: float = 1.0,
    f1: float = 1.0,
    hallucination_rate: float = 0.0,
) -> AccuracyScore:
    return AccuracyScore(
        baseline_id=baseline_id,
        total_agent_findings=5,
        total_baseline_findings=5,
        required_baseline_findings=5,
        precision=precision,
        recall=recall,
        f1=f1,
        hallucination_rate=hallucination_rate,
    )


class CompareAgainstBaselineTest(unittest.TestCase):
    def test_passes_when_lower_hallucination_rate(self):
        subject = _score(hallucination_rate=0.10)
        reference = _score(hallucination_rate=0.30)
        report = compare_against_baseline(subject, reference)
        self.assertTrue(report.passes)
        self.assertEqual(report.hallucination_delta, 0.20)

    def test_passes_when_equal_hallucination_rate(self):
        subject = _score(hallucination_rate=0.15)
        reference = _score(hallucination_rate=0.15)
        report = compare_against_baseline(subject, reference)
        self.assertTrue(report.passes)

    def test_fails_when_higher_hallucination_rate(self):
        subject = _score(hallucination_rate=0.40)
        reference = _score(hallucination_rate=0.20)
        report = compare_against_baseline(subject, reference)
        self.assertFalse(report.passes)

    def test_precision_recall_f1_deltas_are_subject_minus_reference(self):
        subject = _score(precision=0.9, recall=0.8, f1=0.85)
        reference = _score(precision=0.7, recall=0.6, f1=0.65)
        report = compare_against_baseline(subject, reference)
        self.assertAlmostEqual(report.precision_delta, 0.2)
        self.assertAlmostEqual(report.recall_delta, 0.2)
        self.assertAlmostEqual(report.f1_delta, 0.2)

    def test_zero_rates_both_sides(self):
        report = compare_against_baseline(_score(), _score())
        self.assertTrue(report.passes)
        self.assertEqual(report.hallucination_delta, 0.0)

    def test_to_dict_is_serializable(self):
        report = compare_against_baseline(_score(), _score())
        d = report.to_dict()
        import json

        self.assertIn("passes", d)
        json.dumps(d)
