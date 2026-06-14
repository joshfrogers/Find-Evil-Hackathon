# pyre-strict
"""Accuracy & scoring framework.

Scores investigation reports against ground-truth baselines, detects
hallucinated findings by cross-checking against the audit log, and produces
a head-to-head comparison vs reference agents (e.g. Protocol SIFT).
"""

from __future__ import annotations

from accuracy.baseline import Baseline, BaselineFinding, load_baseline
from accuracy.baseline_comparator import compare_against_baseline, ComparisonReport
from accuracy.hallucination import detect_hallucinations, HallucinationFlag
from accuracy.scorer import AccuracyScore, MatchedFinding, score_report

__all__ = [
    "AccuracyScore",
    "Baseline",
    "BaselineFinding",
    "ComparisonReport",
    "HallucinationFlag",
    "MatchedFinding",
    "compare_against_baseline",
    "detect_hallucinations",
    "load_baseline",
    "score_report",
]
