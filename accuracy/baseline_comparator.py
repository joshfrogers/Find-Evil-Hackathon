# pyre-strict
"""Head-to-head comparison vs a reference agent (e.g. Protocol SIFT).

The SANS Find Evil! hackathon's stated success metric is "fewer hallucinated
findings than Protocol SIFT's baseline." This module compares two
``AccuracyScore`` results (subject vs reference, both scored against the same
ground truth) and reports whether the subject beats the reference.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from accuracy.scorer import AccuracyScore


@dataclass(frozen=True)
class ComparisonReport:
    """Side-by-side comparison of two scored reports.

    ``passes`` is True iff the subject hallucination rate is <= the reference's.
    Accuracy deltas are reported as ``subject - reference`` (positive = subject wins).
    """

    subject_baseline_id: str
    reference_baseline_id: str
    subject_hallucination_rate: float
    reference_hallucination_rate: float
    subject_precision: float
    reference_precision: float
    subject_recall: float
    reference_recall: float
    subject_f1: float
    reference_f1: float
    hallucination_delta: float
    precision_delta: float
    recall_delta: float
    f1_delta: float
    passes: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compare_against_baseline(
    subject: AccuracyScore, reference: AccuracyScore
) -> ComparisonReport:
    """Compare two scores. Both must be scored against the same case_id."""
    halluc_delta = round(
        reference.hallucination_rate - subject.hallucination_rate, 4
    )
    return ComparisonReport(
        subject_baseline_id=subject.baseline_id,
        reference_baseline_id=reference.baseline_id,
        subject_hallucination_rate=subject.hallucination_rate,
        reference_hallucination_rate=reference.hallucination_rate,
        subject_precision=subject.precision,
        reference_precision=reference.precision,
        subject_recall=subject.recall,
        reference_recall=reference.recall,
        subject_f1=subject.f1,
        reference_f1=reference.f1,
        hallucination_delta=halluc_delta,
        precision_delta=round(subject.precision - reference.precision, 4),
        recall_delta=round(subject.recall - reference.recall, 4),
        f1_delta=round(subject.f1 - reference.f1, 4),
        passes=subject.hallucination_rate <= reference.hallucination_rate,
    )
