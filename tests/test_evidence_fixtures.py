# pyre-strict
"""WS5b: evidence-type regression harness.

For each evidence type we record a snapshot (report.json + audit.jsonl) and
the ground-truth baseline, then assert the scorer's output stays within
known-good bounds. If a prompt change or refactor silently degrades
detection on a previously-passing image, these tests fail before we ship.

To add a new evidence type:

  1. Capture a clean investigation run on the new image, copy ``report.json``
     and ``audit.jsonl`` into ``tests/fixtures/snapshots/<case_id>/``.
  2. Author the matching baseline at
     ``tests/fixtures/baselines/<case_id>.json``.
  3. Append a new ``EvidenceFixture`` entry to ``FIXTURES`` below.

The pattern keeps fixtures additive — no shared mutable state — so scaling
to a fleet of evidence types is just dropping in files.
"""

from __future__ import annotations

import json
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from accuracy.baseline import load_baseline
from accuracy.scorer import score_report

FIXTURES_DIR: Path = Path(__file__).parent / "fixtures"


@dataclass(frozen=True)
class EvidenceFixture:
    """One evidence-type regression entry.

    Thresholds are intentionally permissive at v0 (the agent improves over
    time); tighten them once the snapshot is taken from a verified-good run.
    """

    case_id: str
    min_precision: float
    min_recall: float
    min_f1: float
    max_hallucination_rate: float
    min_caught_hallucinations: int = 0


FIXTURES: list[EvidenceFixture] = [
    EvidenceFixture(
        case_id="sample-case",
        min_precision=0.80,
        min_recall=0.70,
        min_f1=0.75,
        max_hallucination_rate=0.05,
        min_caught_hallucinations=1,
    ),
]


def _load_snapshot(case_id: str) -> tuple[dict, list[dict]]:
    snap = FIXTURES_DIR / "snapshots" / case_id
    report = json.loads((snap / "report.json").read_text())
    events: list[dict] = []
    audit_path = snap / "audit.jsonl"
    if audit_path.exists():
        for line in audit_path.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return report, events


class EvidenceFixturesTest(unittest.TestCase):
    def _assert_fixture(self, fx: EvidenceFixture) -> None:
        baseline_path = FIXTURES_DIR / "baselines" / f"{fx.case_id}.json"
        baseline = load_baseline(baseline_path)
        report, events = _load_snapshot(fx.case_id)
        score = score_report(report, events, baseline)

        msg = (
            f"[{fx.case_id}] precision={score.precision:.3f} "
            f"recall={score.recall:.3f} f1={score.f1:.3f} "
            f"hallucination_rate={score.hallucination_rate:.3f} "
            f"missed={score.missed_baseline_findings} "
            f"extra={score.extra_findings} "
            f"flagged={len(score.hallucinations_flagged)} "
            f"caught={len(score.hallucinations_caught_by_verifier)}"
        )

        self.assertGreaterEqual(score.precision, fx.min_precision, msg)
        self.assertGreaterEqual(score.recall, fx.min_recall, msg)
        self.assertGreaterEqual(score.f1, fx.min_f1, msg)
        self.assertLessEqual(score.hallucination_rate, fx.max_hallucination_rate, msg)
        self.assertGreaterEqual(
            len(score.hallucinations_caught_by_verifier),
            fx.min_caught_hallucinations,
            msg,
        )

    def test_sample_case_snapshot(self):
        self._assert_fixture(FIXTURES[0])

    def test_all_baselines_load(self):
        """Every checked-in baseline parses cleanly — schema sanity check."""
        baselines_dir = FIXTURES_DIR / "baselines"
        files = list(baselines_dir.glob("*.json"))
        self.assertGreater(len(files), 0, "expected at least one baseline fixture")
        for p in files:
            with self.subTest(baseline=p.name):
                b = load_baseline(p)
                self.assertTrue(b.case_id, f"{p.name}: case_id must be set")
                self.assertGreater(
                    len(b.findings), 0, f"{p.name}: baseline must have findings"
                )

    def test_every_fixture_has_snapshot_and_baseline(self):
        """Every entry in FIXTURES has matching files on disk."""
        for fx in FIXTURES:
            with self.subTest(case_id=fx.case_id):
                baseline = FIXTURES_DIR / "baselines" / f"{fx.case_id}.json"
                snap_report = FIXTURES_DIR / "snapshots" / fx.case_id / "report.json"
                self.assertTrue(baseline.exists(), f"missing baseline: {baseline}")
                self.assertTrue(
                    snap_report.exists(), f"missing snapshot: {snap_report}"
                )
