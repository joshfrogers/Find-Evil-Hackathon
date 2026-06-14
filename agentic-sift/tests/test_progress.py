"""Tests for the progress tracker."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from progress.tracker import ProgressTracker


class ProgressTrackerTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._path = Path(self._tmpdir) / "progress.json"
        self.tracker = ProgressTracker(self._path)
        self.tracker.start("inv-001", "/cases/image.E01", "disk")

    def test_start_creates_file(self):
        self.assertTrue(self._path.exists())
        with open(self._path) as f:
            data = json.load(f)
        self.assertEqual(data["investigation_id"], "inv-001")

    def test_hypothesis_lifecycle(self):
        self.tracker.add_hypothesis("H1", "Ransomware via phishing")
        self.assertEqual(len(self.tracker.active_hypotheses), 1)

        self.tracker.update_hypothesis(
            "H1", "refuted", evidence_against=["No email artifacts"]
        )
        self.assertEqual(len(self.tracker.active_hypotheses), 0)
        self.assertEqual(self.tracker.progress.hypotheses[0].status, "refuted")

    def test_record_failure(self):
        self.tracker.record_failure(
            "log2timeline",
            ["--parsers", "all"],
            "timeout after 300s",
            "Use targeted parsers",
        )
        self.assertIn("log2timeline", self.tracker.failed_tools)
        self.assertEqual(self.tracker.get_lessons(), ["Use targeted parsers"])

    def test_iteration_cap(self):
        self.tracker.start("inv-002", "/cases/img.E01", "disk", max_iterations=3)
        self.assertTrue(self.tracker.can_continue)
        self.assertTrue(self.tracker.increment_iteration())  # round 1
        self.assertTrue(self.tracker.increment_iteration())  # round 2
        self.assertFalse(self.tracker.increment_iteration())  # round 3 = limit
        self.assertFalse(self.tracker.can_continue)
        self.assertEqual(self.tracker.progress.status, "iteration_limit")

    def test_persistence_round_trip(self):
        self.tracker.add_hypothesis("H1", "Lateral movement via RDP")
        self.tracker.record_failure("vol", ["-f", "mem.raw"], "crash", "Check profile")
        self.tracker.record_pivot("broad triage", "focused RDP", "found RDP logs")
        self.tracker.increment_iteration()

        tracker2 = ProgressTracker(self._path)
        self.assertTrue(tracker2.load())
        self.assertEqual(tracker2.iteration, 1)
        self.assertEqual(len(tracker2.progress.hypotheses), 1)
        self.assertEqual(len(tracker2.progress.failed_approaches), 1)
        self.assertEqual(len(tracker2.progress.strategy_pivots), 1)

    def test_error_sets_errored_terminal_status(self):
        tmp = tempfile.mkdtemp()
        tracker = ProgressTracker(str(Path(tmp) / "progress.json"))
        tracker.start("inv-x", "/cases/img.E01", "disk")
        tracker.error()
        self.assertEqual(tracker.progress.status, "errored")

    def test_format_for_prompt(self):
        self.tracker.add_hypothesis("H1", "Malware persistence")
        self.tracker.record_failure("fls", ["-r"], "permission denied", "Run as root")
        output = self.tracker.format_for_prompt()
        self.assertIn("H1", output)
        self.assertIn("Malware persistence", output)
        self.assertIn("permission denied", output)
        self.assertIn("Run as root", output)


if __name__ == "__main__":
    unittest.main()
