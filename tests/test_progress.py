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

    def test_open_hypotheses_includes_active_and_contested(self):
        # open_hypotheses drives the investigation loop: untested (active) AND
        # contested (unresolved) hypotheses stay open; supported/refuted are done.
        self.tracker.add_hypothesis("H1", "untested")
        self.tracker.add_hypothesis("H2", "conflicting evidence")
        self.tracker.add_hypothesis("H3", "clearly supported")
        self.tracker.add_hypothesis("H4", "clearly refuted")
        self.tracker.update_hypothesis("H2", "contested")
        self.tracker.update_hypothesis("H3", "supported")
        self.tracker.update_hypothesis("H4", "refuted")

        self.assertEqual({h.id for h in self.tracker.open_hypotheses}, {"H1", "H2"})
        # active_hypotheses stays strict (untested only).
        self.assertEqual({h.id for h in self.tracker.active_hypotheses}, {"H1"})

        # Once H2's follow-up has been spawned it is retired from the open set,
        # so it is never re-dispatched as an identical replay.
        for h in self.tracker.progress.hypotheses:
            if h.id == "H2":
                h.followup_spawned = True
        self.assertEqual({h.id for h in self.tracker.open_hypotheses}, {"H1"})

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

    def test_update_missing_hypothesis_does_not_raise(self):
        # A missing id must degrade gracefully (log + ignore), never crash the
        # orchestrator loop with a KeyError.
        self.tracker.update_hypothesis("H-nope", "supported")  # must not raise

    def test_status_property(self):
        self.assertEqual(self.tracker.status, "in_progress")
        self.tracker.complete()
        self.assertEqual(self.tracker.status, "completed")


class ProgressTrackerConcurrencyTest(unittest.TestCase):
    """All read-modify-write mutators must hold the lock: a worker's
    record_failure -> save() -> asdict() must not iterate a list another thread
    is concurrently appending to (RuntimeError: changed size during iteration)."""

    def test_concurrent_mutation_and_save_is_safe(self):
        import threading

        tmp = tempfile.mkdtemp()
        tracker = ProgressTracker(str(Path(tmp) / "progress.json"))
        tracker.start("inv-conc", "/cases/img.E01", "disk")

        errors: list[BaseException] = []
        barrier = threading.Barrier(3)

        def add_hypotheses() -> None:
            barrier.wait()
            try:
                for i in range(200):
                    tracker.add_hypothesis(f"H{i}", f"hypothesis {i}")
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        def record_failures() -> None:
            barrier.wait()
            try:
                for i in range(200):
                    tracker.record_failure(f"tool{i}", ["-x"], "boom", "lesson")
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        def record_pivots() -> None:
            barrier.wait()
            try:
                for i in range(200):
                    tracker.record_pivot("a", "b", f"reason {i}")
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [
            threading.Thread(target=add_hypotheses),
            threading.Thread(target=record_failures),
            threading.Thread(target=record_pivots),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"concurrent mutation raised: {errors}")
        self.assertEqual(len(tracker.progress.hypotheses), 200)
        self.assertEqual(len(tracker.progress.failed_approaches), 200)
        self.assertEqual(len(tracker.progress.strategy_pivots), 200)
        # The on-disk snapshot must still be valid JSON after the storm.
        with open(Path(tmp) / "progress.json") as f:
            json.load(f)


if __name__ == "__main__":
    unittest.main()
