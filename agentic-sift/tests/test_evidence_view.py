"""Tests for the evidence view — the analysis surface wrapper.

The view decides, per evidence type, whether the evidence is a mountable
filesystem image (mount it read-only and expose its roots) or a raw container
analyzed directly (memory dumps, packet captures, plain logs). It also owns the
teardown + integrity bracket. These tests inject a fake session so no real
mounting, privileged commands, or files are required.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evidence.session import IntegrityRecord, SpoliationError
from evidence.view import close_evidence, EvidenceView, open_evidence, TeardownResult


class _FakeSession:
    """Stand-in for EvidenceSession with scriptable open/close behavior."""

    last_init: dict = {}

    def __init__(self, image_path, *, runner, work_dir, executor=None):
        # Record construction so tests can assert what was threaded through.
        _FakeSession.last_init = {
            "image_path": image_path,
            "runner": runner,
            "work_dir": work_dir,
            "executor": executor,
        }
        self._image_path = image_path
        self.open_called = 0
        self.close_called = 0
        # Configurable behavior (set by the test before/after construction).
        self._roots = ["/mnt/agentic-sift/p1", "/mnt/agentic-sift/p2"]
        self._open_error: Exception | None = None
        self._close_error: Exception | None = None
        self._integrity = IntegrityRecord(
            image_path=image_path,
            before_sha256="abc",
            after_sha256="abc",
        )

    def open(self):
        self.open_called += 1
        if self._open_error is not None:
            raise self._open_error
        return self

    def close(self):
        self.close_called += 1
        if self._close_error is not None:
            raise self._close_error

    def roots(self):
        return list(self._roots)

    def integrity(self):
        return self._integrity


def _factory_returning(session_holder):
    """Build a session_factory that stashes the created fake for inspection."""

    def factory(image_path, *, runner, work_dir, executor=None):
        sess = _FakeSession(
            image_path, runner=runner, work_dir=work_dir, executor=executor
        )
        session_holder.append(sess)
        return sess

    return factory


class OpenEvidenceTest(unittest.TestCase):
    def test_memory_evidence_is_raw_only(self):
        created: list = []
        view = open_evidence(
            "/cases/mem.raw",
            "memory",
            session_factory=_factory_returning(created),
        )
        self.assertEqual(view.raw_path, "/cases/mem.raw")
        self.assertEqual(view.mount_roots, [])
        self.assertIsNone(view.session)
        self.assertFalse(view.is_mounted)
        # No filesystem to mount -> the session factory must not be touched.
        self.assertEqual(created, [])

    def test_pcap_and_logs_are_raw_only(self):
        for etype, path in (("pcap", "/cases/cap.pcapng"), ("logs", "/cases/x.log")):
            created: list = []
            view = open_evidence(
                path, etype, session_factory=_factory_returning(created)
            )
            self.assertFalse(view.is_mounted)
            self.assertEqual(created, [])

    def test_disk_evidence_is_mounted_and_exposes_roots(self):
        created: list = []
        view = open_evidence(
            "/cases/img.E01",
            "disk",
            work_dir="/tmp/wd",
            session_factory=_factory_returning(created),
        )
        self.assertTrue(view.is_mounted)
        self.assertEqual(
            view.mount_roots, ["/mnt/agentic-sift/p1", "/mnt/agentic-sift/p2"]
        )
        self.assertIsNotNone(view.session)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].open_called, 1)

    def test_directory_evidence_is_treated_as_premounted_root(self):
        # Pointing --evidence at a DIRECTORY means "this filesystem is already
        # mounted/extracted" — analyze it directly, with no ewfmount/losetup/root
        # (the portable path when EWF/libewf is unavailable). No mount session is
        # created and the executor is granted read access to the tree.
        created: list = []

        class _Ex:
            def __init__(self):
                self.roots: list = []

            def add_evidence_root(self, p):
                self.roots.append(p)

        ex = _Ex()
        d = tempfile.mkdtemp()
        try:
            view = open_evidence(
                d, "disk", executor=ex, session_factory=_factory_returning(created)
            )
            self.assertTrue(view.is_mounted)
            self.assertEqual(view.mount_roots, [d])
            self.assertIsNone(view.session)  # direct tree, no mount session
            self.assertEqual(view.raw_path, d)
            self.assertEqual(created, [])  # session factory NOT used
            self.assertIn(d, ex.roots)
        finally:
            os.rmdir(d)

    def test_executor_and_work_dir_are_threaded_to_session(self):
        created: list = []
        sentinel_executor = object()
        open_evidence(
            "/cases/img.E01",
            "disk",
            executor=sentinel_executor,
            work_dir="/tmp/custom-wd",
            session_factory=_factory_returning(created),
        )
        self.assertIs(_FakeSession.last_init["executor"], sentinel_executor)
        self.assertEqual(_FakeSession.last_init["work_dir"], "/tmp/custom-wd")

    def test_mount_failure_degrades_to_raw_only(self):
        created: list = []

        def failing_factory(image_path, *, runner, work_dir, executor=None):
            sess = _FakeSession(
                image_path, runner=runner, work_dir=work_dir, executor=executor
            )
            sess._open_error = RuntimeError("no driver for this filesystem")
            created.append(sess)
            return sess

        view = open_evidence(
            "/cases/weird.E01",
            "disk",
            work_dir="/tmp/wd",
            session_factory=failing_factory,
        )
        # Mounting failed, but Sleuth Kit can still read the raw image, so the
        # view degrades to raw-only rather than aborting the investigation.
        self.assertFalse(view.is_mounted)
        self.assertEqual(view.raw_path, "/cases/weird.E01")
        self.assertIsNone(view.session)

    def test_open_failure_cleans_up_work_dir_it_created(self):
        # When open_evidence creates its own temp work_dir and the mount fails,
        # that directory must be removed rather than leaked.
        created_dir = tempfile.mkdtemp()

        def failing_factory(image_path, *, runner, work_dir, executor=None):
            sess = _FakeSession(
                image_path, runner=runner, work_dir=work_dir, executor=executor
            )
            sess._open_error = RuntimeError("mount failed")
            return sess

        with patch("evidence.view.tempfile.mkdtemp", return_value=created_dir):
            view = open_evidence(
                "/cases/x.E01", "disk", session_factory=failing_factory
            )
        self.assertFalse(view.is_mounted)
        self.assertFalse(os.path.exists(created_dir))

    def test_open_failure_keeps_caller_provided_work_dir(self):
        # A caller-supplied work_dir is the caller's to manage — never delete it.
        caller_dir = tempfile.mkdtemp()

        def failing_factory(image_path, *, runner, work_dir, executor=None):
            sess = _FakeSession(
                image_path, runner=runner, work_dir=work_dir, executor=executor
            )
            sess._open_error = RuntimeError("mount failed")
            return sess

        view = open_evidence(
            "/cases/x.E01",
            "disk",
            work_dir=caller_dir,
            session_factory=failing_factory,
        )
        self.assertFalse(view.is_mounted)
        self.assertTrue(os.path.exists(caller_dir))
        os.rmdir(caller_dir)


class CloseEvidenceTest(unittest.TestCase):
    def test_close_raw_only_view_is_a_noop(self):
        view = EvidenceView(raw_path="/cases/mem.raw")
        result = close_evidence(view)
        self.assertIsInstance(result, TeardownResult)
        self.assertIsNone(result.integrity)
        self.assertIsNone(result.spoliation)

    def test_close_mounted_view_tears_down_and_returns_integrity(self):
        created: list = []
        view = open_evidence(
            "/cases/img.E01",
            "disk",
            work_dir="/tmp/wd",
            session_factory=_factory_returning(created),
        )
        result = close_evidence(view)
        self.assertEqual(created[0].close_called, 1)
        self.assertIsNotNone(result.integrity)
        self.assertTrue(result.integrity.verified)
        self.assertIsNone(result.spoliation)

    def test_close_reports_spoliation_instead_of_raising(self):
        created: list = []
        view = open_evidence(
            "/cases/img.E01",
            "disk",
            work_dir="/tmp/wd",
            session_factory=_factory_returning(created),
        )
        created[0]._close_error = SpoliationError("hash changed: abc -> def")
        # A changed hash must not crash teardown — it is captured so the report
        # can flag the evidence as compromised.
        result = close_evidence(view)
        self.assertIsNotNone(result.spoliation)
        self.assertIn("hash changed", result.spoliation)


if __name__ == "__main__":
    unittest.main()
