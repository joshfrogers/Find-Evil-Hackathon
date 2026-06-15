"""Tests for CLI argument parsing."""

import argparse
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cli.main import (
    _load_audit_events,
    _missing_catalog_message,
    _score_from_dict,
    build_evidence_specs,
    build_executor,
    cmd_compare_agents,
    cmd_investigate,
    cmd_refresh,
    cmd_score,
    load_catalog_tools,
)


class BuildExecutorTest(unittest.TestCase):
    def setUp(self):
        self.tools = [
            {"name": "fls", "path": "/usr/bin/fls", "description": "list files"},
        ]
        self.roots = ["/cases"]

    def test_local_executor_when_no_remote(self):
        from executor.runner import LocalExecutor

        ex = build_executor(self.tools, self.roots, remote=None)
        self.assertIsInstance(ex, LocalExecutor)

    def test_ssh_executor_with_remote(self):
        from executor.runner import SSHExecutor

        # user is now caller-supplied (no baked-in default) — thread it through.
        ex = build_executor(
            self.tools, self.roots, remote="localhost:5555", remote_user="analyst"
        )
        self.assertIsInstance(ex, SSHExecutor)
        self.assertEqual(ex._user, "analyst")

    def test_remote_without_port_exits(self):
        """A bare host with no port is now an error — no environment-specific
        port (5555) is baked in as a default."""
        with self.assertRaises(SystemExit):
            build_executor(
                self.tools, self.roots, remote="myhost", remote_user="analyst"
            )

    def test_invalid_port_exits(self):
        with self.assertRaises(SystemExit):
            build_executor(
                self.tools, self.roots, remote="localhost:abc", remote_user="analyst"
            )

    def test_remote_help_has_no_environment_identifiers(self):
        import cli.main as m

        text = m.__doc__ or ""
        for bad in ("5555", "sansforensics", "localhost:"):
            self.assertNotIn(bad, text)

    def test_build_executor_accepts_output_dir(self):
        import os

        from executor.runner import LocalExecutor

        d = tempfile.mkdtemp()
        out = os.path.join(d, "outputs")
        ex = build_executor(self.tools, self.roots, remote=None, output_dir=out)
        self.assertIsInstance(ex, LocalExecutor)
        self.assertTrue(os.path.isdir(out))  # Executor.__init__ creates output_dir


class BuildEvidenceSpecsTest(unittest.TestCase):
    def test_single_evidence_defaults_to_disk(self):
        specs = build_evidence_specs(["/cases/img.E01"], None)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].path, "/cases/img.E01")
        self.assertEqual(specs[0].evidence_type, "disk")

    def test_paired_evidence_and_types(self):
        specs = build_evidence_specs(
            ["/cases/img.E01", "/cases/mem.raw"], ["disk", "memory"]
        )
        self.assertEqual(
            [(s.path, s.evidence_type) for s in specs],
            [
                ("/cases/img.E01", "disk"),
                ("/cases/mem.raw", "memory"),
            ],
        )

    def test_missing_types_default_to_disk(self):
        # More evidence than types -> the unpaired items default to disk.
        specs = build_evidence_specs(["/cases/a.E01", "/cases/b.E01"], ["disk"])
        self.assertEqual([s.evidence_type for s in specs], ["disk", "disk"])

    def test_more_types_than_evidence_exits(self):
        with self.assertRaises(SystemExit):
            build_evidence_specs(["/cases/a.E01"], ["disk", "memory"])


class InvestigateCommandTest(unittest.TestCase):
    def test_errored_report_exits_nonzero(self):
        import cli.main as m

        class _Executor:
            def ensure_scratch(self):
                pass

            def cleanup_scratch(self):
                pass

        class _Investigator:
            def __init__(self, *args, **kwargs):
                pass

            def investigate_evidence(self, specs, focus=None, brief=None):
                return {
                    "status": "errored",
                    "rounds_completed": 0,
                    "findings": [],
                    "iocs": [],
                }

        orig_sudo = m._acquire_local_sudo_password
        orig_load = m.load_catalog_tools
        orig_stale = m._print_staleness
        orig_build = m.build_executor
        orig_inv = m.Investigator
        self.addCleanup(lambda: setattr(m, "_acquire_local_sudo_password", orig_sudo))
        self.addCleanup(lambda: setattr(m, "load_catalog_tools", orig_load))
        self.addCleanup(lambda: setattr(m, "_print_staleness", orig_stale))
        self.addCleanup(lambda: setattr(m, "build_executor", orig_build))
        self.addCleanup(lambda: setattr(m, "Investigator", orig_inv))
        m._acquire_local_sudo_password = lambda: None
        m.load_catalog_tools = lambda catalog: ([], Path("/tmp/tool_catalog.json"))
        m._print_staleness = lambda cat_path: None
        m.build_executor = lambda *args, **kwargs: _Executor()
        m.Investigator = _Investigator

        args = argparse.Namespace(
            fast=False,
            remote_mount=None,
            catalog=None,
            evidence_roots=None,
            output=None,
            remote=None,
            remote_user=None,
            focus=None,
            brief=None,
            brief_file=None,
            evidence=["/cases/missing.E01"],
            type=["disk"],
            max_rounds=1,
            baseline=None,
        )
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                cmd_investigate(args)
        self.assertEqual(ctx.exception.code, 1)

    def test_report_write_failure_exits_nonzero(self):
        import cli.main as m

        class _Executor:
            def ensure_scratch(self):
                pass

            def cleanup_scratch(self):
                pass

        class _Investigator:
            def __init__(self, *args, **kwargs):
                pass

            def investigate_evidence(self, specs, focus=None, brief=None):
                return {
                    "status": "completed",
                    "rounds_completed": 0,
                    "findings": [],
                    "iocs": [],
                    "error": "Report write failed: disk full",
                    "report_write_failed": True,
                }

        orig_sudo = m._acquire_local_sudo_password
        orig_load = m.load_catalog_tools
        orig_stale = m._print_staleness
        orig_build = m.build_executor
        orig_inv = m.Investigator
        self.addCleanup(lambda: setattr(m, "_acquire_local_sudo_password", orig_sudo))
        self.addCleanup(lambda: setattr(m, "load_catalog_tools", orig_load))
        self.addCleanup(lambda: setattr(m, "_print_staleness", orig_stale))
        self.addCleanup(lambda: setattr(m, "build_executor", orig_build))
        self.addCleanup(lambda: setattr(m, "Investigator", orig_inv))
        m._acquire_local_sudo_password = lambda: None
        m.load_catalog_tools = lambda catalog: ([], Path("/tmp/tool_catalog.json"))
        m._print_staleness = lambda cat_path: None
        m.build_executor = lambda *args, **kwargs: _Executor()
        m.Investigator = _Investigator

        args = argparse.Namespace(
            fast=False,
            remote_mount=None,
            catalog=None,
            evidence_roots=None,
            output=None,
            remote=None,
            remote_user=None,
            focus=None,
            brief=None,
            brief_file=None,
            evidence=["/cases/img.E01"],
            type=["disk"],
            max_rounds=1,
            baseline=None,
        )
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                cmd_investigate(args)
        self.assertEqual(ctx.exception.code, 1)


class LoadCatalogToolsTest(unittest.TestCase):
    def test_missing_catalog_exits(self):
        # D8 instruct-then-exit: a missing catalog must exit non-zero, NOT build
        # a seed (there is no shipped seed).
        with self.assertRaises(SystemExit):
            load_catalog_tools("/nonexistent/path/tool_catalog.json")

    def test_missing_catalog_message_names_path_and_refresh(self):
        # The message must name the checked path, the literal `agentic-sift
        # refresh`, the phrase "current directory", and the `--catalog` override.
        msg = _missing_catalog_message(Path("/home/me/cases/tool_catalog.json"))
        self.assertIn("/home/me/cases/tool_catalog.json", msg)
        self.assertIn("agentic-sift refresh", msg)
        self.assertIn("current directory", msg)
        self.assertIn("--catalog", msg)

    def test_loads_flat_tools_from_catalog(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        cat_path = Path(td.name) / "tool_catalog.json"
        cat_path.write_text(
            json.dumps(
                {
                    "metadata": {"refreshed_at": "2026-06-14T00:00:00Z"},
                    "tools": [
                        {
                            "name": "fls",
                            "path": "/usr/bin/fls",
                            "target_os": ["any"],
                        },
                        {
                            "name": "vol",
                            "path": "/usr/local/bin/vol",
                            "target_os": ["any"],
                        },
                    ],
                }
            )
        )

        tools, resolved = load_catalog_tools(str(cat_path))

        self.assertEqual(resolved, cat_path)
        self.assertEqual([t["name"] for t in tools], ["fls", "vol"])


class RefreshConcurrencyTest(unittest.TestCase):
    """`refresh` enriches the diff set concurrently (the one-time-build speed
    lever), drops relevance-filtered tools, skips unchanged tools, and writes the
    catalog once."""

    def test_enrichment_is_concurrent_and_filters(self):
        import threading

        from tool_registry import enrich as en
        from tool_registry import scanner as sc

        diff_tools = [
            {"name": "rip.pl", "path": "/usr/bin/rip.pl", "package": "", "source": "path"},
            {"name": "vol", "path": "/usr/local/bin/vol", "package": "", "source": "path"},
            {"name": "ls", "path": "/bin/ls", "package": "", "source": "path"},
        ]

        orig_enum = sc.enumerate_tools
        orig_bundle = en.build_signal_bundle
        orig_enrich = en.enrich_tool
        self.addCleanup(lambda: setattr(sc, "enumerate_tools", orig_enum))
        self.addCleanup(lambda: setattr(en, "build_signal_bundle", orig_bundle))
        self.addCleanup(lambda: setattr(en, "enrich_tool", orig_enrich))

        sc.enumerate_tools = lambda: diff_tools
        en.build_signal_bundle = lambda t: {"name": t.get("name", "")}

        live = {"cur": 0, "max": 0}
        lock = threading.Lock()
        # All three workers must be in-flight at once to clear the barrier; on
        # serial enrichment the first blocks here until timeout and max stays 1.
        barrier = threading.Barrier(3, timeout=5)

        def fake_enrich(
            tool, bundle, now="", model="claude", enriched_at="", trust_relevant=False
        ):
            with lock:
                live["cur"] += 1
                live["max"] = max(live["max"], live["cur"])
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
            with lock:
                live["cur"] -= 1
            if tool.get("name") == "ls":
                return None  # relevance filter drops coreutils noise
            return {
                "name": tool["name"],
                "path": tool.get("path", ""),
                "relevant": True,
                "target_os": ["any"],
                "input_types": [],
                "provenance": {},
            }

        en.enrich_tool = fake_enrich

        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        cat_path = Path(td.name) / "tool_catalog.json"
        args = argparse.Namespace(
            catalog=str(cat_path),
            overrides=str(Path(td.name) / "overrides.json"),
            seed_only=False,
            dry_run=False,
        )
        with redirect_stdout(io.StringIO()):
            cmd_refresh(args)

        self.assertEqual(live["max"], 3, "enrichment did not run concurrently")
        obj = json.loads(cat_path.read_text())
        # 'ls' dropped by the relevance filter; the other two written, once.
        self.assertEqual(sorted(t["name"] for t in obj["tools"]), ["rip.pl", "vol"])
        self.assertEqual(obj["metadata"]["tool_count"], 2)
        self.assertTrue(obj["metadata"]["installed_hash"])

    def test_dry_run_writes_nothing(self):
        from tool_registry import scanner as sc

        orig_enum = sc.enumerate_tools
        self.addCleanup(lambda: setattr(sc, "enumerate_tools", orig_enum))
        sc.enumerate_tools = lambda: [
            {"name": "fls", "path": "/usr/bin/fls", "package": "", "source": "path"}
        ]

        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        cat_path = Path(td.name) / "tool_catalog.json"
        args = argparse.Namespace(
            catalog=str(cat_path),
            overrides=str(Path(td.name) / "overrides.json"),
            seed_only=False,
            dry_run=True,
        )
        with redirect_stdout(io.StringIO()):
            cmd_refresh(args)
        self.assertFalse(cat_path.exists())


def _write_baseline(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "case_id": "cli-test",
                "evidence_image": "x.E01",
                "findings": [
                    {
                        "id": "B-1",
                        "description": "thing",
                        "ioc_type": "ip",
                        "ioc_value": "1.1.1.1",
                        "must_find": True,
                    }
                ],
            }
        )
    )


def _write_report(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": "F-1",
                        "description": "match",
                        "confidence": "confirmed",
                        "ioc_type": "ip",
                        "ioc_value": "1.1.1.1",
                        "evidence_links": ["e-1"],
                    }
                ]
            }
        )
    )


def _write_audit(path: Path) -> None:
    path.write_text(
        json.dumps(
            {"event_id": "e-1", "event_type": "tool_execution", "tool_name": "fls"}
        )
        + "\n"
    )


class LoadAuditEventsTest(unittest.TestCase):
    def test_missing_file_returns_empty(self):
        self.assertEqual(_load_audit_events(Path("/nonexistent.jsonl")), [])

    def test_jsonl_parsed(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "audit.jsonl"
        p.write_text('{"event_id":"a"}\n{"event_id":"b"}\n')
        events = _load_audit_events(p)
        self.assertEqual([e["event_id"] for e in events], ["a", "b"])

    def test_blank_lines_skipped(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "audit.jsonl"
        p.write_text('\n{"event_id":"a"}\n\n')
        events = _load_audit_events(p)
        self.assertEqual(len(events), 1)


class ScoreCommandTest(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = Path(td.name)
        self.report_path = self.dir / "report.json"
        self.audit_path = self.dir / "audit.jsonl"
        self.baseline_path = self.dir / "baseline.json"
        _write_report(self.report_path)
        _write_audit(self.audit_path)
        _write_baseline(self.baseline_path)

    def test_score_writes_accuracy_block(self):
        args = argparse.Namespace(
            report=str(self.report_path),
            baseline=str(self.baseline_path),
            audit=None,
            output=None,
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_score(args)
        scored = json.loads(self.report_path.read_text())
        self.assertIn("accuracy_score", scored)
        self.assertEqual(scored["accuracy_score"]["baseline_id"], "cli-test")
        self.assertEqual(scored["accuracy_score"]["precision"], 1.0)

    def test_score_writes_separate_output(self):
        out = self.dir / "scored.json"
        args = argparse.Namespace(
            report=str(self.report_path),
            baseline=str(self.baseline_path),
            audit=None,
            output=str(out),
        )
        with redirect_stdout(io.StringIO()):
            cmd_score(args)
        self.assertTrue(out.exists())
        # original is untouched
        original = json.loads(self.report_path.read_text())
        self.assertNotIn("accuracy_score", original)

    def test_score_renders_markdown(self):
        args = argparse.Namespace(
            report=str(self.report_path),
            baseline=str(self.baseline_path),
            audit=None,
            output=None,
        )
        with redirect_stdout(io.StringIO()):
            cmd_score(args)
        md = self.report_path.with_suffix(".md")
        self.assertTrue(md.exists())
        self.assertIn("Accuracy & Scoring", md.read_text())

    def test_score_missing_report_exits(self):
        args = argparse.Namespace(
            report="/nonexistent/report.json",
            baseline=str(self.baseline_path),
            audit=None,
            output=None,
        )
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()):
                cmd_score(args)

    def test_score_missing_baseline_exits(self):
        args = argparse.Namespace(
            report=str(self.report_path),
            baseline="/nonexistent/baseline.json",
            audit=None,
            output=None,
        )
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()):
                cmd_score(args)


class ScoreFromDictRoundTripTest(unittest.TestCase):
    def test_round_trip_through_dict(self):
        from accuracy.scorer import AccuracyScore

        original = AccuracyScore(
            baseline_id="x",
            total_agent_findings=3,
            total_baseline_findings=4,
            required_baseline_findings=4,
            precision=0.75,
            recall=0.5,
            f1=0.6,
            hallucination_rate=0.1,
            missed_baseline_findings=["B-1"],
            extra_findings=["F-9"],
            confirmed_vs_inferred={
                "confirmed": 2,
                "inferred": 1,
                "possible": 0,
                "other": 0,
            },
        )
        rebuilt = _score_from_dict(original.to_dict())
        self.assertEqual(rebuilt.baseline_id, "x")
        self.assertEqual(rebuilt.precision, 0.75)
        self.assertEqual(rebuilt.missed_baseline_findings, ["B-1"])
        self.assertEqual(rebuilt.confirmed_vs_inferred["confirmed"], 2)


class CompareBaselineCommandTest(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = Path(td.name)

    def _write_scored(self, path: Path, hallucination_rate: float) -> None:
        path.write_text(
            json.dumps(
                {
                    "findings": [],
                    "accuracy_score": {
                        "baseline_id": "c",
                        "total_agent_findings": 5,
                        "total_baseline_findings": 5,
                        "required_baseline_findings": 5,
                        "precision": 1.0,
                        "recall": 1.0,
                        "f1": 1.0,
                        "hallucination_rate": hallucination_rate,
                        "missed_baseline_findings": [],
                        "extra_findings": [],
                        "confirmed_vs_inferred": {},
                        "hallucinations_flagged": [],
                        "hallucinations_caught_by_verifier": [],
                    },
                }
            )
        )

    def test_compare_passes_when_lower_hallucination(self):
        subject = self.dir / "subject.json"
        reference = self.dir / "reference.json"
        self._write_scored(subject, 0.1)
        self._write_scored(reference, 0.3)
        args = argparse.Namespace(
            report=str(subject), reference_report=str(reference), output=None
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_compare_agents(args)
        self.assertIn("PASS", buf.getvalue())

    def test_compare_writes_output_with_block(self):
        subject = self.dir / "subject.json"
        reference = self.dir / "reference.json"
        out = self.dir / "out.json"
        self._write_scored(subject, 0.1)
        self._write_scored(reference, 0.3)
        args = argparse.Namespace(
            report=str(subject), reference_report=str(reference), output=str(out)
        )
        with redirect_stdout(io.StringIO()):
            cmd_compare_agents(args)
        data = json.loads(out.read_text())
        self.assertIn("baseline_comparison", data)
        self.assertTrue(data["baseline_comparison"]["passes"])

    def test_compare_missing_accuracy_block_exits(self):
        subject = self.dir / "subject.json"
        reference = self.dir / "reference.json"
        subject.write_text(json.dumps({"findings": []}))
        self._write_scored(reference, 0.3)
        args = argparse.Namespace(
            report=str(subject), reference_report=str(reference), output=None
        )
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()):
                cmd_compare_agents(args)

    def test_compare_missing_report_exits(self):
        args = argparse.Namespace(
            report="/nonexistent/a.json",
            reference_report="/nonexistent/b.json",
            output=None,
        )
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()):
                cmd_compare_agents(args)


class FastModeTest(unittest.TestCase):
    """`--fast` dials the run down via env (set-at-runtime, read at use-time)
    and caps rounds, without clobbering values an operator already exported."""

    def test_sets_speed_env_and_caps_rounds(self):
        import os

        from cli.main import _apply_fast_mode

        keys = [
            "AGENTIC_SIFT_MAX_HYPOTHESES",
            "AGENTIC_SIFT_VERIFIER_ROUNDS",
            "AGENTIC_SIFT_MAX_STEPS",
            "AGENTIC_SIFT_MAX_PARALLEL",
            "AGENTIC_SIFT_VERIFY_HIGH_VALUE_ONLY",
            "AGENTIC_SIFT_LLM_TIMEOUT",
        ]
        saved = {k: os.environ.pop(k, None) for k in keys}

        def _restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        self.addCleanup(_restore)
        args = argparse.Namespace(max_rounds=5)
        with redirect_stdout(io.StringIO()):
            _apply_fast_mode(args)
        self.assertEqual(args.max_rounds, 2)
        self.assertEqual(os.environ["AGENTIC_SIFT_VERIFIER_ROUNDS"], "1")
        self.assertEqual(os.environ["AGENTIC_SIFT_VERIFY_HIGH_VALUE_ONLY"], "1")
        self.assertEqual(os.environ["AGENTIC_SIFT_MAX_HYPOTHESES"], "3")

    def test_does_not_override_explicit_env(self):
        import os

        from cli.main import _apply_fast_mode

        # _apply_fast_mode sets several env vars via setdefault; snapshot and
        # restore all of them so this test can't leak state into later tests.
        keys = [
            "AGENTIC_SIFT_MAX_HYPOTHESES",
            "AGENTIC_SIFT_VERIFIER_ROUNDS",
            "AGENTIC_SIFT_MAX_STEPS",
            "AGENTIC_SIFT_MAX_PARALLEL",
            "AGENTIC_SIFT_VERIFY_HIGH_VALUE_ONLY",
            "AGENTIC_SIFT_LLM_TIMEOUT",
        ]
        saved = {k: os.environ.pop(k, None) for k in keys}
        os.environ["AGENTIC_SIFT_MAX_HYPOTHESES"] = "6"

        def _restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            os.environ.pop("AGENTIC_SIFT_MAX_HYPOTHESES", None)
            if saved["AGENTIC_SIFT_MAX_HYPOTHESES"] is not None:
                os.environ["AGENTIC_SIFT_MAX_HYPOTHESES"] = saved[
                    "AGENTIC_SIFT_MAX_HYPOTHESES"
                ]

        self.addCleanup(_restore)
        args = argparse.Namespace(max_rounds=1)
        with redirect_stdout(io.StringIO()):
            _apply_fast_mode(args)
        # An already-set value wins; rounds already below the cap stay.
        self.assertEqual(os.environ["AGENTIC_SIFT_MAX_HYPOTHESES"], "6")
        self.assertEqual(args.max_rounds, 1)
