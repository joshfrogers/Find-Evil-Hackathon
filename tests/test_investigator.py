"""Tests for the orchestrator/investigator."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.base import AgentResult, Finding
from agents.claude import ClaudeError
from evidence.session import IntegrityRecord
from evidence.view import EvidenceSpec, EvidenceView, TeardownResult
from executor.runner import ExecutionResult, LocalExecutor
from orchestrator.investigator import (
    _CHARACTERIZATION_MISSION,
    Investigator,
    is_novel_hypothesis,
)


def _make_exec_result(**kwargs) -> ExecutionResult:
    defaults = {
        "execution_id": "e001",
        "tool": "/usr/bin/mmls",
        "argv": ["/usr/bin/mmls", "/cases/img.E01"],
        "cwd": "/tmp",
        "exit_code": 0,
        "duration_ms": 200,
        "stdout": "DOS Partition Table\nOffset: 0000000000",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "timestamp": "2026-05-21T00:00:00Z",
    }
    defaults.update(kwargs)
    return ExecutionResult(**defaults)


def _make_finding(**kwargs) -> Finding:
    defaults = {
        "finding_id": "F-test001",
        "description": "Suspicious executable in /tmp",
        "confidence": "confirmed",
        "evidence_links": ["exec-001"],
        "agent_name": "disk_agent",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class InvestigatorInitTest(unittest.TestCase):
    def test_creates_output_dir(self):
        tmpdir = tempfile.mkdtemp()
        output = Path(tmpdir) / "inv-test"
        executor = MagicMock(spec=LocalExecutor)

        Investigator(executor, [], str(output))

        self.assertTrue(output.exists())

    def test_assigns_unique_investigation_id(self):
        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)

        inv1 = Investigator(executor, [], str(Path(tmpdir) / "inv1"))
        inv2 = Investigator(executor, [], str(Path(tmpdir) / "inv2"))

        self.assertNotEqual(inv1.investigation_id, inv2.investigation_id)


class HypothesisEvaluationTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.inv = Investigator(
            self.executor, [], str(Path(self._tmpdir) / "inv"), max_rounds=3
        )
        self.inv._brief = None

    def test_evaluate_filters_by_hypothesis_id(self):
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.add_hypothesis("H1", "Malware persistence")
        self.inv.progress.add_hypothesis("H2", "Data exfiltration")

        f1 = Finding.new("Run key found", "confirmed", ["e1"], agent_name="disk_agent")
        f1.hypothesis_id = "H1"

        f2 = Finding.new("No FTP traffic", "confirmed", ["e2"], agent_name="net_agent")
        f2.hypothesis_id = "H2"
        f2.verification_verdict = "refuted"

        self.inv._evaluate_hypotheses([f1, f2])

        h1 = next(h for h in self.inv.progress.progress.hypotheses if h.id == "H1")
        h2 = next(h for h in self.inv.progress.progress.hypotheses if h.id == "H2")

        self.assertEqual(h1.status, "supported")
        self.assertEqual(h2.status, "refuted")

    def test_mixed_evidence_records_both_and_marks_contested(self):
        # A hypothesis supported AND contradicted in the same round must not be
        # reported as cleanly "supported" with the contradictions dropped — the
        # report has to show both sides.
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.add_hypothesis("H1", "Malware persistence")

        sup = Finding.new("Run key present", "confirmed", ["e1"])
        sup.hypothesis_id = "H1"
        con = Finding.new("But the binary is MS-signed", "confirmed", ["e2"])
        con.hypothesis_id = "H1"
        con.verification_verdict = "refuted"

        self.inv._evaluate_hypotheses([sup, con])

        h1 = next(h for h in self.inv.progress.progress.hypotheses if h.id == "H1")
        self.assertEqual(h1.status, "contested")
        self.assertTrue(h1.evidence_for)
        self.assertTrue(h1.evidence_against)

    def test_contested_hypothesis_is_reevaluated(self):
        # Regression: _evaluate_hypotheses used to iterate only strictly-"active"
        # hypotheses, so a "contested" one was never revisited — the run ended
        # with unused round budget. It must now re-evaluate contested hypotheses
        # so a later round's findings can resolve them.
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.add_hypothesis("H1", "Malware persistence")
        self.inv.progress.update_hypothesis("H1", "contested")

        sup = Finding.new("Confirmed persistence via Run key", "confirmed", ["e9"])
        sup.hypothesis_id = "H1"
        self.inv._evaluate_hypotheses([sup])

        h1 = next(h for h in self.inv.progress.progress.hypotheses if h.id == "H1")
        self.assertEqual(h1.status, "supported")

    def test_contested_hypothesis_spawns_followup_and_is_retired(self):
        # Churn guard (3a): a contested hypothesis spawns a focused active
        # follow-up and is retired from re-dispatch, so the next round does NEW
        # work on the conflict instead of replaying the same dispatch.
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.add_hypothesis("H1", "System used as hacking platform")
        self.inv.progress.update_hypothesis(
            "H1",
            "contested",
            evidence_for=["Mr. Evil profile present"],
            evidence_against=["binary is MS-signed"],
        )

        self.assertEqual(self.inv._spawn_contested_followups(), 1)

        h1 = next(h for h in self.inv.progress.progress.hypotheses if h.id == "H1")
        self.assertTrue(h1.followup_spawned)
        self.assertEqual(h1.status, "contested")  # status kept for the report

        followups = [
            h
            for h in self.inv.progress.progress.hypotheses
            if h.status == "active" and h.id != "H1"
        ]
        self.assertEqual(len(followups), 1)
        self.assertIn("H1", followups[0].description)

        # open_hypotheses now drives the next round: the follow-up is open, the
        # retired contested original is not (no replay).
        open_ids = {h.id for h in self.inv.progress.open_hypotheses}
        self.assertIn(followups[0].id, open_ids)
        self.assertNotIn("H1", open_ids)

    def test_spawn_followups_is_idempotent(self):
        # Running the spawn step again must not keep adding follow-ups for the
        # same contested hypothesis (no unbounded growth / no per-round replay).
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.add_hypothesis("H1", "X")
        self.inv.progress.update_hypothesis("H1", "contested")
        self.assertEqual(self.inv._spawn_contested_followups(), 1)
        self.assertEqual(self.inv._spawn_contested_followups(), 0)

    def test_evaluate_skips_hypothesis_with_no_findings(self):
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.add_hypothesis("H1", "Malware")
        self.inv.progress.add_hypothesis("H2", "Exfil")

        f1 = Finding.new("Found malware", "confirmed", ["e1"])
        f1.hypothesis_id = "H1"

        self.inv._evaluate_hypotheses([f1])

        h1 = next(h for h in self.inv.progress.progress.hypotheses if h.id == "H1")
        h2 = next(h for h in self.inv.progress.progress.hypotheses if h.id == "H2")

        self.assertEqual(h1.status, "supported")
        self.assertEqual(h2.status, "active")


class BriefInjectionTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.executor.run.return_value = _make_exec_result()
        self.tools = [
            {
                "name": "mmls",
                "path": "/usr/bin/mmls",
                "description": "Display partition layout",
                "category": "disk_forensics",
            }
        ]

    @patch("orchestrator.investigator.call_claude_json")
    def test_brief_appears_in_hypothesis_prompt(self, mock_claude):
        mock_claude.return_value = {
            "hypotheses": [
                {
                    "id": "H1",
                    "description": "Insider exfiltration via USB",
                    "domains_to_investigate": ["disk"],
                    "reasoning": "Brief mentions USB",
                }
            ]
        }

        inv = Investigator(self.executor, self.tools, str(Path(self._tmpdir) / "inv"))
        inv._brief = "Insider threat: USB exfiltration suspected"
        inv.progress.start("inv-test", "/cases/img.E01", "disk")

        inv._form_hypotheses("triage output", "disk", None)

        prompt = mock_claude.call_args[0][0]
        self.assertIn("Insider threat: USB exfiltration suspected", prompt)
        self.assertIn("Case briefing from the analyst", prompt)

    @patch("orchestrator.investigator.call_claude_json")
    def test_no_brief_omits_briefing_section(self, mock_claude):
        mock_claude.return_value = {"hypotheses": []}

        inv = Investigator(self.executor, self.tools, str(Path(self._tmpdir) / "inv"))
        inv._brief = None
        inv.progress.start("inv-test", "/cases/img.E01", "disk")

        inv._form_hypotheses("triage output", "disk", None)

        prompt = mock_claude.call_args[0][0]
        self.assertNotIn("Case briefing", prompt)

    def test_brief_saved_in_report(self):
        inv = Investigator(self.executor, self.tools, str(Path(self._tmpdir) / "inv"))
        inv._brief = "Test brief content"
        inv.progress.start("inv-test", "/cases/img.E01", "disk")
        inv.progress.complete()

        report = inv._generate_report("/cases/img.E01", "disk")

        self.assertEqual(report["brief"], "Test brief content")

    def test_no_brief_saved_as_empty_string(self):
        inv = Investigator(self.executor, self.tools, str(Path(self._tmpdir) / "inv"))
        inv._brief = None
        inv.progress.start("inv-test", "/cases/img.E01", "disk")
        inv.progress.complete()

        report = inv._generate_report("/cases/img.E01", "disk")

        self.assertEqual(report["brief"], "")


class CorrelationIntegrationTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.tools = [
            {
                "name": "mmls",
                "path": "/usr/bin/mmls",
                "description": "Display partition layout",
                "category": "disk_forensics",
            }
        ]
        self.investigator = Investigator(
            self.executor, self.tools, str(Path(self._tmpdir) / "inv")
        )
        self.investigator._brief = None
        self.investigator.progress.start("inv-test", "/fake/path", "disk")
        self.investigator.progress.complete()

    def test_report_contains_correlation_section(self):
        report = self.investigator._generate_report("/fake/path", "disk")
        self.assertIn("correlation", report)
        self.assertIn("timeline", report["correlation"])
        self.assertIn("event_chains", report["correlation"])
        self.assertIn("timeline_gaps", report["correlation"])


class TriageTest(unittest.TestCase):
    def test_triage_runs_correct_tools_for_disk(self):
        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        executor.run.return_value = _make_exec_result()

        tools = [
            {
                "name": "mmls",
                "path": "/usr/bin/mmls",
                "description": "partitions",
                "category": "disk_forensics",
            },
            {
                "name": "fsstat",
                "path": "/usr/bin/fsstat",
                "description": "fs stats",
                "category": "disk_forensics",
            },
            {
                "name": "img_stat",
                "path": "/usr/bin/img_stat",
                "description": "image stats",
                "category": "disk_forensics",
            },
            {
                "name": "vol",
                "path": "/usr/local/bin/vol",
                "description": "volatility",
                "category": "memory_analysis",
            },
        ]

        inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))
        inv._run_triage(EvidenceView(raw_path="/cases/img.E01"), "disk")

        called_tools = [
            call.kwargs.get("tool_path", call.args[0] if call.args else "")
            for call in executor.run.call_args_list
        ]
        self.assertEqual(executor.run.call_count, 3)
        self.assertNotIn("/usr/local/bin/vol", called_tools)

    def test_triage_runs_raw_tools_against_raw_path(self):
        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        executor.run.return_value = _make_exec_result()
        tools = [
            {
                "name": "mmls",
                "path": "/usr/bin/mmls",
                "description": "partitions",
                "category": "disk_forensics",
            }
        ]
        inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))
        # Even when the image is mounted, triage tools that read the raw
        # container (mmls) must still receive the raw image path, not a mount.
        view = EvidenceView(raw_path="/cases/img.E01", mount_roots=["/mnt/sift/p1"])
        inv._run_triage(view, "disk")
        argv = executor.run.call_args_list[0]
        passed_args = argv.kwargs.get("args", [])
        self.assertIn("/cases/img.E01", passed_args)

    def test_triage_surfaces_mounted_filesystems(self):
        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        executor.run.return_value = _make_exec_result()
        inv = Investigator(executor, [], str(Path(tmpdir) / "inv"))

        class _Sess:
            os = "Windows"

        view = EvidenceView(
            raw_path="/cases/img.E01",
            mount_roots=["/mnt/sift/p1", "/mnt/sift/p2"],
            session=_Sess(),
        )
        triage = inv._run_triage(view, "disk")
        # The mounted roots and detected OS are made visible to hypothesis
        # formation without running a tool to discover them.
        self.assertIn("/mnt/sift/p1", triage)
        self.assertIn("/mnt/sift/p2", triage)
        self.assertIn("Windows", triage)

    def test_triage_exit_failure_does_not_blocklist_tool(self):
        # Triage runs tools with fixed arguments (e.g. a fixed partition offset)
        # that can be wrong for a given image. Such a failure must NOT poison the
        # shared advisor and block the tool, or every sub-agent that needs it
        # (with the correct arguments) will skip it and find nothing.
        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        executor.run.return_value = _make_exec_result(
            exit_code=1, stderr="Cannot determine file system type"
        )
        tools = [
            {
                "name": "fls",
                "path": "/usr/bin/fls",
                "description": "list files",
                "category": "disk_forensics",
            }
        ]
        inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))
        inv._run_triage(EvidenceView(raw_path="/cases/img.E01"), "disk")
        self.assertFalse(inv.advisor.is_known_bad("/usr/bin/fls"))

    def test_triage_success_credits_tool(self):
        # A tool that works in triage is still credited so the advisor knows it
        # runs on this image.
        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        executor.run.return_value = _make_exec_result(exit_code=0)
        tools = [
            {
                "name": "fls",
                "path": "/usr/bin/fls",
                "description": "list files",
                "category": "disk_forensics",
            }
        ]
        inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))
        inv._run_triage(EvidenceView(raw_path="/cases/img.E01"), "disk")
        self.assertEqual(inv.advisor.matrix()["/usr/bin/fls"]["successes"], 1)

    def test_triage_uses_partition_offset_from_session(self):
        # Triage tools that take an offset must use the real partition start
        # (from the enumerated volumes), not a hardcoded 0 that fails on any
        # partitioned image.
        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        executor.run.return_value = _make_exec_result()
        tools = [
            {
                "name": "fls",
                "path": "/usr/bin/fls",
                "description": "list files",
                "category": "disk_forensics",
            }
        ]
        inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))

        class _Vol:
            start_sector = 2048

        class _Sess:
            os = "Windows"

            def volumes(self):
                return [_Vol()]

        view = EvidenceView(
            raw_path="/cases/img.E01", mount_roots=["/mnt/p1"], session=_Sess()
        )
        inv._run_triage(view, "disk")
        self.assertEqual(
            executor.run.call_args.kwargs["args"],
            ["-o", "2048", "/cases/img.E01"],
        )

    def test_triage_offset_defaults_to_zero_without_session(self):
        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        executor.run.return_value = _make_exec_result()
        tools = [
            {
                "name": "fls",
                "path": "/usr/bin/fls",
                "description": "list files",
                "category": "disk_forensics",
            }
        ]
        inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))
        inv._run_triage(EvidenceView(raw_path="/cases/img.E01"), "disk")
        self.assertEqual(
            executor.run.call_args.kwargs["args"],
            ["-o", "0", "/cases/img.E01"],
        )


class EvidenceLifecycleTest(unittest.TestCase):
    """investigate() opens the evidence view, threads it through, and closes it."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.executor.run.return_value = _make_exec_result()

    def _opener(self, view, teardown, calls):
        def opener(evidence_path, evidence_type, *, executor=None, runner=None):
            calls.append(
                {
                    "evidence_path": evidence_path,
                    "evidence_type": evidence_type,
                    "executor": executor,
                }
            )
            return view

        return opener

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_investigate_opens_and_closes_view(self, mock_claude, mock_close):
        mock_claude.return_value = {"hypotheses": []}
        mock_close.return_value = TeardownResult()
        calls: list = []
        view = EvidenceView(raw_path="/cases/img.E01")
        inv = Investigator(
            self.executor,
            [],
            str(Path(self._tmpdir) / "inv"),
            evidence_opener=self._opener(view, None, calls),
        )
        inv.investigate(evidence_path="/cases/img.E01", evidence_type="disk")

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["evidence_path"], "/cases/img.E01")
        self.assertIs(calls[0]["executor"], self.executor)
        mock_close.assert_called_once_with(view)

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_report_includes_integrity_section(self, mock_claude, mock_close):
        mock_claude.return_value = {"hypotheses": []}
        mock_close.return_value = TeardownResult(
            integrity=IntegrityRecord(
                image_path="/cases/img.E01",
                before_sha256="abc",
                after_sha256="abc",
            )
        )
        calls: list = []
        view = EvidenceView(raw_path="/cases/img.E01", mount_roots=["/mnt/sift/p1"])
        inv = Investigator(
            self.executor,
            [],
            str(Path(self._tmpdir) / "inv"),
            evidence_opener=self._opener(view, None, calls),
        )
        report = inv.investigate(evidence_path="/cases/img.E01", evidence_type="disk")
        self.assertIn("integrity", report)
        self.assertTrue(report["integrity"]["checked"])
        self.assertTrue(report["integrity"]["verified"])

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_report_flags_spoliation(self, mock_claude, mock_close):
        mock_claude.return_value = {"hypotheses": []}
        mock_close.return_value = TeardownResult(
            integrity=IntegrityRecord(
                image_path="/cases/img.E01",
                before_sha256="abc",
                after_sha256="def",
            ),
            spoliation="hash changed: abc -> def",
        )
        calls: list = []
        view = EvidenceView(raw_path="/cases/img.E01", mount_roots=["/mnt/sift/p1"])
        inv = Investigator(
            self.executor,
            [],
            str(Path(self._tmpdir) / "inv"),
            evidence_opener=self._opener(view, None, calls),
        )
        report = inv.investigate(evidence_path="/cases/img.E01", evidence_type="disk")
        self.assertFalse(report["integrity"]["verified"])
        self.assertIn("hash changed", report["integrity"]["spoliation"])

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_view_is_closed_even_when_investigation_raises(
        self, mock_claude, mock_close
    ):
        mock_claude.side_effect = RuntimeError("boom during hypotheses")
        mock_close.return_value = TeardownResult()
        calls: list = []
        view = EvidenceView(raw_path="/cases/img.E01")
        inv = Investigator(
            self.executor,
            [],
            str(Path(self._tmpdir) / "inv"),
            evidence_opener=self._opener(view, None, calls),
        )
        # A mid-run failure is recorded in the report (with a terminal status)
        # rather than propagated, so a crashed run still leaves a report behind.
        report = inv.investigate(evidence_path="/cases/img.E01", evidence_type="disk")
        self.assertNotEqual(report["status"], "in_progress")
        self.assertTrue(report["error"])
        # Mounts must be released even on a mid-run failure.
        mock_close.assert_called_once_with(view)


class SystemCharacterizationTest(unittest.TestCase):
    """An always-on characterization pass emits the standard forensic-report
    identity facts (host, owner, OS, timezone, accounts, network identity)
    independent of any hypothesis — so they are reported even when no hypothesis
    would surface them. Reuses the sub-agent machinery; runs once per MOUNTABLE
    item."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.executor.run.return_value = _make_exec_result()
        self.tools = [
            {
                "name": "rip",
                "display_name": "rip",
                "path": "/usr/bin/rip.pl",
                "description": "registry parser",
                "category": "windows_artifact_analysis",
            }
        ]

    def _inv(self) -> Investigator:
        return Investigator(
            self.executor, self.tools, str(Path(self._tmpdir) / "inv")
        )

    def test_mission_names_the_required_identity_facts(self):
        low = _CHARACTERIZATION_MISSION.lower()
        for fact in ("host", "owner", "time zone", "account", "ip address", "mac"):
            self.assertIn(fact, low, f"characterization mission must cover {fact!r}")

    @patch("orchestrator.investigator.DomainAgent")
    def test_runs_once_per_mountable_item_and_returns_findings(self, mock_subagent):
        ip_finding = Finding(
            finding_id="F-id1",
            description="Host IP 192.168.1.111",
            confidence="confirmed",
            evidence_links=["e1"],
            ioc_type="ip",
            ioc_value="192.168.1.111",
        )
        agent = mock_subagent.return_value
        agent.investigate.return_value = AgentResult(
            agent_name="artifacts_agent",
            domain="artifacts",
            findings=[ip_finding],
        )
        mounted = EvidenceView(raw_path="/cases/img.E01", mount_roots=["/mnt/p1"])
        raw_only = EvidenceView(raw_path="/cases/mem.raw", mount_roots=[])
        items = [
            (EvidenceSpec("/cases/img.E01", "disk"), mounted),
            (EvidenceSpec("/cases/mem.raw", "memory"), raw_only),
        ]

        findings, exec_outputs = self._inv()._characterize_systems(items)

        # Only the mountable item is characterized (filesystem identity sources).
        self.assertEqual(agent.investigate.call_count, 1)
        self.assertIn(ip_finding, findings)
        # The dispatched task is the fixed identity mission, NOT a hypothesis.
        _, kwargs = agent.investigate.call_args
        self.assertEqual(kwargs.get("task"), _CHARACTERIZATION_MISSION)
        self.assertEqual(kwargs.get("mount_roots"), ["/mnt/p1"])

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_characterization_runs_even_with_no_hypotheses(
        self, mock_claude, mock_close
    ):
        # Even when hypothesis formation yields nothing, the characterization pass
        # must still run (it does not depend on hypotheses).
        mock_claude.return_value = {"hypotheses": []}
        mock_close.return_value = TeardownResult()
        view = EvidenceView(raw_path="/cases/img.E01", mount_roots=["/mnt/p1"])

        def opener(path, etype, *, executor=None, runner=None):
            return view

        inv = Investigator(
            self.executor,
            self.tools,
            str(Path(self._tmpdir) / "inv2"),
            evidence_opener=opener,
        )
        with patch.object(
            inv, "_characterize_systems", return_value=([], {})
        ) as mock_char:
            inv.investigate(evidence_path="/cases/img.E01", evidence_type="disk")
        mock_char.assert_called_once()


class MultiRoundVerifyTest(unittest.TestCase):
    """Orchestrator wires multi-round verification + recalibration."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.inv = Investigator(self.executor, [], str(Path(self._tmpdir) / "inv"))
        self.inv._brief = None

    def _finding(self, fid, agent, conf="confirmed", links=None, **kw) -> Finding:
        return Finding(
            finding_id=fid,
            description=kw.get("description", "d"),
            confidence=conf,
            evidence_links=links or [],
            agent_name=agent,
            ioc_type=kw.get("ioc_type", ""),
            ioc_value=kw.get("ioc_value", ""),
        )

    @patch("orchestrator.investigator.MultiRoundVerifier")
    def test_threads_original_outputs_to_verifier(self, mock_mrv_cls):
        from verification.multi_round import VerificationOutcome

        captured = {}

        def fake_verify(
            finding,
            original_outputs,
            evidence_path,
            corroboration_count=0,
            corroboration_ids=None,
        ):
            captured["outputs"] = original_outputs
            return VerificationOutcome("confirmed", 1, [], [])

        mock_mrv_cls.return_value.verify.side_effect = fake_verify

        f = self._finding("F-1", "disk_agent", links=["e1"])
        exec_outputs = {"e1": {"execution_id": "e1", "stdout": "real output"}}
        self.inv._verify_round([f], exec_outputs, "/img")

        # The original_outputs=[] bug is fixed: the verifier gets the real output.
        self.assertEqual(
            captured["outputs"], [{"execution_id": "e1", "stdout": "real output"}]
        )
        self.assertIn(f, self.inv.accepted_findings)

    @patch("orchestrator.investigator.MultiRoundVerifier")
    def test_downgrade_lowers_confidence_and_logs_self_correction(self, mock_mrv_cls):
        from verification.multi_round import VerificationOutcome

        mock_mrv_cls.return_value.verify.return_value = VerificationOutcome(
            "downgraded", 2, [], []
        )
        f = self._finding("F-1", "disk_agent", conf="confirmed", links=["e1"])
        self.inv._verify_round([f], {}, "/img")

        self.assertEqual(f.verification_verdict, "downgraded")
        self.assertEqual(f.confidence, "inferred")  # one level down
        self.assertIn(f, self.inv.accepted_findings)  # downgraded still accepted
        sc = self.inv.audit.get_events("self_correction")
        self.assertEqual(len(sc), 1)
        self.assertEqual(sc[0]["previous_confidence"], "confirmed")
        self.assertEqual(sc[0]["new_confidence"], "inferred")
        self.assertEqual(sc[0]["rounds_taken"], 2)

    @patch("orchestrator.investigator.MultiRoundVerifier")
    def test_refuted_is_dropped_and_logged(self, mock_mrv_cls):
        from verification.multi_round import VerificationOutcome

        mock_mrv_cls.return_value.verify.return_value = VerificationOutcome(
            "refuted", 1, [], []
        )
        f = self._finding("F-1", "disk_agent", links=["e1"])
        self.inv._verify_round([f], {}, "/img")

        self.assertEqual(f.verification_verdict, "refuted")
        self.assertNotIn(f, self.inv.accepted_findings)
        self.assertEqual(len(self.inv.audit.get_events("self_correction")), 1)

    @patch("orchestrator.investigator.MultiRoundVerifier")
    def test_confirmed_corroborated_raises_confidence(self, mock_mrv_cls):
        from verification.multi_round import VerificationOutcome

        captured = {}

        def fake_verify(
            finding,
            original_outputs,
            evidence_path,
            corroboration_count=0,
            corroboration_ids=None,
        ):
            captured[finding.finding_id] = corroboration_count
            return VerificationOutcome("confirmed", 1, [], [])

        mock_mrv_cls.return_value.verify.side_effect = fake_verify

        # Two cross-domain findings with the same IOC corroborate each other.
        f1 = self._finding(
            "F-1", "disk_agent", conf="inferred", ioc_type="ip", ioc_value="10.0.0.5"
        )
        f2 = self._finding(
            "F-2", "network_agent", conf="inferred", ioc_type="ip", ioc_value="10.0.0.5"
        )
        self.inv._verify_round([f1, f2], {}, "/img")

        self.assertEqual(captured["F-1"], 1)  # corroborated by F-2
        self.assertEqual(f1.confidence, "confirmed")  # inferred -> confirmed

    @patch("orchestrator.investigator.MultiRoundVerifier")
    def test_low_confidence_findings_are_also_verified(self, mock_mrv_cls):
        # Weak ("possible") findings are the ones that most need challenging, so
        # they go through verification too rather than landing in the report
        # unchecked.
        from verification.multi_round import VerificationOutcome

        mock_mrv_cls.return_value.verify.return_value = VerificationOutcome(
            "refuted", 1, [], []
        )
        f = self._finding("F-1", "disk_agent", conf="possible", links=["e1"])
        self.inv._verify_round(
            [f], {"e1": {"execution_id": "e1", "stdout": "x"}}, "/img"
        )

        mock_mrv_cls.return_value.verify.assert_called_once()
        self.assertTrue(f.verified)
        # A refuted weak finding is dropped instead of polluting the report.
        self.assertNotIn(f, self.inv.accepted_findings)

    @patch("orchestrator.investigator.MultiRoundVerifier")
    def test_unverified_outcome_keeps_finding_without_marking_verified(
        self, mock_mrv_cls
    ):
        # When the verifier LLM is unavailable the outcome is "unverified": the
        # finding is KEPT (not dropped) but must NOT be marked verified or have
        # its confidence recalibrated — otherwise an unverified claim would be
        # presented at parity with a genuinely challenged one.
        from verification.multi_round import VerificationOutcome

        mock_mrv_cls.return_value.verify.return_value = VerificationOutcome(
            "unverified", 1, [], []
        )
        f = self._finding("F-1", "disk_agent", conf="confirmed", links=["e1"])
        self.inv._verify_round([f], {}, "/img")

        self.assertFalse(f.verified)
        self.assertEqual(f.confidence, "confirmed")  # unchanged, not recalibrated
        self.assertIn(f, self.inv.accepted_findings)  # kept, not dropped
        self.assertEqual(len(self.inv.audit.get_events("self_correction")), 0)


class SemanticCorrelationWiringTest(unittest.TestCase):
    """The orchestrator runs semantic correlation over accepted findings and
    surfaces the resulting clusters in the generated report."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.inv = Investigator(self.executor, [], str(Path(self._tmpdir) / "inv"))
        self.inv._brief = None
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.complete()

    def _finding(self, fid, desc) -> Finding:
        f = Finding.new(desc, "confirmed", ["e1"], agent_name="disk_agent")
        f.finding_id = fid
        return f

    @patch("correlation.semantic.call_claude_json")
    def test_clusters_appear_in_report(self, mock_claude):
        mock_claude.return_value = {
            "clusters": [
                {
                    "label": "evil.exe persistence",
                    "finding_ids": ["F-1", "F-2"],
                    "reasoning": "File drop and run key for same binary",
                }
            ]
        }
        self.inv.accepted_findings = [
            self._finding("F-1", "evil.exe written to C:\\Temp"),
            self._finding("F-2", "Run key added for evil.exe"),
        ]

        self.inv._correlate_semantically()

        report = self.inv._generate_report("/cases/img.E01", "disk")
        clusters = report["correlation"]["semantic_clusters"]
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["label"], "evil.exe persistence")
        self.assertEqual(clusters[0]["finding_ids"], ["F-1", "F-2"])
        self.assertEqual(
            clusters[0]["reasoning"], "File drop and run key for same binary"
        )

    def test_no_findings_produces_empty_clusters_without_error(self):
        self.inv.accepted_findings = []

        # Must not raise and must not call out to the LLM with nothing to group.
        self.inv._correlate_semantically()

        self.assertEqual(self.inv.semantic_result.clusters, [])
        report = self.inv._generate_report("/cases/img.E01", "disk")
        self.assertEqual(report["correlation"]["semantic_clusters"], [])

    @patch("correlation.semantic.call_claude_json")
    def test_llm_returning_nothing_yields_empty_clusters(self, mock_claude):
        mock_claude.return_value = None
        self.inv.accepted_findings = [
            self._finding("F-1", "event A"),
            self._finding("F-2", "event B"),
        ]

        self.inv._correlate_semantically()

        self.assertEqual(self.inv.semantic_result.clusters, [])
        report = self.inv._generate_report("/cases/img.E01", "disk")
        self.assertEqual(report["correlation"]["semantic_clusters"], [])


class ReportFilesTest(unittest.TestCase):
    """The orchestrator emits both a machine-readable report.json and a
    human-readable report.md to the output directory."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.inv = Investigator(self.executor, [], str(Path(self._tmpdir) / "inv"))
        self.inv._brief = None
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.complete()

    def test_write_reports_emits_json_and_markdown(self):
        report = self.inv._generate_report("/cases/img.E01", "disk")

        self.inv._write_reports(report)

        json_path = self.inv.output_dir / "report.json"
        md_path = self.inv.output_dir / "report.md"
        self.assertTrue(json_path.exists())
        self.assertTrue(md_path.exists())
        self.assertGreater(md_path.stat().st_size, 0)
        self.assertIn("# Forensic Investigation Report", md_path.read_text())


class HypothesisNoveltyTest(unittest.TestCase):
    """A re-hypothesize step must not re-propose hypotheses it already has, so
    duplicates are recognized despite case/punctuation/spacing differences."""

    def test_exact_duplicate_is_not_novel(self):
        self.assertFalse(
            is_novel_hypothesis(
                "Lateral movement via RDP", ["Lateral movement via RDP"]
            )
        )

    def test_case_and_punctuation_insensitive(self):
        self.assertFalse(
            is_novel_hypothesis(
                "lateral movement via rdp!", ["Lateral movement via RDP"]
            )
        )

    def test_distinct_hypothesis_is_novel(self):
        self.assertTrue(
            is_novel_hypothesis(
                "Data exfiltration over DNS", ["Lateral movement via RDP"]
            )
        )

    def test_novel_against_empty_set(self):
        self.assertTrue(is_novel_hypothesis("anything at all", []))


class RehypothesizeTest(unittest.TestCase):
    """The deepen/pivot step forms new hypotheses from findings and records
    pivots, but stays bounded: it dedups, caps the total, and stops forming new
    ones after the cutoff round."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.inv = Investigator(self.executor, [], str(Path(self._tmpdir) / "inv"))
        self.inv._brief = None
        self.inv.progress.start("inv-test", "/cases/img.E01", "disk")
        self.inv.progress.add_hypothesis("H1", "Lateral movement via RDP")

    def _descriptions(self):
        return [h.description for h in self.inv.progress.progress.hypotheses]

    @patch("orchestrator.investigator.call_claude_json")
    def test_adds_novel_hypothesis(self, mock_claude):
        mock_claude.return_value = {
            "new_hypotheses": [
                {"description": "Data exfiltration over DNS", "reasoning": "r"}
            ],
            "pivots": [],
        }
        added = self.inv._rehypothesize([], round_num=1)
        self.assertEqual(added, 1)
        self.assertIn("Data exfiltration over DNS", self._descriptions())

    @patch("orchestrator.investigator.call_claude_json")
    def test_adds_up_to_cap_without_double_counting(self, mock_claude):
        # The cap check must not double-count hypotheses as they are added.
        # Starting with 1 existing and proposing 7 distinct new ones, all 7 are
        # added (total 8 = the cap) — not stopped at roughly half.
        mock_claude.return_value = {
            "new_hypotheses": [
                {"description": f"distinct theory number {i}"} for i in range(7)
            ],
            "pivots": [],
        }
        added = self.inv._rehypothesize([], round_num=1)
        self.assertEqual(added, 7)
        self.assertEqual(len(self.inv.progress.progress.hypotheses), 8)

    @patch("orchestrator.investigator.call_claude_json")
    def test_new_hypothesis_ids_are_unique(self, mock_claude):
        # IDs for newly-formed hypotheses must not collide with existing ones or
        # each other.
        mock_claude.return_value = {
            "new_hypotheses": [
                {"description": "theory alpha"},
                {"description": "theory beta"},
            ],
            "pivots": [],
        }
        self.inv._rehypothesize([], round_num=1)
        ids = [h.id for h in self.inv.progress.progress.hypotheses]
        self.assertEqual(len(ids), len(set(ids)))

    @patch("orchestrator.investigator.call_claude_json")
    def test_skips_duplicate_hypothesis(self, mock_claude):
        mock_claude.return_value = {
            "new_hypotheses": [{"description": "lateral movement via rdp"}],
            "pivots": [],
        }
        added = self.inv._rehypothesize([], round_num=1)
        self.assertEqual(added, 0)
        self.assertEqual(len(self._descriptions()), 1)

    @patch("orchestrator.investigator.call_claude_json")
    def test_no_new_hypotheses_after_cutoff_round(self, mock_claude):
        added = self.inv._rehypothesize([], round_num=4)
        self.assertEqual(added, 0)
        mock_claude.assert_not_called()

    @patch("orchestrator.investigator.call_claude_json")
    def test_respects_total_hypothesis_cap(self, mock_claude):
        for i in range(2, 9):  # bring the total up to the cap (H1..H8 = 8)
            self.inv.progress.add_hypothesis(f"H{i}", f"hypothesis {i}")
        mock_claude.return_value = {
            "new_hypotheses": [{"description": "one more idea"}],
            "pivots": [],
        }
        added = self.inv._rehypothesize([], round_num=1)
        self.assertEqual(added, 0)

    @patch("orchestrator.investigator.call_claude_json")
    def test_records_pivot(self, mock_claude):
        mock_claude.return_value = {
            "new_hypotheses": [],
            "pivots": [
                {
                    "from": "Lateral movement via RDP",
                    "to": "Data exfiltration over DNS",
                    "reason": "RDP hypothesis refuted",
                }
            ],
        }
        self.inv._rehypothesize([], round_num=1)
        pivots = self.inv.progress.progress.strategy_pivots
        self.assertEqual(len(pivots), 1)
        self.assertEqual(pivots[0].to_strategy, "Data exfiltration over DNS")


class EvidenceRoutingTest(unittest.TestCase):
    """A domain is routed to the evidence items its tools can actually read."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.inv = Investigator(self.executor, [], str(Path(self._tmpdir) / "inv"))

    @staticmethod
    def _item(path, etype, mounted=False):
        roots = ["/mnt/sift/p1"] if mounted else []
        return (
            EvidenceSpec(path=path, evidence_type=etype),
            EvidenceView(raw_path=path, mount_roots=roots),
        )

    def test_memory_domain_routes_to_memory_item(self):
        disk = self._item("/c/img.E01", "disk", mounted=True)
        mem = self._item("/c/mem.raw", "memory")
        picked = self.inv._evidence_for_domain("memory", [disk, mem])
        self.assertEqual([v.raw_path for _, v in picked], ["/c/mem.raw"])

    def test_disk_domain_routes_to_disk_item(self):
        disk = self._item("/c/img.E01", "disk", mounted=True)
        mem = self._item("/c/mem.raw", "memory")
        picked = self.inv._evidence_for_domain("disk", [disk, mem])
        self.assertEqual([v.raw_path for _, v in picked], ["/c/img.E01"])

    def test_memory_domain_skipped_without_memory_evidence(self):
        disk = self._item("/c/img.E01", "disk", mounted=True)
        picked = self.inv._evidence_for_domain("memory", [disk])
        self.assertEqual(picked, [])

    def test_network_domain_prefers_pcap_then_falls_back_to_disk(self):
        disk = self._item("/c/img.E01", "disk", mounted=True)
        pcap = self._item("/c/cap.pcapng", "pcap")
        # With a capture present, network analysis goes to the capture...
        picked = self.inv._evidence_for_domain("network", [disk, pcap])
        self.assertEqual([v.raw_path for _, v in picked], ["/c/cap.pcapng"])
        # ...but with only a disk image, it still runs against the disk.
        picked = self.inv._evidence_for_domain("network", [disk])
        self.assertEqual([v.raw_path for _, v in picked], ["/c/img.E01"])


class MultiEvidenceTest(unittest.TestCase):
    """investigate_evidence() opens, triages, and closes several evidence items."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.executor = MagicMock(spec=LocalExecutor)
        self.executor.run.return_value = _make_exec_result()

    def _opener(self, views_by_path, calls):
        def opener(evidence_path, evidence_type, *, executor=None, runner=None):
            calls.append((evidence_path, evidence_type))
            return views_by_path[evidence_path]

        return opener

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_opens_and_closes_every_item(self, mock_claude, mock_close):
        mock_claude.return_value = {"hypotheses": []}
        mock_close.return_value = TeardownResult()
        disk_view = EvidenceView(raw_path="/c/img.E01", mount_roots=["/mnt/p1"])
        mem_view = EvidenceView(raw_path="/c/mem.raw")
        calls: list = []
        inv = Investigator(
            self.executor,
            [],
            str(Path(self._tmpdir) / "inv"),
            evidence_opener=self._opener(
                {"/c/img.E01": disk_view, "/c/mem.raw": mem_view}, calls
            ),
        )
        inv.investigate_evidence(
            [
                EvidenceSpec("/c/img.E01", "disk"),
                EvidenceSpec("/c/mem.raw", "memory"),
            ]
        )
        self.assertEqual(calls, [("/c/img.E01", "disk"), ("/c/mem.raw", "memory")])
        self.assertEqual(mock_close.call_count, 2)

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_report_lists_all_evidence_with_integrity(self, mock_claude, mock_close):
        mock_claude.return_value = {"hypotheses": []}
        mock_close.side_effect = [
            TeardownResult(
                integrity=IntegrityRecord(
                    image_path="/c/img.E01",
                    before_sha256="a",
                    after_sha256="a",
                )
            ),
            TeardownResult(),  # memory: nothing mounted, no integrity bracket
        ]
        disk_view = EvidenceView(raw_path="/c/img.E01", mount_roots=["/mnt/p1"])
        mem_view = EvidenceView(raw_path="/c/mem.raw")
        calls: list = []
        inv = Investigator(
            self.executor,
            [],
            str(Path(self._tmpdir) / "inv"),
            evidence_opener=self._opener(
                {"/c/img.E01": disk_view, "/c/mem.raw": mem_view}, calls
            ),
        )
        report = inv.investigate_evidence(
            [
                EvidenceSpec("/c/img.E01", "disk"),
                EvidenceSpec("/c/mem.raw", "memory"),
            ]
        )
        self.assertEqual(len(report["evidence"]), 2)
        paths = [e["path"] for e in report["evidence"]]
        self.assertEqual(paths, ["/c/img.E01", "/c/mem.raw"])
        types = [e["evidence_type"] for e in report["evidence"]]
        self.assertEqual(types, ["disk", "memory"])
        # The disk item carries an integrity bracket; the memory item does not.
        self.assertTrue(report["evidence"][0]["integrity"]["checked"])
        self.assertFalse(report["evidence"][1]["integrity"]["checked"])

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_single_investigate_is_backward_compatible(self, mock_claude, mock_close):
        mock_claude.return_value = {"hypotheses": []}
        mock_close.return_value = TeardownResult(
            integrity=IntegrityRecord(
                image_path="/c/img.E01", before_sha256="a", after_sha256="a"
            )
        )
        view = EvidenceView(raw_path="/c/img.E01", mount_roots=["/mnt/p1"])
        calls: list = []
        inv = Investigator(
            self.executor,
            [],
            str(Path(self._tmpdir) / "inv"),
            evidence_opener=self._opener({"/c/img.E01": view}, calls),
        )
        report = inv.investigate(evidence_path="/c/img.E01", evidence_type="disk")
        # Single-evidence callers keep the top-level fields...
        self.assertEqual(report["evidence_path"], "/c/img.E01")
        self.assertEqual(report["evidence_type"], "disk")
        self.assertTrue(report["integrity"]["checked"])
        # ...and also get the unified evidence list with one entry.
        self.assertEqual(len(report["evidence"]), 1)

    @patch("orchestrator.investigator.close_evidence")
    @patch("orchestrator.investigator.call_claude_json")
    def test_partial_open_failure_closes_already_opened_items(
        self, mock_claude, mock_close
    ):
        mock_claude.return_value = {"hypotheses": []}
        mock_close.return_value = TeardownResult()
        v1 = EvidenceView(raw_path="/c/a.E01", mount_roots=["/mnt/a"])

        def opener(evidence_path, evidence_type, *, executor=None, runner=None):
            if evidence_path == "/c/a.E01":
                return v1
            raise RuntimeError("second mount failed")

        inv = Investigator(
            self.executor,
            [],
            str(Path(self._tmpdir) / "inv"),
            evidence_opener=opener,
        )
        # The second item's open fails; the run records the error and still
        # produces a report instead of propagating.
        report = inv.investigate_evidence(
            [
                EvidenceSpec("/c/a.E01", "disk"),
                EvidenceSpec("/c/b.E01", "disk"),
            ]
        )
        self.assertNotEqual(report["status"], "in_progress")
        self.assertTrue(report["error"])
        # The first item was already opened before the second item's open
        # raised; the finally must still close it so its mount does not leak.
        mock_close.assert_any_call(v1)


class ReportOnErrorTest(unittest.TestCase):
    """A crash partway through a run must still produce a report with a
    terminal status and the error recorded, rather than discarding everything
    and leaving the run stuck at "in_progress"."""

    def _inv(self) -> Investigator:
        tmp = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        inv = Investigator(executor, [], str(Path(tmp) / "inv"))
        inv.progress.start(inv.investigation_id, "/cases/img.E01", "disk")
        return inv

    def test_report_is_written_even_when_the_loop_raises(self):
        tmp = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)

        def opener(path, etype, **kwargs):
            return EvidenceView(raw_path=path)

        inv = Investigator(executor, [], str(Path(tmp) / "inv"), evidence_opener=opener)
        inv._run_triage_all = MagicMock(side_effect=RuntimeError("boom mid-run"))
        inv.investigate("/cases/img.E01", "disk")  # must NOT propagate
        report_path = Path(tmp) / "inv" / "report.json"
        self.assertTrue(report_path.exists())
        report = json.loads(report_path.read_text())
        self.assertNotEqual(report["status"], "in_progress")
        self.assertIn(report["status"], ("errored", "incomplete"))
        self.assertTrue(report.get("error"))

    def test_post_correlation_failure_does_not_overwrite_completed_status(self):
        # A run that fully finished the investigation but failed ONLY in the
        # Phase 4 post-processing (correlation) must NOT be reported as a fully
        # errored run: complete() must win over a correlation crash, while a
        # report is still written.
        tmp = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)

        def opener(path, etype, **kwargs):
            return EvidenceView(raw_path=path)

        inv = Investigator(executor, [], str(Path(tmp) / "inv"), evidence_opener=opener)
        # Investigation phases all succeed: triage returns, no hypotheses form
        # (so the loop exits immediately and the run reaches Phase 4).
        inv._run_triage_all = MagicMock(return_value="triage output")
        inv._form_hypotheses = MagicMock(return_value=[])
        # Post-processing correlation is the ONLY thing that fails.
        inv._correlate_semantically = MagicMock(
            side_effect=RuntimeError("boom in correlation")
        )

        inv.investigate("/cases/img.E01", "disk")  # must NOT propagate

        report_path = Path(tmp) / "inv" / "report.json"
        self.assertTrue(report_path.exists())
        report = json.loads(report_path.read_text())
        # A finished investigation that only failed in post-processing stays
        # "completed" rather than being flipped to "errored".
        self.assertEqual(report["status"], "completed")

    def test_iteration_limit_status_is_not_overwritten_by_complete(self):
        # A run that exhausts its round budget ends with status "iteration_limit"
        # (set by increment_iteration). The post-loop complete() must NOT clobber
        # that back to "completed" — otherwise a cut-short run is mislabeled and
        # the report's triage-only warning never fires.
        tmp = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)

        def opener(path, etype, **kwargs):
            return EvidenceView(raw_path=path)

        inv = Investigator(
            executor, [], str(Path(tmp) / "inv"), max_rounds=1, evidence_opener=opener
        )
        inv._run_triage_all = MagicMock(return_value="triage output")
        inv._characterize_systems = MagicMock(return_value=([], {}))

        def _form(*_a, **_k):
            inv.progress.add_hypothesis("H1", "a hypothesis worth one round")

        inv._form_hypotheses = MagicMock(side_effect=_form)
        # The round dispatches but produces nothing; the hypothesis stays open, so
        # the loop would continue — except the 1-round budget stops it.
        inv._dispatch_sub_agents = MagicMock(return_value=([], {}))
        inv._verify_round = MagicMock()
        inv._evaluate_hypotheses = MagicMock()
        inv._spawn_contested_followups = MagicMock(return_value=0)
        inv._rehypothesize = MagicMock()

        inv.investigate("/cases/img.E01", "disk")

        report = json.loads((Path(tmp) / "inv" / "report.json").read_text())
        self.assertEqual(report["status"], "iteration_limit")
        self.assertTrue(report["findings_unverified"])

    def test_report_write_failure_is_surfaced_not_propagated(self):
        # The final report-write step is itself wrapped: if writing the report to
        # disk raises (e.g. an IO error), investigate() must NOT propagate the
        # exception — it returns the in-memory report with the write failure
        # recorded, preserving the "always leave a report" guarantee for callers.
        tmp = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)

        def opener(path, etype, **kwargs):
            return EvidenceView(raw_path=path)

        inv = Investigator(executor, [], str(Path(tmp) / "inv"), evidence_opener=opener)
        inv._run_triage_all = MagicMock(return_value="triage output")
        inv._form_hypotheses = MagicMock(return_value=[])
        # The on-disk write is the only thing that fails.
        inv._write_reports = MagicMock(side_effect=OSError("disk full"))

        report = inv.investigate("/cases/img.E01", "disk")  # must NOT propagate

        # The in-memory report is still returned, with the write failure recorded.
        self.assertIsInstance(report, dict)
        self.assertIn("disk full", report.get("error", ""))
        self.assertIs(report.get("report_write_failed"), True)


class ReportExecutionsMapTest(unittest.TestCase):
    """The report must carry the accumulated per-execution outputs so a reader
    can trace each finding back to the exact command that produced it."""

    def _inv(self) -> Investigator:
        tmp = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        inv = Investigator(executor, [], str(Path(tmp) / "inv"))
        inv.progress.start(inv.investigation_id, "/cases/img.E01", "disk")
        # _generate_report reads the case brief, which is normally set when a run
        # starts; set it here since this test drives report generation directly.
        inv._brief = None
        return inv

    def test_report_carries_executions_map(self):
        inv = self._inv()
        inv.progress.complete()
        inv._all_exec_outputs = {
            "e1": {
                "tool": "/usr/bin/fls",
                "args": ["-r", "/cases/img.E01"],
                "exit_code": 0,
                "execution_id": "e1",
            }
        }
        report = inv._generate_report("/cases/img.E01", "disk")
        self.assertIn("e1", report["executions"])
        self.assertEqual(report["executions"]["e1"]["tool"], "/usr/bin/fls")


class OneFailedAiCallTest(unittest.TestCase):
    """A single transient failure of an AI reasoning call must not abort the
    whole run. It should be caught, recorded as a failed approach so it is
    visible in the report, and the investigation should still finish and write
    a report."""

    @patch("agents.base.call_claude_json")
    def test_one_failed_ai_call_does_not_abort_the_run(self, mock_claude):
        tmp = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)

        def opener(path, etype, **kwargs):
            return EvidenceView(raw_path=path)

        # A non-empty registry so a sub-agent is actually dispatched. With no
        # matched categories, the per-domain tool filter falls back to the first
        # slice of the registry; passing one tool keeps that slice non-empty so
        # the dispatch loop does not skip every domain (which would mean the
        # patched AI call never fires and the test would pass vacuously).
        registry_tools = [
            {
                "name": "fls",
                "path": "/usr/bin/fls",
                "category": "disk_forensics",
                "description": "List files and directory entries in an image",
            }
        ]
        inv = Investigator(
            executor, registry_tools, str(Path(tmp) / "inv"), evidence_opener=opener
        )
        inv._run_triage_all = MagicMock(return_value="triage output")
        # Force one active hypothesis so a dispatch happens. Its wording matches
        # no task keywords, so it routes to the default disk + artifacts domains,
        # and the disk opener above gives those domains a target.
        inv._form_hypotheses = MagicMock(
            side_effect=lambda *a, **k: inv.progress.add_hypothesis("H1", "test hyp")
        )
        # The sub-agent's planning AI call raises once.
        mock_claude.side_effect = ClaudeError("transient gateway")

        inv.investigate("/cases/img.E01", "disk")  # must NOT propagate

        report_path = Path(tmp) / "inv" / "report.json"
        self.assertTrue(report_path.exists())
        # A failed approach was recorded for the degraded dispatch, naming the
        # AI/Claude failure so the reader can see the run was partial.
        report = json.loads(report_path.read_text())
        self.assertTrue(
            any(
                "ai" in (fa.get("failure", "")).lower()
                or "claude" in (fa.get("failure", "")).lower()
                for fa in report.get("failed_approaches", [])
            )
        )


class PartialRunLabellingTest(unittest.TestCase):
    """When a run is cut short (no rounds completed, timed out, hit the iteration
    cap, errored, or nothing verified), the report must flag the run and label
    its findings triage-only instead of presenting them as verified. Limitations
    gathered by sub-agents must also be carried into the report."""

    def _inv(self) -> Investigator:
        tmp = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        inv = Investigator(executor, [], str(Path(tmp) / "inv"))
        inv.progress.start(inv.investigation_id, "/cases/img.E01", "disk")
        # _generate_report reads the case brief, which is normally set when a run
        # starts; set it here since this test drives report generation directly.
        inv._brief = None
        return inv

    def test_zero_round_run_marks_findings_triage_only(self):
        inv = self._inv()
        inv.progress.complete()  # complete() runs even on a 0-round run
        inv.accepted_findings = [_make_finding(finding_id="F-1", verified=False)]
        report = inv._generate_report("/cases/img.E01", "disk")
        self.assertTrue(report["findings_unverified"])
        self.assertEqual(report["findings"][0]["verification_state"], "triage_only")

    def test_timed_out_run_marks_findings_triage_only(self):
        inv = self._inv()
        inv.progress.increment_iteration()  # rounds_completed = 1
        inv.progress.timeout()  # status = "timed_out"
        inv.accepted_findings = [_make_finding(finding_id="F-2", verified=True)]
        report = inv._generate_report("/cases/img.E01", "disk")
        self.assertTrue(report["findings_unverified"])
        self.assertEqual(report["findings"][0]["verification_state"], "triage_only")

    def test_completed_run_with_no_verified_findings_is_triage_only(self):
        # Exercises the (has_findings and not any_verified) partial branch in
        # isolation: the run reaches a clean terminal state (status "completed",
        # rounds_completed > 0) so neither the zero-round nor the failed-status
        # branch fires — only the "produced findings, none verified" branch can
        # flag this run partial. An unverified finding from an otherwise-complete
        # run must still be labelled triage-only, not presented at parity.
        inv = self._inv()
        inv.progress.increment_iteration()  # rounds_completed = 1
        inv.progress.complete()  # status = "completed"
        inv.accepted_findings = [_make_finding(finding_id="F-4", verified=False)]
        report = inv._generate_report("/cases/img.E01", "disk")
        self.assertTrue(report["findings_unverified"])
        self.assertEqual(report["findings"][0]["verification_state"], "triage_only")

    def test_completed_verified_run_is_not_triage_only(self):
        inv = self._inv()
        inv.progress.increment_iteration()
        inv.progress.complete()
        inv.accepted_findings = [_make_finding(finding_id="F-3", verified=True)]
        report = inv._generate_report("/cases/img.E01", "disk")
        self.assertFalse(report.get("findings_unverified", False))
        self.assertEqual(report["findings"][0]["verification_state"], "verified")

    def test_completed_run_with_no_findings_is_not_triage_only(self):
        # A run that completes normally but legitimately finds nothing must not
        # be labeled triage-only: "completed, nothing found" is a clean result,
        # not a cut-short run. With no findings there is nothing to verify, so
        # the absence of verified findings alone must not flag the run partial.
        inv = self._inv()
        inv.progress.increment_iteration()
        inv.progress.complete()
        inv.accepted_findings = []
        report = inv._generate_report("/cases/img.E01", "disk")
        self.assertFalse(report.get("findings_unverified", False))
        self.assertEqual(report["findings"], [])

    def test_report_carries_limitations(self):
        inv = self._inv()
        inv.progress.complete()
        inv._limitations = ["Unbacked claim dropped (no successful evidence): x"]
        report = inv._generate_report("/cases/img.E01", "disk")
        self.assertIn("x", " ".join(report["limitations"]))


class ParallelDispatchTest(unittest.TestCase):
    """Independent sub-agents (one per hypothesis x domain x evidence item) run
    concurrently, not serially — the ~20 serial claude calls per round were 95%
    of wall-clock. Results are merged single-writer in the calling thread."""

    def test_sub_agents_run_concurrently_and_results_merge(self):
        import threading
        from types import SimpleNamespace

        from agents.base import AgentResult, Finding

        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        tools = [
            {
                "name": "fls",
                "path": "/usr/bin/fls",
                "description": "x",
                "category": "disk_forensics",
            }
        ]
        inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))
        inv._brief = None
        inv.progress.start("inv-test", "/cases/img.E01", "disk")
        # Force two independent work items: two hypotheses, each -> disk domain,
        # one evidence target. Stub the resolution helpers so the test controls
        # exactly how many sub-agents are dispatched.
        inv._domains_for_hypothesis = lambda h: ["disk"]
        inv._evidence_for_domain = lambda dn, it: it
        inv._filter_tools_for_domain = lambda domain, hid: tools
        inv._primary_offset = lambda v: 0

        h1 = SimpleNamespace(id="H1", description="hyp one")
        h2 = SimpleNamespace(id="H2", description="hyp two")
        items = [
            (
                EvidenceSpec(path="/cases/img.E01", evidence_type="disk"),
                EvidenceView(raw_path="/cases/img.E01"),
            )
        ]

        live = {"cur": 0, "max": 0}
        lock = threading.Lock()
        # Both sub-agents must be in-flight at once to pass the barrier; on serial
        # dispatch the first blocks here until timeout and max concurrency stays 1.
        barrier = threading.Barrier(2, timeout=5)

        class FakeAgent:
            def __init__(self, **kwargs):
                self.name = "disk_agent"
                self.domain = kwargs["domain"]

            def investigate(self, **kwargs):
                with lock:
                    live["cur"] += 1
                    live["max"] = max(live["max"], live["cur"])
                try:
                    barrier.wait()
                except threading.BrokenBarrierError:
                    pass
                with lock:
                    live["cur"] -= 1
                return AgentResult(
                    agent_name="disk_agent",
                    domain=self.domain.name,
                    findings=[
                        Finding.new("f " + kwargs["hypothesis"], "confirmed", [])
                    ],
                )

        with patch("orchestrator.investigator.DomainAgent", FakeAgent):
            findings, _ = inv._dispatch_sub_agents([h1, h2], items, "disk")

        self.assertEqual(live["max"], 2, "sub-agents did not run concurrently")
        self.assertEqual(len(findings), 2, "findings from both sub-agents not merged")
        self.assertEqual({f.hypothesis_id for f in findings}, {"H1", "H2"})


class ParallelVerificationTest(unittest.TestCase):
    """Per-finding verification is independent (each runs its own adversarial
    rounds of claude + counter-evidence tool calls) and was the serial tail after
    dispatch was parallelized. The verifies run concurrently; the orchestrator
    merges the outcomes single-writer."""

    def test_findings_verified_concurrently_and_merged(self):
        import threading
        from types import SimpleNamespace

        tmpdir = tempfile.mkdtemp()
        executor = MagicMock(spec=LocalExecutor)
        inv = Investigator(executor, [], str(Path(tmpdir) / "inv"))
        inv.progress.start("inv-test", "/cases/img.E01", "disk")

        f1 = Finding.new("finding one", "confirmed", ["e1"])
        f1.hypothesis_id = "H1"
        f2 = Finding.new("finding two", "confirmed", ["e2"])
        f2.hypothesis_id = "H2"
        exec_outputs = {
            "e1": {"execution_id": "e1", "stdout": "a", "exit_code": 0},
            "e2": {"execution_id": "e2", "stdout": "b", "exit_code": 0},
        }

        live = {"cur": 0, "max": 0}
        lock = threading.Lock()
        barrier = threading.Barrier(2, timeout=5)

        class FakeVerifier:
            def __init__(self, *args, **kwargs):
                pass

            def verify(self, finding, original_outputs, evidence_path, **kwargs):
                with lock:
                    live["cur"] += 1
                    live["max"] = max(live["max"], live["cur"])
                try:
                    barrier.wait()
                except threading.BrokenBarrierError:
                    pass
                with lock:
                    live["cur"] -= 1
                return SimpleNamespace(
                    verdict="confirmed", rounds_taken=1, reasoning_chain=["r"]
                )

        with patch("orchestrator.investigator.MultiRoundVerifier", FakeVerifier):
            inv._verify_round([f1, f2], exec_outputs, "/cases/img.E01")

        self.assertEqual(live["max"], 2, "verifications did not run concurrently")
        self.assertTrue(f1.verified and f2.verified)
        self.assertEqual(len(inv.accepted_findings), 2)


class PrimaryOffsetTest(unittest.TestCase):
    """For a raw (unmounted) partitioned image, the orchestrator derives the
    filesystem's start sector from mmls so sub-agents target the real partition
    instead of sector 0 — which fails 'Cannot determine file system type' on any
    partitioned disk (NIST images start at sector 63 / 128, not 0)."""

    NIST_HACKING_MMLS = (
        "DOS Partition Table\n"
        "Offset Sector: 0\n"
        "Units are in 512-byte sectors\n\n"
        "      Slot      Start        End          Length       Description\n"
        "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
        "001:  -------   0000000000   0000000062   0000000063   Unallocated\n"
        "002:  000:000   0000000063   0009510479   0009510417   NTFS / exFAT (0x07)\n"
        "003:  -------   0009510480   0009514259   0000003780   Unallocated\n"
    )

    def test_parse_skips_meta_and_unallocated_returns_first_fs(self):
        self.assertEqual(
            Investigator._parse_first_fs_offset(self.NIST_HACKING_MMLS), 63
        )

    def test_parse_fat32_partition(self):
        leak = "002:  000:000   0000000128   0002097279   0002097152   Win95 FAT32 (0x0b)\n"
        self.assertEqual(Investigator._parse_first_fs_offset(leak), 128)

    def test_parse_no_partition_table_returns_zero(self):
        self.assertEqual(Investigator._parse_first_fs_offset(""), 0)
        self.assertEqual(Investigator._parse_first_fs_offset("Cannot determine fs"), 0)

    def test_primary_offset_uses_mmls_when_no_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = MagicMock(spec=LocalExecutor)
            executor.run.return_value = _make_exec_result(
                stdout=self.NIST_HACKING_MMLS, exit_code=0
            )
            tools = [
                {"name": "mmls", "path": "/usr/bin/mmls", "description": "partitions"}
            ]
            inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))
            view = EvidenceView(raw_path="/cases/img.E01")  # session=None -> raw only
            self.assertEqual(inv._primary_offset(view), 63)

    def test_primary_offset_caches_mmls_result(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = MagicMock(spec=LocalExecutor)
            executor.run.return_value = _make_exec_result(
                stdout=self.NIST_HACKING_MMLS, exit_code=0
            )
            tools = [{"name": "mmls", "path": "/usr/bin/mmls", "description": "x"}]
            inv = Investigator(executor, tools, str(Path(tmpdir) / "inv"))
            view = EvidenceView(raw_path="/cases/img.E01")
            inv._primary_offset(view)
            inv._primary_offset(view)
            executor.run.assert_called_once()  # mmls run once, then cached


class SpeedKnobTest(unittest.TestCase):
    """Env-driven speed levers: helpers + high-value-only verification."""

    def test_int_env_reads_and_falls_back(self):
        from orchestrator.investigator import _int_env

        os.environ["AGENTIC_SIFT_X_INT"] = "7"
        self.addCleanup(os.environ.pop, "AGENTIC_SIFT_X_INT", None)
        self.assertEqual(_int_env("AGENTIC_SIFT_X_INT", 3), 7)
        self.assertEqual(_int_env("AGENTIC_SIFT_X_MISSING", 3), 3)

    def test_bool_env(self):
        from orchestrator.investigator import _bool_env

        os.environ["AGENTIC_SIFT_X_BOOL"] = "yes"
        self.addCleanup(os.environ.pop, "AGENTIC_SIFT_X_BOOL", None)
        self.assertTrue(_bool_env("AGENTIC_SIFT_X_BOOL"))
        self.assertFalse(_bool_env("AGENTIC_SIFT_X_MISSING_BOOL"))

    def test_is_high_value(self):
        from types import SimpleNamespace

        from orchestrator.investigator import _is_high_value

        self.assertTrue(
            _is_high_value(SimpleNamespace(ioc_value="1.2.3.4", confidence="possible"))
        )
        self.assertTrue(
            _is_high_value(SimpleNamespace(ioc_value="", confidence="confirmed"))
        )
        self.assertFalse(
            _is_high_value(SimpleNamespace(ioc_value="", confidence="possible"))
        )

    @patch("orchestrator.investigator.MultiRoundVerifier")
    def test_high_value_only_skips_low_value_verification(self, mock_mrv_cls):
        from verification.multi_round import VerificationOutcome

        mock_mrv_cls.return_value.verify.return_value = VerificationOutcome(
            "confirmed", 1, [], []
        )
        os.environ["AGENTIC_SIFT_VERIFY_HIGH_VALUE_ONLY"] = "1"
        self.addCleanup(os.environ.pop, "AGENTIC_SIFT_VERIFY_HIGH_VALUE_ONLY", None)

        tmpdir = tempfile.mkdtemp()
        inv = Investigator(
            MagicMock(spec=LocalExecutor), [], str(Path(tmpdir) / "inv")
        )
        high = Finding(
            finding_id="F-high",
            description="ioc finding",
            confidence="possible",
            ioc_type="ip",
            ioc_value="10.0.0.1",
        )
        low = Finding(
            finding_id="F-low",
            description="weak finding",
            confidence="possible",
        )
        inv._verify_round([high, low], {}, "/img")

        # Only the high-value finding is verified; the low-value one is accepted
        # unverified (skips the long verification tail).
        self.assertEqual(mock_mrv_cls.return_value.verify.call_count, 1)
        self.assertTrue(high.verified)
        self.assertFalse(low.verified)
        self.assertIn(high, inv.accepted_findings)
        self.assertIn(low, inv.accepted_findings)


class PhaseMarkerTest(unittest.TestCase):
    """The audit-silent end-of-run steps announce themselves to stdout AND the
    audit log, so a monitor doesn't mistake post-processing for a hang."""

    def test_phase_prints_and_writes_audit_event(self):
        import io
        from contextlib import redirect_stdout

        tmpdir = tempfile.mkdtemp()
        inv = Investigator(
            MagicMock(spec=LocalExecutor), [], str(Path(tmpdir) / "inv")
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            inv._phase("Correlating findings")

        self.assertIn("[phase] Correlating findings", buf.getvalue())
        events = inv.audit.get_events("agent_message")
        self.assertTrue(
            any(
                e.get("message_type") == "phase"
                and "Correlating findings" in e.get("content_summary", "")
                for e in events
            ),
            "no phase audit event written",
        )
