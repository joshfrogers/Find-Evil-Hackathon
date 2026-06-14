"""Tests for sub-agents and verifier agents."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents import claude as claude_mod
from agents.base import Finding, reconcile_evidence_links, DomainAgent, VerifierAgent
from agents.claude import (
    call_claude,
    call_claude_json,
    ClaudeError,
    ClaudeNotFoundError,
    ClaudeTimeoutError,
)
from agents.domains import AGENT_DOMAINS
from audit.logger import AuditLogger
from executor.runner import ExecutionResult, LocalExecutor
from progress.tracker import ProgressTracker
from tools.advisor import ToolAdvisor


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


def _make_exec_result(**kwargs) -> ExecutionResult:
    defaults = {
        "execution_id": "e001",
        "tool": "/usr/bin/fls",
        "argv": ["/usr/bin/fls", "-r", "/cases/img.E01"],
        "cwd": "/tmp",
        "exit_code": 0,
        "duration_ms": 500,
        "stdout": "file listing output",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "timestamp": "2026-05-21T00:00:00Z",
    }
    defaults.update(kwargs)
    return ExecutionResult(**defaults)


class FindingTest(unittest.TestCase):
    def test_new_generates_unique_id(self):
        f1 = Finding.new("desc1", "confirmed", ["e1"])
        f2 = Finding.new("desc2", "inferred", ["e2"])
        self.assertNotEqual(f1.finding_id, f2.finding_id)
        self.assertTrue(f1.finding_id.startswith("F-"))

    def test_default_fields(self):
        f = Finding.new("desc", "possible", [])
        self.assertFalse(f.verified)
        self.assertEqual(f.verification_verdict, "")
        self.assertEqual(f.hypothesis_id, "")

    def test_finding_timestamp_and_artifact_type_defaults(self):
        f = Finding.new("desc", "confirmed", ["e1"])
        self.assertEqual(f.timestamp, "")
        self.assertEqual(f.artifact_type, "")

    def test_finding_timestamp_and_artifact_type_set(self):
        f = Finding.new(
            "desc",
            "confirmed",
            ["e1"],
            timestamp="2026-05-21T12:00:00Z",
            artifact_type="registry",
        )
        self.assertEqual(f.timestamp, "2026-05-21T12:00:00Z")
        self.assertEqual(f.artifact_type, "registry")


class SubAgentTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        self.progress = ProgressTracker(Path(self._tmpdir) / "progress.json")
        self.progress.start("inv-test", "/cases/img.E01", "disk")

        self.executor = MagicMock(spec=LocalExecutor)
        self.executor.run.return_value = _make_exec_result()

        self.domain = AGENT_DOMAINS["disk"]
        self.tools = [
            {
                "name": "fls",
                "display_name": "fls",
                "path": "/usr/bin/fls",
                "description": "List files",
            }
        ]

    @patch("agents.base.call_claude_json")
    def test_investigate_returns_findings(self, mock_claude):
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": "/usr/bin/fls",
                        "args": ["-r", "/cases/img.E01"],
                        "reasoning": "list files",
                        "expected_outcome": "file listing",
                    }
                ]
            },
            {
                "findings": [
                    {
                        "description": "Found suspicious file",
                        "confidence": "confirmed",
                        "evidence_links": ["e001"],
                    }
                ]
            },
        ]

        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )
        result = agent.investigate("Analyze disk", "/cases/img.E01", "malware")

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].confidence, "confirmed")
        self.assertEqual(result.agent_name, "disk_agent")
        self.executor.run.assert_called_once()

    def test_format_tools_tolerates_string_and_dict_usage_examples(self):
        # The locally-built catalog emits usage_examples as plain command STRINGS;
        # older/seed catalogs use {"command","title"} dicts. _format_tools (and
        # therefore the whole dispatch) must handle BOTH — a string example
        # previously crashed every sub-agent with "string indices must be
        # integers", yielding a 0-finding run.
        tools = [
            {
                "name": "rip.pl",
                "path": "/usr/local/bin/rip.pl",
                "description": "registry parser",
                "usage_examples": ["rip.pl -r SYSTEM -f system"],
            },
            {
                "name": "fls",
                "path": "/usr/bin/fls",
                "description": "list files",
                "usage_examples": [{"command": "fls -r img", "title": "list"}],
            },
            {"name": "vol", "path": "/usr/local/bin/vol", "description": "memory"},
        ]
        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, tools
        )
        out = agent._format_tools()
        self.assertIn("`rip.pl -r SYSTEM -f system`", out)  # string example
        self.assertIn("`fls -r img` — list", out)  # dict example
        self.assertIn("vol", out)  # no usage_examples -> no crash

    @patch("agents.base.call_claude_json")
    def test_finding_carries_timestamp_and_artifact_type(self, mock_claude):
        # Correlation keys on a finding's event timestamp + artifact type, so the
        # interpretation step must extract them and they must reach the Finding.
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": "/usr/bin/fls",
                        "args": ["-r", "/cases/img.E01"],
                        "reasoning": "list files",
                        "expected_outcome": "file listing",
                    }
                ]
            },
            {
                "findings": [
                    {
                        "description": "Run key 'evil.exe' added",
                        "confidence": "confirmed",
                        "evidence_links": ["e001"],
                        "timestamp": "2026-03-15T08:42:01Z",
                        "artifact_type": "registry",
                    }
                ]
            },
        ]

        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )
        result = agent.investigate("Analyze disk", "/cases/img.E01", "persistence")

        self.assertEqual(result.findings[0].timestamp, "2026-03-15T08:42:01Z")
        self.assertEqual(result.findings[0].artifact_type, "registry")

    @patch("agents.base.call_claude_json")
    def test_investigate_handles_no_plan(self, mock_claude):
        mock_claude.return_value = None

        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )
        result = agent.investigate("Analyze disk", "/cases/img.E01")

        self.assertEqual(len(result.findings), 0)
        self.assertIn("Failed to get execution plan", result.errors[0])

    @patch("agents.base.call_claude_json")
    def test_investigate_handles_rejected_command(self, mock_claude):
        mock_claude.side_effect = [
            {
                "commands": [
                    {"tool_path": "/usr/bin/rm", "args": ["-rf", "/"], "reasoning": ""}
                ]
            },
            # Closed loop: after the rejected command produces no usable output, the
            # next step ends the loop (no further commands, no findings).
            {"commands": []},
        ]
        self.executor.run.return_value = _make_exec_result(
            rejected=True, rejection_reason="Tool not in allowlist: /usr/bin/rm"
        )

        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )
        result = agent.investigate("Analyze disk", "/cases/img.E01")

        self.assertIn("Rejected", result.errors[0])

    @patch("agents.base.call_claude_json")
    def test_finding_without_successful_execution_is_dropped(self, mock_claude):
        """A finding whose only evidence_link is a FAILED execution must not become a
        finding; it is recorded as a limitation instead."""
        self.executor.run.return_value = _make_exec_result(
            execution_id="e-fail", exit_code=1, stdout="", stderr="fls: cannot open"
        )
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": "/usr/bin/fls",
                        "args": ["-o", "128", "/cases/img.E01"],
                        "reasoning": "list",
                        "expected_outcome": "files",
                    }
                ]
            },
            {
                "findings": [
                    {
                        "description": "evil at offset 128",
                        "confidence": "confirmed",
                        "evidence_links": ["e-fail"],
                    }
                ]
            },
        ]
        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )
        result = agent.investigate("Analyze disk", "/cases/img.E01", "malware")

        self.assertEqual(result.findings, [])
        self.assertTrue(any("evil at offset 128" in lim for lim in result.limitations))

    @patch("agents.base.call_claude_json")
    def test_failed_execution_link_is_not_counted_as_hallucination(self, mock_claude):
        """A link citing a real-but-FAILED execution is unsuccessful evidence, not
        an invented ID: only links that match no execution at all are
        hallucinations. The failed-exec link must be dropped (no finding) without
        inflating the hallucination signal, while a truly invented ID must."""
        self.executor.run.return_value = _make_exec_result(
            execution_id="e-fail", exit_code=1, stdout="", stderr="fls: cannot open"
        )
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": "/usr/bin/fls",
                        "args": ["-o", "128", "/cases/img.E01"],
                        "reasoning": "list",
                        "expected_outcome": "files",
                    }
                ]
            },
            {
                "findings": [
                    {
                        "description": "cites a real but failed execution",
                        "confidence": "confirmed",
                        "evidence_links": ["e-fail"],
                    },
                    {
                        "description": "cites an execution that never ran",
                        "confidence": "confirmed",
                        "evidence_links": ["ghost-id"],
                    },
                ]
            },
        ]
        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )
        result = agent.investigate("Analyze disk", "/cases/img.E01", "malware")

        # Invented ID is a hallucination; the real-but-failed ID is not.
        self.assertIn("ghost-id", result.hallucinated_links)
        self.assertNotIn("e-fail", result.hallucinated_links)
        # Both findings are still dropped (neither has a successful backing).
        self.assertEqual(result.findings, [])

    @patch("agents.base.call_claude_json")
    def test_interpret_results_passes_outputs_and_returns_findings(self, mock_claude):
        """Characterization: _interpret_results sends the tool outputs to the LLM and
        returns the findings list it gets back. Pins behaviour before the
        _build_interpret_prompt extraction."""
        mock_claude.return_value = {
            "findings": [
                {
                    "description": "d",
                    "confidence": "possible",
                    "evidence_links": ["e001"],
                }
            ]
        }
        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )
        outputs = [
            {
                "tool": "/usr/bin/strings",
                "args": [],
                "exit_code": 0,
                "stdout": "noise",
                "stderr": "",
                "expected": "",
                "execution_id": "e001",
            }
        ]
        findings = agent._interpret_results("task", "hyp", outputs)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["description"], "d")
        sent_prompt = mock_claude.call_args.args[0]
        self.assertIn("noise", sent_prompt)
        self.assertIn("e001", sent_prompt)

    def test_interpret_prompt_forbids_failures_as_findings(self):
        """The interpret prompt must instruct the model to route tool failures and
        tool/environment limitations to a limitations section, never the findings
        list, and to require each finding cite an execution that produced output."""
        agent = DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )
        prompt = agent._build_interpret_prompt(
            "task",
            "hyp",
            [
                {
                    "tool": "/usr/bin/strings",
                    "args": [],
                    "exit_code": 0,
                    "stdout": "noise",
                    "stderr": "",
                    "expected": "",
                    "execution_id": "e1",
                }
            ],
        )
        low = prompt.lower()
        self.assertIn("do not", low)
        self.assertTrue("tool failure" in low or "failed command" in low)
        self.assertIn("limitation", low)


class DomainPromptTest(unittest.TestCase):
    """Disk-touching domains steer agents to the mounted filesystem first."""

    DISK_DOMAINS = ["disk", "timeline", "artifacts", "malware"]

    def test_disk_domains_reference_the_mount(self):
        for name in self.DISK_DOMAINS:
            prompt = AGENT_DOMAINS[name].system_prompt.lower()
            self.assertIn(
                "mount", prompt, f"{name} prompt should reference the mounted tree"
            )

    def test_disk_domains_keep_sleuth_kit_for_deleted_files(self):
        for name in self.DISK_DOMAINS:
            prompt = AGENT_DOMAINS[name].system_prompt.lower()
            self.assertIn("deleted", prompt, f"{name} should cover deleted files")
            self.assertTrue(
                "icat" in prompt or "fls" in prompt,
                f"{name} should retain Sleuth Kit for deleted/inode recovery",
            )

    def test_disk_domains_do_not_mandate_manual_partition_mount_first(self):
        # The mounted-first workflow must not open with manual partition mounting
        # as the required first step (the old offset-based workflow header).
        for name in self.DISK_DOMAINS:
            prompt = AGENT_DOMAINS[name].system_prompt
            self.assertNotIn("Step 1: Determine the partition layout", prompt)


class DomainSystemIdentificationTest(unittest.TestCase):
    """The artifacts domain steers the agent to establish host/owner identity
    FIRST, via the system-identification registry plugins, so the baseline
    system-ID items (computer name, registered owner, accounts/SIDs, timezone,
    network identity) are recovered instead of only user-activity artifacts."""

    def setUp(self):
        self.prompt = AGENT_DOMAINS["artifacts"].system_prompt
        self.low = self.prompt.lower()

    def test_lists_each_system_identification_plugin(self):
        # The host/owner identification plugins must be named explicitly so the
        # agent runs them rather than the user-activity plugins it defaulted to.
        for plugin in ("compname", "winnt_cv", "timezone", "samparse", "nic2"):
            self.assertIn(
                plugin,
                self.low,
                f"artifacts prompt should name the {plugin} system-ID plugin",
            )

    def test_identification_is_prioritized_first(self):
        # Identity must be framed as the up-front step, not buried in a flat list
        # alongside user-activity plugins (the cause of the registry recall miss).
        self.assertIn("identif", self.low)
        self.assertTrue(
            "first" in self.low or "up front" in self.low,
            "system identification should be steered as a first/up-front step",
        )

    def test_steers_registry_key_ioc_findings(self):
        # The recovered facts must be emitted as registry_key IOC findings whose
        # value is the hive-relative key path (what the path-aware scorer matches).
        self.assertIn("registry_key", self.low)

    def test_names_the_identity_facts_to_recover(self):
        # Tie the plugins to the concrete facts the baseline scores, so the agent
        # knows what to report (and as which IOC).
        for fact in ("computername", "registeredowner"):
            self.assertIn(fact, self.low.replace(" ", ""))
        # Network identity (IP/MAC) is reported as an `ip` IOC, not registry_key.
        self.assertIn("ip address", self.low)

    def test_identification_is_os_conditional_not_windows_only(self):
        # We also get Linux/macOS E01s — the agent must pick the identity set that
        # matches the image's OS and NOT run Windows registry plugins on a
        # non-Windows image.
        self.assertIn("linux", self.low)
        self.assertIn("macos", self.low)
        self.assertIn("non-windows", self.low)

    def test_covers_linux_identity_sources(self):
        # Linux identity comes from flat files on the mount, not the registry.
        self.assertIn("/etc/passwd", self.low)
        self.assertTrue(
            "/etc/hostname" in self.low or "os-release" in self.low,
            "linux identity should reference hostname / os-release",
        )

    def test_covers_macos_identity_sources(self):
        # macOS identity comes from plists (often binary -> plutil/PlistBuddy).
        self.assertIn(".plist", self.low)
        self.assertIn("systemversion.plist", self.low)

    def test_handles_triage_partial_images(self):
        # A triage E01 is a logical artifact collection, not a full disk: locate
        # sources with find, and record a missing source as a limitation rather
        # than fabricating the value.
        self.assertIn("triage", self.low)
        self.assertIn("find", self.low)
        self.assertIn("limitation", self.low)


class EmitIdentityFindingsPromptTest(unittest.TestCase):
    """Both the plan prompt and the interpret prompt must direct the agent to emit
    standard forensic-report identity/account/config-file facts as their OWN
    findings — even when they are background to the hypothesis. A hypothesis-driven
    agent otherwise summarizes these away (measured: the host IP, *.ini contents,
    and email addresses were captured by tools but never emitted as findings)."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        self.progress = ProgressTracker(Path(self._tmpdir) / "progress.json")
        self.progress.start("inv-test", "/cases/img.E01", "disk")
        self.executor = MagicMock(spec=LocalExecutor)
        self.executor.run.return_value = _make_exec_result()
        self.agent = DomainAgent(
            AGENT_DOMAINS["artifacts"],
            self.executor,
            self.audit,
            self.progress,
            [{"name": "rip", "display_name": "rip", "path": "/usr/bin/rip.pl",
              "description": "registry"}],
        )

    def _plan(self) -> str:
        return self.agent._build_plan_prompt(
            "task", "/cases/img.E01", "hypo", "", mount_roots=["/mnt/p1"]
        ).lower()

    def _interpret(self) -> str:
        return self.agent._build_interpret_prompt("task", "hypo", []).lower()

    def _assert_directive(self, p: str, where: str):
        self.assertIn("ip address", p, f"{where}: emit host IP as a finding")
        self.assertIn("mac address", p, f"{where}: emit MAC")
        self.assertIn("email", p, f"{where}: emit email/account artifacts")
        self.assertIn("config", p, f"{where}: parse config-file contents")
        self.assertIn(".ini", p, f"{where}: name a config-file example")
        # framed as emit-even-when-background, not hypothesis-only
        self.assertIn("background", p, f"{where}: emit even if background")

    def test_plan_prompt_directs_identity_emission(self):
        self._assert_directive(self._plan(), "plan prompt")

    def test_interpret_prompt_directs_identity_emission(self):
        self._assert_directive(self._interpret(), "interpret prompt")


class SubAgentMountRootsTest(unittest.TestCase):
    """The plan prompt points the agent at the mounted filesystem when present."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        self.progress = ProgressTracker(Path(self._tmpdir) / "progress.json")
        self.progress.start("inv-test", "/cases/img.E01", "disk")
        self.executor = MagicMock(spec=LocalExecutor)
        self.executor.run.return_value = _make_exec_result()
        self.domain = AGENT_DOMAINS["disk"]
        self.tools = [
            {
                "name": "fls",
                "display_name": "fls",
                "path": "/usr/bin/fls",
                "description": "List files",
            }
        ]

    def _agent(self) -> DomainAgent:
        return DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )

    def test_plan_prompt_presents_mounted_roots_and_raw_image(self):
        prompt = self._agent()._build_plan_prompt(
            "Test hypothesis",
            "/cases/img.E01",
            "some hypothesis",
            "",
            mount_roots=["/mnt/sift/p1", "/mnt/sift/p2"],
        )
        # Both mounted roots are offered for browsing live files...
        self.assertIn("/mnt/sift/p1", prompt)
        self.assertIn("/mnt/sift/p2", prompt)
        # ...and the raw image is still offered for deleted-file recovery.
        self.assertIn("/cases/img.E01", prompt)
        self.assertIn("mounted", prompt.lower())

    def test_plan_prompt_raw_only_when_no_mounts(self):
        prompt = self._agent()._build_plan_prompt(
            "Test hypothesis",
            "/cases/mem.raw",
            "some hypothesis",
            "",
            mount_roots=[],
        )
        self.assertIn("/cases/mem.raw", prompt)
        # With nothing mounted, the prompt must not claim a mounted filesystem.
        self.assertNotIn("mounted read-only at", prompt.lower())

    @patch("agents.base.call_claude_json")
    def test_investigate_threads_mount_roots_into_prompt(self, mock_claude):
        mock_claude.side_effect = [
            {"commands": []},  # plan with no commands -> short-circuits
        ]
        self._agent().investigate(
            "Analyze disk",
            "/cases/img.E01",
            "malware",
            mount_roots=["/mnt/sift/p1"],
        )
        plan_prompt = mock_claude.call_args_list[0][0][0]
        self.assertIn("/mnt/sift/p1", plan_prompt)


class SubAgentFallbackTest(unittest.TestCase):
    """The agent recovers from tool failures via the advisor."""

    MFTECMD = {
        "name": "MFTECmd",
        "path": "/opt/zimmermantools/MFTECmd.exe",
        "symlink": "/usr/local/bin/mftecmd",
        "runtime": ".NET",
        "category": "windows_artifact_analysis",
        "description": "MFT parser (.NET)",
    }
    ANALYZEMFT = {
        "name": "analyzemft",
        "path": "/opt/analyzemft/bin/analyzemft",
        "symlink": "/usr/local/bin/analyzemft",
        "category": "windows_artifact_analysis",
        "description": "MFT parser (Python)",
    }
    FOREMOST = {
        "name": "foremost",
        "path": "/usr/bin/foremost",
        "category": "file_carving_recovery",
        "description": "File carver",
    }
    SCALPEL = {
        "name": "scalpel",
        "path": "/usr/bin/scalpel",
        "category": "file_carving_recovery",
        "description": "File carver",
    }

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        self.progress = ProgressTracker(Path(self._tmpdir) / "progress.json")
        self.progress.start("inv-test", "/cases/img.E01", "disk")
        self.executor = MagicMock(spec=LocalExecutor)
        self.domain = AGENT_DOMAINS["artifacts"]

    @patch("agents.base.call_claude_json")
    def test_prevalidation_skips_dotnet_and_falls_back(self, mock_claude):
        # The .NET tool is caught before it ever runs; the Python equivalent runs.
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": self.MFTECMD["path"],
                        "args": ["/cases/MFT"],
                        "reasoning": "parse MFT",
                        "expected_outcome": "MFT records",
                    }
                ]
            },
            {
                "findings": [
                    {
                        "description": "Parsed MFT",
                        "confidence": "confirmed",
                        "evidence_links": ["e100"],
                    }
                ]
            },
        ]
        self.executor.run.return_value = _make_exec_result(
            execution_id="e100", stdout="MFT parsed", exit_code=0
        )

        agent = DomainAgent(
            self.domain,
            self.executor,
            self.audit,
            self.progress,
            [self.MFTECMD, self.ANALYZEMFT],
            advisor=ToolAdvisor(host_os="Linux"),
        )
        result = agent.investigate("Parse MFT", "/cases/img.E01", "mft hypothesis")

        # MFTECmd never executed (pre-validated out); only analyzemft ran.
        self.executor.run.assert_called_once()
        self.assertEqual(
            self.executor.run.call_args.kwargs["tool_path"], self.ANALYZEMFT["path"]
        )
        self.assertEqual(result.tools_used, [self.ANALYZEMFT["path"]])
        self.assertEqual(len(result.findings), 1)
        # No extra LLM call — fallback reuses args deterministically.
        self.assertEqual(mock_claude.call_count, 2)

    @patch("agents.base.call_claude_json")
    def test_falls_back_on_execution_failure(self, mock_claude):
        # foremost runs and fails; the advisor routes to scalpel with the same args.
        args = ["-i", "/cases/image.E01", "-o", "/tmp/out"]
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": self.FOREMOST["path"],
                        "args": args,
                        "reasoning": "carve files",
                        "expected_outcome": "recovered files",
                    }
                ]
            },
            {
                "findings": [
                    {
                        "description": "Recovered files",
                        "confidence": "inferred",
                        "evidence_links": ["e201"],
                    }
                ]
            },
        ]
        self.executor.run.side_effect = [
            _make_exec_result(exit_code=1, stderr="carve error", execution_id="e200"),
            _make_exec_result(exit_code=0, stdout="carved", execution_id="e201"),
        ]

        agent = DomainAgent(
            self.domain,
            self.executor,
            self.audit,
            self.progress,
            [self.FOREMOST, self.SCALPEL],
            advisor=ToolAdvisor(host_os="Linux"),
        )
        result = agent.investigate(
            "Carve files", "/cases/img.E01", "carving hypothesis"
        )

        self.assertEqual(self.executor.run.call_count, 2)
        # The fallback ran scalpel with the original args, verbatim.
        second_call = self.executor.run.call_args_list[1]
        self.assertEqual(second_call.kwargs["tool_path"], self.SCALPEL["path"])
        self.assertEqual(second_call.kwargs["args"], args)
        self.assertIn(self.SCALPEL["path"], result.tools_used)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(mock_claude.call_count, 2)


class VerifierAgentTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        self.executor = MagicMock(spec=LocalExecutor)
        self.tools = [
            {
                "name": "fls",
                "display_name": "fls",
                "path": "/usr/bin/fls",
                "description": "List files",
            }
        ]

    @patch("agents.base.call_claude_json")
    def test_verify_confirms_when_output_supports(self, mock_claude):
        mock_claude.return_value = {
            "output_supports_claim": True,
            "counter_evidence_commands": [],
            "alternative_explanation": "none",
        }

        verifier = VerifierAgent(self.executor, self.audit, self.tools)
        verdict = verifier.verify(_make_finding(), [], "/cases/img.E01")

        self.assertEqual(verdict, "confirmed")

    @patch("agents.base.call_claude_json")
    def test_verify_refutes_when_output_doesnt_support(self, mock_claude):
        mock_claude.return_value = {
            "output_supports_claim": False,
            "output_analysis": "No evidence of this in the output",
        }

        verifier = VerifierAgent(self.executor, self.audit, self.tools)
        verdict = verifier.verify(_make_finding(), [], "/cases/img.E01")

        self.assertEqual(verdict, "refuted")

    @patch("agents.base.call_claude_json")
    def test_verify_validates_verdict_values(self, mock_claude):
        mock_claude.side_effect = [
            {
                "output_supports_claim": True,
                "counter_evidence_commands": [
                    {"tool_path": "/usr/bin/fls", "args": ["-r"], "looking_for": "x"}
                ],
            },
            {"verdict": "invalid_value", "reasoning": "bad LLM output"},
        ]
        self.executor.run.return_value = _make_exec_result()

        verifier = VerifierAgent(self.executor, self.audit, self.tools)
        verdict = verifier.verify(_make_finding(), [], "/cases/img.E01")

        self.assertEqual(verdict, "confirmed")

    @patch("agents.base.call_claude_json")
    def test_verify_defaults_to_confirmed_on_claude_failure(self, mock_claude):
        mock_claude.return_value = None

        verifier = VerifierAgent(self.executor, self.audit, self.tools)
        verdict = verifier.verify(_make_finding(), [], "/cases/img.E01")

        self.assertEqual(verdict, "confirmed")


class TestEvidenceLinkReconciliation(unittest.TestCase):
    """A finding's claimed evidence links are reconciled against the execution
    IDs that actually ran. Links with no backing execution are dropped and
    surfaced as a hallucination signal — a finding may only cite output that was
    really produced."""

    def test_keeps_only_backed_links(self):
        valid, unbacked = reconcile_evidence_links(
            ["e1", "e2", "ghost"], ["e1", "e2", "e3"]
        )
        self.assertEqual(valid, ["e1", "e2"])
        self.assertEqual(unbacked, ["ghost"])

    def test_all_links_backed(self):
        valid, unbacked = reconcile_evidence_links(["e1"], ["e1", "e2"])
        self.assertEqual(valid, ["e1"])
        self.assertEqual(unbacked, [])

    def test_no_claimed_links(self):
        valid, unbacked = reconcile_evidence_links([], ["e1"])
        self.assertEqual(valid, [])
        self.assertEqual(unbacked, [])

    def test_fully_hallucinated_links_all_unbacked(self):
        valid, unbacked = reconcile_evidence_links(["x", "y"], ["e1"])
        self.assertEqual(valid, [])
        self.assertEqual(unbacked, ["x", "y"])

    def test_preserves_claimed_order(self):
        valid, _ = reconcile_evidence_links(["e3", "e1"], ["e1", "e2", "e3"])
        self.assertEqual(valid, ["e3", "e1"])


class CallClaudeRetryTest(unittest.TestCase):
    """`call_claude` retries transient API/transport failures (5xx, resets,
    timeouts) before giving up, and maps failures to typed errors. The HTTP
    transport (`_post_messages`) is mocked so no network call is made."""

    def setUp(self):
        # Avoid the real backoff sleep slowing the suite down.
        sleep_patcher = patch("agents.claude.time.sleep")
        self.mock_sleep = sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)

    @patch("agents.claude._post_messages")
    def test_returns_text_on_first_success(self, mock_post):
        mock_post.return_value = "hello"
        self.assertEqual(call_claude("prompt"), "hello")
        self.assertEqual(mock_post.call_count, 1)
        self.mock_sleep.assert_not_called()

    @patch("agents.claude._post_messages")
    def test_retries_then_succeeds(self, mock_post):
        mock_post.side_effect = [ClaudeError("transient status 503"), "recovered"]
        self.assertEqual(call_claude("prompt"), "recovered")
        self.assertEqual(mock_post.call_count, 2)
        self.mock_sleep.assert_called_once()

    @patch("agents.claude._post_messages")
    def test_exhausts_retries_and_raises_last_error(self, mock_post):
        mock_post.side_effect = ClaudeError("status 500: boom")
        with self.assertRaises(ClaudeError) as ctx:
            call_claude("prompt")
        self.assertEqual(mock_post.call_count, claude_mod._MAX_ATTEMPTS)
        self.assertIn("boom", str(ctx.exception))

    @patch("agents.claude._post_messages")
    def test_all_timeouts_raise_timeout_error(self, mock_post):
        mock_post.side_effect = ClaudeTimeoutError("timed out")
        with self.assertRaises(ClaudeTimeoutError):
            call_claude("prompt")
        self.assertEqual(mock_post.call_count, claude_mod._MAX_ATTEMPTS)

    @patch("agents.claude._post_messages")
    def test_missing_transport_raises_immediately_without_retry(self, mock_post):
        mock_post.side_effect = ClaudeNotFoundError("no credentials")
        with self.assertRaises(ClaudeNotFoundError):
            call_claude("prompt")
        # Missing credentials are not transient — no retry, no backoff.
        self.assertEqual(mock_post.call_count, 1)
        self.mock_sleep.assert_not_called()

    @patch("agents.claude._post_messages")
    def test_honors_retry_after_on_rate_limit(self, mock_post):
        err = ClaudeError("status 429: rate limited")
        err.retry_after = 7.0  # server-provided Retry-After (seconds)
        mock_post.side_effect = [err, "ok"]
        self.assertEqual(call_claude("prompt"), "ok")
        self.mock_sleep.assert_called_once_with(7.0)


class CallClaudeJsonTest(unittest.TestCase):
    """`call_claude_json` parses the response, tolerates code fences, and
    returns None (rather than raising) when the underlying call fails."""

    @patch("agents.claude.call_claude")
    def test_parses_plain_json(self, mock_call):
        mock_call.return_value = '{"hypotheses": []}'
        self.assertEqual(call_claude_json("prompt"), {"hypotheses": []})

    @patch("agents.claude.call_claude")
    def test_strips_json_code_fence(self, mock_call):
        mock_call.return_value = '```json\n{"ok": true}\n```'
        self.assertEqual(call_claude_json("prompt"), {"ok": True})

    @patch("agents.claude.call_claude")
    def test_returns_none_when_call_fails(self, mock_call):
        mock_call.side_effect = ClaudeError("every attempt failed")
        self.assertIsNone(call_claude_json("prompt"))

    @patch("agents.claude.call_claude")
    def test_returns_none_on_unparseable_output(self, mock_call):
        mock_call.return_value = "not json at all"
        self.assertIsNone(call_claude_json("prompt"))

    @patch("agents.claude.call_claude")
    def test_parses_json_after_leading_preamble(self, mock_call):
        # Headless `claude --print` sometimes prepends commentary (e.g. a
        # skill-activation preamble injected by local hooks) before a fenced
        # JSON block. The valid JSON must still be extracted, not dropped.
        mock_call.return_value = (
            "No skills apply — this is a forensic task requiring JSON-only "
            'output.\n\n```json\n{"hypotheses": [{"id": "H1"}]}\n```'
        )
        self.assertEqual(call_claude_json("prompt"), {"hypotheses": [{"id": "H1"}]})

    @patch("agents.claude.call_claude")
    def test_parses_bare_json_object_surrounded_by_prose(self, mock_call):
        mock_call.return_value = 'Here is the result: {"commands": []} — done.'
        self.assertEqual(call_claude_json("prompt"), {"commands": []})


class DomainPromptScratchTest(unittest.TestCase):
    """Domain system prompts must not hardcode /tmp for tool output. /tmp is not
    under the executor's allowlist, so any tool the prompt steered to /tmp was
    rejected. Output guidance must reference the task-provided scratch dir."""

    def test_no_domain_prompt_hardcodes_tmp(self):
        for name, domain in AGENT_DOMAINS.items():
            self.assertNotIn(
                "/tmp",
                domain.system_prompt,
                f"{name} domain prompt hardcodes /tmp; tool output must be "
                "directed to the scratch directory named in the agent's task",
            )


class SubAgentScratchTest(unittest.TestCase):
    """The sub-agent surfaces the executor's scratch dir to the LLM (so it writes
    output there) and runs each tool with the scratch dir as cwd."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        self.progress = ProgressTracker(Path(self._tmpdir) / "progress.json")
        self.progress.start("inv-test", "/cases/img.E01", "disk")
        self.executor = MagicMock(spec=LocalExecutor)
        self.executor.run.return_value = _make_exec_result()
        self.executor.scratch_dir = "/work/scratch"
        self.domain = AGENT_DOMAINS["disk"]
        self.tools = [
            {
                "name": "fls",
                "display_name": "fls",
                "path": "/usr/bin/fls",
                "description": "List files",
            }
        ]

    def _agent(self) -> DomainAgent:
        return DomainAgent(
            self.domain,
            self.executor,
            self.audit,
            self.progress,
            self.tools,
            advisor=ToolAdvisor(host_os="Linux"),
        )

    @patch("agents.base.call_claude_json")
    def test_plan_prompt_directs_output_to_scratch_dir(self, mock_claude):
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": "/usr/bin/fls",
                        "args": ["-r", "/cases/img.E01"],
                        "reasoning": "list",
                        "expected_outcome": "files",
                    }
                ]
            },
            {"findings": [
                {"description": "ok", "confidence": "possible",
                 "evidence_links": ["e001"]}
            ]},
        ]
        self._agent().investigate("Map disk", "/cases/img.E01", "disk hypothesis")
        plan_prompt = mock_claude.call_args_list[0].args[0]
        self.assertIn("/work/scratch", plan_prompt)

    @patch("agents.base.call_claude_json")
    def test_tool_runs_with_scratch_dir_as_cwd(self, mock_claude):
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": "/usr/bin/fls",
                        "args": ["-r", "/cases/img.E01"],
                        "reasoning": "list",
                        "expected_outcome": "files",
                    }
                ]
            },
            {"findings": [
                {"description": "ok", "confidence": "possible",
                 "evidence_links": ["e001"]}
            ]},
        ]
        self._agent().investigate("Map disk", "/cases/img.E01", "disk hypothesis")
        self.assertEqual(self.executor.run.call_args.kwargs["cwd"], "/work/scratch")

    @patch("agents.base.call_claude_json")
    def test_plan_prompt_includes_primary_offset(self, mock_claude):
        # The orchestrator knows the filesystem's start sector; passing it stops
        # the sub-agent guessing a wrong -o (e.g. 2048 on a single-volume image,
        # which fails "Cannot determine file system type").
        mock_claude.side_effect = [
            {
                "commands": [
                    {
                        "tool_path": "/usr/bin/fls",
                        "args": ["-r", "/cases/img.E01"],
                        "reasoning": "list",
                        "expected_outcome": "files",
                    }
                ]
            },
            {"findings": [
                {"description": "ok", "confidence": "possible",
                 "evidence_links": ["e001"]}
            ]},
        ]
        self._agent().investigate(
            "Map disk", "/cases/img.E01", "disk hypothesis", primary_offset=0
        )
        plan_prompt = mock_claude.call_args_list[0].args[0]
        self.assertIn("SECTOR OFFSET 0", plan_prompt)
        self.assertIn("-o 0", plan_prompt)


class SubAgentClosedLoopTest(unittest.TestCase):
    """The sub-agent runs a bounded ReAct loop: it sees each command's real
    output before planning the next, so a value discovered in one step (an inode,
    a path) is substituted into the next command instead of a placeholder."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        self.progress = ProgressTracker(Path(self._tmpdir) / "progress.json")
        self.progress.start("inv-test", "/cases/img.E01", "disk")
        self.executor = MagicMock(spec=LocalExecutor)
        self.domain = AGENT_DOMAINS["disk"]
        self.tools = [
            {"name": "ifind", "display_name": "ifind", "path": "/usr/bin/ifind",
             "description": "find inode by name"},
            {"name": "icat", "display_name": "icat", "path": "/usr/bin/icat",
             "description": "extract by inode"},
        ]

    def _agent(self) -> DomainAgent:
        return DomainAgent(
            self.domain, self.executor, self.audit, self.progress, self.tools
        )

    @patch("agents.base.call_claude_json")
    def test_prior_output_is_fed_into_next_step_prompt(self, mock_claude):
        # Step 1 finds inode 12345; step 2 must use that REAL value, proving the
        # loop fed step 1's output back into step 2's planning prompt (this is the
        # fix for the open-loop "<SOFTWARE_inode>" placeholder bug).
        self.executor.run.side_effect = [
            _make_exec_result(
                execution_id="e1",
                stdout="12345  WINDOWS/system32/config/software",
            ),
            _make_exec_result(execution_id="e2", stdout="regf hive bytes"),
        ]
        mock_claude.side_effect = [
            {"commands": [{
                "tool_path": "/usr/bin/ifind",
                "args": ["-n", "WINDOWS/system32/config/software", "/cases/img.E01"],
                "reasoning": "find hive inode",
                "expected_outcome": "inode",
            }]},
            {"commands": [{
                "tool_path": "/usr/bin/icat",
                "args": ["/cases/img.E01", "12345"],
                "reasoning": "extract hive",
                "expected_outcome": "hive bytes",
            }]},
            {"findings": [{
                "description": "SOFTWARE hive extracted",
                "confidence": "confirmed",
                "evidence_links": ["e2"],
            }]},
        ]
        result = self._agent().investigate(
            "Extract SOFTWARE hive", "/cases/img.E01", "registry"
        )
        self.assertEqual(self.executor.run.call_count, 2)
        step2_prompt = mock_claude.call_args_list[1].args[0]
        self.assertIn("12345", step2_prompt)
        self.assertEqual(len(result.findings), 1)

    @patch("agents.base.call_claude_json")
    def test_empty_findings_list_does_not_end_the_loop(self, mock_claude):
        # The model echoes an empty "findings": [] alongside its commands every
        # turn (it is in the response schema). That must NOT be read as "done" —
        # otherwise the agent stops after one command with zero findings.
        self.executor.run.side_effect = [
            _make_exec_result(execution_id="e1", stdout="found it"),
            _make_exec_result(execution_id="e2", stdout="more"),
        ]
        mock_claude.side_effect = [
            {"commands": [{
                "tool_path": "/usr/bin/ifind",
                "args": ["-n", "f", "/cases/img.E01"],
                "reasoning": "r", "expected_outcome": "o",
            }], "findings": []},  # empty findings + a command -> keep going
            {"commands": [{
                "tool_path": "/usr/bin/icat",
                "args": ["/cases/img.E01", "12345"],
                "reasoning": "r", "expected_outcome": "o",
            }], "findings": []},  # still empty -> keep going
            {"commands": [], "findings": [{
                "description": "real finding",
                "confidence": "confirmed",
                "evidence_links": ["e2"],
            }]},  # non-empty findings -> done
        ]
        result = self._agent().investigate("t", "/cases/img.E01", "h")
        self.assertEqual(self.executor.run.call_count, 2)  # did NOT stop early
        self.assertEqual(len(result.findings), 1)

    @patch("agents.base.call_claude_json")
    def test_findings_response_stops_the_loop(self, mock_claude):
        self.executor.run.return_value = _make_exec_result(
            execution_id="e1", stdout="x"
        )
        mock_claude.side_effect = [
            {"commands": [{
                "tool_path": "/usr/bin/ifind",
                "args": ["-n", "f", "/cases/img.E01"],
                "reasoning": "r", "expected_outcome": "o",
            }]},
            {"findings": [{
                "description": "done early",
                "confidence": "confirmed",
                "evidence_links": ["e1"],
            }]},
        ]
        result = self._agent().investigate("t", "/cases/img.E01", "h")
        self.assertEqual(mock_claude.call_count, 2)  # stops once findings arrive
        self.assertEqual(len(result.findings), 1)

    @patch("agents.base.call_claude_json")
    def test_no_progress_guard_stops_repeated_commands(self, mock_claude):
        # A model that keeps re-issuing the SAME command (learning nothing new)
        # must be stopped well before MAX_STEPS by the no-progress guard.
        self.executor.run.return_value = _make_exec_result(
            execution_id="e1", stdout="same output"
        )
        same = {
            "commands": [{
                "tool_path": "/usr/bin/ifind",
                "args": ["-n", "f", "/cases/img.E01"],
                "reasoning": "r", "expected_outcome": "o",
            }],
            "findings": [],
        }
        interp = {"findings": [{
            "description": "x", "confidence": "possible", "evidence_links": ["e1"],
        }]}
        mock_claude.side_effect = [same] * DomainAgent.MAX_STEPS + [interp]
        self._agent().investigate("t", "/cases/img.E01", "h")
        # First new command + MAX_NO_PROGRESS_STEPS repeats, then stop — far below
        # the hard MAX_STEPS cap.
        self.assertEqual(
            self.executor.run.call_count, DomainAgent.MAX_NO_PROGRESS_STEPS + 1
        )
        self.assertLess(self.executor.run.call_count, DomainAgent.MAX_STEPS)

    @patch("agents.base.call_claude_json")
    def test_loop_is_bounded_by_max_steps(self, mock_claude):
        self.executor.run.return_value = _make_exec_result(
            execution_id="e1", stdout="x"
        )
        # A DISTINCT command each turn (so the no-progress guard never fires) that
        # never returns findings -> the loop must cap at MAX_STEPS, then run one
        # final interpret to turn the accumulated outputs into findings.
        mock_claude.side_effect = [
            {"commands": [{
                "tool_path": "/usr/bin/ifind",
                "args": ["-n", f"f{i}", "/cases/img.E01"],
                "reasoning": "r", "expected_outcome": "o",
            }], "findings": []}
            for i in range(DomainAgent.MAX_STEPS)
        ] + [
            {"findings": [{
                "description": "interpreted",
                "confidence": "possible",
                "evidence_links": ["e1"],
            }]}
        ]
        result = self._agent().investigate("t", "/cases/img.E01", "h")
        self.assertEqual(mock_claude.call_count, DomainAgent.MAX_STEPS + 1)
        self.assertEqual(self.executor.run.call_count, DomainAgent.MAX_STEPS)
        self.assertEqual(len(result.findings), 1)


class CallClaudeNullByteTest(unittest.TestCase):
    """Tool output fed back into prompts can contain raw NUL bytes (reading a
    registry hive / binary file). They are stripped before the request so the
    prompt stays clean (a NUL previously crashed the subprocess transport)."""

    @patch("agents.claude._post_messages")
    def test_call_claude_strips_null_bytes(self, mock_post):
        mock_post.return_value = "ok"
        call_claude("before\x00after", system_prompt="sys\x00tem")
        sent_prompt = mock_post.call_args.args[0]
        sent_system = mock_post.call_args.args[1]
        self.assertNotIn("\x00", sent_prompt)
        self.assertNotIn("\x00", sent_system)
        self.assertIn("beforeafter", sent_prompt)


class PostMessagesTransportTest(unittest.TestCase):
    """`_post_messages` builds an Anthropic Messages request and surfaces API
    errors. The HTTPSConnection is mocked — no real network."""

    def _fake_conn(self, status, body, retry_after=None):
        resp = MagicMock(status=status)
        resp.read.return_value = body.encode("utf-8")
        resp.getheader.return_value = retry_after
        conn = MagicMock()
        conn.getresponse.return_value = resp
        return conn

    @patch("agents.claude._request_target")
    @patch("agents.claude.http.client.HTTPSConnection")
    def test_success_concatenates_text_blocks(self, mock_cls, mock_target):
        mock_target.return_value = ("host", {"content-type": "application/json"}, None)
        body = '{"content":[{"type":"text","text":"Greg "},{"type":"text","text":"Schardt"}]}'
        mock_cls.return_value = self._fake_conn(200, body)
        self.assertEqual(call_claude("who?"), "Greg Schardt")

    @patch("agents.claude.time.sleep")
    @patch("agents.claude._request_target")
    @patch("agents.claude.http.client.HTTPSConnection")
    def test_non200_status_surfaces_body_text(self, mock_cls, mock_target, _sleep):
        mock_target.return_value = ("host", {"content-type": "application/json"}, None)
        mock_cls.return_value = self._fake_conn(
            400, '{"error":{"message":"prompt is too long"}}'
        )
        with self.assertRaises(ClaudeError) as ctx:
            call_claude("hi", timeout=1)
        self.assertIn("prompt is too long", str(ctx.exception))
        self.assertIn("400", str(ctx.exception))
