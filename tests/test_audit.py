"""Tests for the audit logger."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from audit.logger import AuditLogger


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._log_path = Path(self._tmpdir) / "audit.jsonl"
        self.logger = AuditLogger(self._log_path)

    def test_tool_execution_logged(self):
        self.logger.log_tool_execution(
            tool_name="fls",
            argv=["/usr/bin/fls", "-r", "/cases/image.E01"],
            cwd="/tmp",
            exit_code=0,
            duration_ms=1500,
            stdout="file listing output",
            stderr="",
        )
        self.assertEqual(self.logger.event_count, 1)
        events = self.logger.get_events("tool_execution")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["tool_name"], "fls")
        self.assertTrue(len(events[0]["stdout_hash"]) > 0)

    def test_tool_execution_records_output_paths(self):
        # The audit entry keeps the hash (integrity) AND the path to the
        # persisted raw output (traceability) so a reviewer can open the exact
        # bytes a finding came from.
        self.logger.log_tool_execution(
            tool_name="fls",
            argv=["/usr/bin/fls", "-r", "/cases/image.E01"],
            cwd="/tmp",
            exit_code=0,
            duration_ms=10,
            stdout="listing",
            stderr="",
            stdout_path="/out/abc123.out",
            stderr_path="/out/abc123.err",
        )
        event = self.logger.get_events("tool_execution")[0]
        self.assertEqual(event["stdout_path"], "/out/abc123.out")
        self.assertEqual(event["stderr_path"], "/out/abc123.err")
        self.assertTrue(len(event["stdout_hash"]) > 0)  # hash still present

    def test_agent_message_logged(self):
        self.logger.log_agent_message(
            from_agent="orchestrator",
            to_agent="disk_agent",
            message_type="task",
            content_summary="Analyze partition layout",
            token_count=150,
        )
        events = self.logger.get_events("agent_message")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["from_agent"], "orchestrator")
        self.assertEqual(events[0]["token_count"], 150)

    def test_finding_logged(self):
        self.logger.log_finding(
            agent_name="disk_agent",
            finding_id="F001",
            description="Suspicious executable in /tmp",
            confidence="confirmed",
            evidence_links=["exec-001", "exec-002"],
            ioc_type="file_path",
            ioc_value="/tmp/evil.exe",
        )
        events = self.logger.get_events("finding")
        self.assertEqual(events[0]["confidence"], "confirmed")
        self.assertEqual(len(events[0]["evidence_links"]), 2)

    def test_verification_logged(self):
        self.logger.log_verification(
            verifier_agent="verifier_001",
            finding_id="F001",
            verdict="confirmed",
            corroboration=["exec-003"],
            rounds_taken=2,
        )
        events = self.logger.get_events("verification")
        self.assertEqual(events[0]["verdict"], "confirmed")
        self.assertEqual(events[0]["rounds_taken"], 2)

    def test_hypothesis_lifecycle(self):
        self.logger.log_hypothesis("H1", "formed", "Ransomware via phishing")
        self.logger.log_hypothesis(
            "H1", "refuted", "Ransomware via phishing", "No email artifacts found"
        )
        events = self.logger.get_events("hypothesis")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["action"], "formed")
        self.assertEqual(events[1]["action"], "refuted")

    def test_jsonl_output_valid(self):
        self.logger.log_tool_execution(
            tool_name="mmls",
            argv=["/usr/bin/mmls", "/cases/img.E01"],
            cwd="/tmp",
            exit_code=0,
            duration_ms=500,
            stdout="partition table",
            stderr="",
        )
        self.logger.log_agent_message("orch", "disk", "task", "check partitions")

        with open(self._log_path) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            record = json.loads(line)
            self.assertIn("event_type", record)
            self.assertIn("timestamp", record)

    def test_event_filtering(self):
        self.logger.log_tool_execution(
            tool_name="fls",
            argv=[],
            cwd="/tmp",
            exit_code=0,
            duration_ms=100,
            stdout="",
            stderr="",
        )
        self.logger.log_agent_message("a", "b", "task", "do something")
        self.logger.log_finding("a", "F1", "found it", "confirmed", ["e1"])

        self.assertEqual(len(self.logger.get_events()), 3)
        self.assertEqual(len(self.logger.get_events("tool_execution")), 1)
        self.assertEqual(len(self.logger.get_events("finding")), 1)


if __name__ == "__main__":
    unittest.main()
