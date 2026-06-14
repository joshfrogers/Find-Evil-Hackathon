# pyre-strict
"""Tests for deterministic cross-domain corroboration."""

import sys
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.base import Finding
from verification.corroboration import CorroborationIndex


def _finding(
    finding_id: str,
    agent_name: str,
    ioc_type: str = "",
    ioc_value: str = "",
    artifact_type: str = "",
    timestamp: str = "",
    evidence_links: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        description="d",
        confidence="confirmed",
        evidence_links=evidence_links or [],
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        agent_name=agent_name,
        artifact_type=artifact_type,
        timestamp=timestamp,
    )


class CorroborationIndexTest(unittest.TestCase):
    def test_cross_domain_ioc_match_corroborates(self):
        a = _finding(
            "F-1", "disk_agent", ioc_type="file_path", ioc_value="C:\\Temp\\evil.exe"
        )
        # Different agent, same IOC written with different casing/slashes.
        b = _finding(
            "F-2", "memory_agent", ioc_type="file_path", ioc_value="c:/temp/evil.exe"
        )
        index = CorroborationIndex([a, b])
        self.assertEqual(index.for_finding("F-1").count, 1)
        self.assertIn("F-2", index.for_finding("F-1").corroborating_ids)
        # Symmetric.
        self.assertIn("F-1", index.for_finding("F-2").corroborating_ids)

    def test_same_agent_is_not_corroboration(self):
        a = _finding("F-1", "disk_agent", ioc_type="hash", ioc_value="abc123")
        b = _finding("F-2", "disk_agent", ioc_type="hash", ioc_value="abc123")
        index = CorroborationIndex([a, b])
        self.assertEqual(index.for_finding("F-1").count, 0)

    def test_artifact_type_within_window_corroborates(self):
        a = _finding(
            "F-1",
            "disk_agent",
            artifact_type="registry",
            timestamp="2026-05-21T12:00:00Z",
        )
        b = _finding(
            "F-2",
            "artifacts_agent",
            artifact_type="registry",
            timestamp="2026-05-21T12:02:00Z",
        )
        index = CorroborationIndex([a, b])
        self.assertEqual(index.for_finding("F-1").count, 1)

    def test_artifact_type_outside_window_does_not_corroborate(self):
        a = _finding(
            "F-1",
            "disk_agent",
            artifact_type="registry",
            timestamp="2026-05-21T12:00:00Z",
        )
        b = _finding(
            "F-2",
            "artifacts_agent",
            artifact_type="registry",
            timestamp="2026-05-21T12:30:00Z",
        )
        index = CorroborationIndex([a, b])
        self.assertEqual(index.for_finding("F-1").count, 0)

    def test_different_artifact_type_does_not_corroborate(self):
        a = _finding(
            "F-1",
            "disk_agent",
            artifact_type="registry",
            timestamp="2026-05-21T12:00:00Z",
        )
        b = _finding(
            "F-2",
            "artifacts_agent",
            artifact_type="prefetch",
            timestamp="2026-05-21T12:01:00Z",
        )
        index = CorroborationIndex([a, b])
        self.assertEqual(index.for_finding("F-1").count, 0)

    def test_shared_evidence_link_corroborates(self):
        a = _finding("F-1", "disk_agent", evidence_links=["exec-1", "exec-2"])
        b = _finding("F-2", "timeline_agent", evidence_links=["exec-2"])
        index = CorroborationIndex([a, b])
        self.assertEqual(index.for_finding("F-1").count, 1)
        self.assertIn("exec-2", index.for_finding("F-1").reasons[0])

    def test_no_overlap_yields_zero(self):
        a = _finding("F-1", "disk_agent", ioc_value="x", evidence_links=["e1"])
        b = _finding("F-2", "memory_agent", ioc_value="y", evidence_links=["e2"])
        index = CorroborationIndex([a, b])
        self.assertEqual(index.for_finding("F-1").count, 0)
        self.assertEqual(index.for_finding("F-2").count, 0)

    def test_unknown_finding_id_returns_empty(self):
        index = CorroborationIndex([])
        self.assertEqual(index.for_finding("nope").count, 0)

    def test_counts_distinct_cross_domain_supporters(self):
        a = _finding("F-1", "disk_agent", ioc_type="ip", ioc_value="10.0.0.5")
        b = _finding("F-2", "network_agent", ioc_type="ip", ioc_value="10.0.0.5")
        c = _finding("F-3", "memory_agent", ioc_type="ip", ioc_value="10.0.0.5")
        index = CorroborationIndex([a, b, c])
        self.assertEqual(index.for_finding("F-1").count, 2)
