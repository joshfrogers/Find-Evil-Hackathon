"""Tests for LLM-based semantic correlation."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.base import Finding
from correlation.semantic import (
    _build_prompt,
    _parse_response,
    correlate_semantically,
    SemanticCluster,
    SemanticCorrelationResult,
)


def _make_finding(
    description: str = "test",
    finding_id: str = "",
    timestamp: str = "",
    artifact_type: str = "",
) -> Finding:
    f = Finding.new(
        description=description,
        confidence="confirmed",
        evidence_links=["E-1"],
        timestamp=timestamp,
        artifact_type=artifact_type,
    )
    if finding_id:
        f.finding_id = finding_id
    return f


class TestBuildPrompt(unittest.TestCase):
    def test_prompt_includes_all_findings(self):
        findings = [
            _make_finding(
                "File evil.exe written", finding_id="F-001", artifact_type="mft"
            ),
            _make_finding(
                "Registry key for evil.exe",
                finding_id="F-002",
                artifact_type="registry",
            ),
        ]
        prompt = _build_prompt(findings)
        self.assertIn("F-001", prompt)
        self.assertIn("F-002", prompt)
        self.assertIn("evil.exe written", prompt)
        self.assertIn("Registry key for evil.exe", prompt)

    def test_prompt_includes_artifact_type(self):
        findings = [
            _make_finding("event", finding_id="F-001", artifact_type="evtx"),
        ]
        prompt = _build_prompt(findings)
        self.assertIn("evtx", prompt)


class TestParseResponse(unittest.TestCase):
    def test_valid_response_with_clusters(self):
        valid_ids = {"F-001", "F-002", "F-003"}
        response = {
            "clusters": [
                {
                    "label": "evil.exe activity",
                    "finding_ids": ["F-001", "F-002"],
                    "reasoning": "Both reference evil.exe",
                }
            ]
        }
        result = _parse_response(response, valid_ids)
        self.assertEqual(len(result.clusters), 1)
        self.assertEqual(result.clusters[0].label, "evil.exe activity")
        self.assertEqual(result.clusters[0].finding_ids, ["F-001", "F-002"])
        self.assertEqual(result.clusters[0].cluster_id, "SC-1")
        self.assertIn("F-003", result.unclustered_ids)

    def test_filters_invalid_finding_ids(self):
        valid_ids = {"F-001", "F-002"}
        response = {
            "clusters": [
                {
                    "label": "group",
                    "finding_ids": ["F-001", "F-INVALID", "F-002"],
                    "reasoning": "test",
                }
            ]
        }
        result = _parse_response(response, valid_ids)
        self.assertEqual(len(result.clusters), 1)
        self.assertEqual(result.clusters[0].finding_ids, ["F-001", "F-002"])

    def test_rejects_cluster_with_fewer_than_two_valid_ids(self):
        valid_ids = {"F-001"}
        response = {
            "clusters": [
                {
                    "label": "lonely",
                    "finding_ids": ["F-001", "F-INVALID"],
                    "reasoning": "only one valid",
                }
            ]
        }
        result = _parse_response(response, valid_ids)
        self.assertEqual(len(result.clusters), 0)
        self.assertIn("F-001", result.unclustered_ids)

    def test_prevents_duplicate_ids_across_clusters(self):
        valid_ids = {"F-001", "F-002", "F-003"}
        response = {
            "clusters": [
                {
                    "label": "first",
                    "finding_ids": ["F-001", "F-002"],
                    "reasoning": "group 1",
                },
                {
                    "label": "second",
                    "finding_ids": ["F-002", "F-003"],
                    "reasoning": "group 2 tries to claim F-002 again",
                },
            ]
        }
        result = _parse_response(response, valid_ids)
        self.assertEqual(len(result.clusters), 1)
        self.assertEqual(result.clusters[0].finding_ids, ["F-001", "F-002"])
        self.assertIn("F-003", result.unclustered_ids)

    def test_handles_empty_clusters(self):
        valid_ids = {"F-001"}
        response = {"clusters": []}
        result = _parse_response(response, valid_ids)
        self.assertEqual(len(result.clusters), 0)
        self.assertIn("F-001", result.unclustered_ids)

    def test_handles_malformed_response(self):
        valid_ids = {"F-001"}
        result = _parse_response({"clusters": "not a list"}, valid_ids)
        self.assertEqual(len(result.clusters), 0)


class TestCorrelateSemantics(unittest.TestCase):
    def test_fewer_than_two_findings_returns_empty(self):
        findings = [_make_finding("solo", finding_id="F-001")]
        result = correlate_semantically(findings)
        self.assertEqual(len(result.clusters), 0)
        self.assertEqual(result.unclustered_ids, ["F-001"])

    @patch("correlation.semantic.call_claude_json")
    def test_successful_correlation(self, mock_claude):
        mock_claude.return_value = {
            "clusters": [
                {
                    "label": "evil.exe persistence",
                    "finding_ids": ["F-001", "F-002"],
                    "reasoning": "File drop and registry persistence for same binary",
                }
            ]
        }
        findings = [
            _make_finding(
                "evil.exe written to C:\\Temp", finding_id="F-001", artifact_type="mft"
            ),
            _make_finding(
                "Run key added for evil.exe",
                finding_id="F-002",
                artifact_type="registry",
            ),
            _make_finding(
                "Unrelated network traffic", finding_id="F-003", artifact_type="evtx"
            ),
        ]
        result = correlate_semantically(findings)
        self.assertEqual(len(result.clusters), 1)
        self.assertEqual(result.clusters[0].label, "evil.exe persistence")
        self.assertIn("F-003", result.unclustered_ids)
        mock_claude.assert_called_once()

    @patch("correlation.semantic.call_claude_json")
    def test_llm_failure_returns_all_unclustered(self, mock_claude):
        mock_claude.return_value = None
        findings = [
            _make_finding("event A", finding_id="F-001"),
            _make_finding("event B", finding_id="F-002"),
        ]
        result = correlate_semantically(findings)
        self.assertEqual(len(result.clusters), 0)
        self.assertEqual(len(result.unclustered_ids), 2)


if __name__ == "__main__":
    unittest.main()
