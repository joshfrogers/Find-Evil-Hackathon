"""Tests for the report generator."""

import sys
import tempfile
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from report.generator import ReportGenerator


def _make_report(**overrides) -> dict:
    report = {
        "investigation_id": "inv-test001",
        "evidence_path": "/cases/image.E01",
        "evidence_type": "disk",
        "brief": "",
        "timestamp": "2026-05-21T00:00:00Z",
        "rounds_completed": 2,
        "status": "completed",
        "hypotheses": [
            {
                "id": "H1",
                "description": "Malware persistence via registry",
                "status": "supported",
                "evidence_for": ["Run key found"],
                "evidence_against": [],
            }
        ],
        "findings": [
            {
                "finding_id": "F-001",
                "description": "Run key evil.exe added",
                "confidence": "confirmed",
                "verified": True,
                "verification_verdict": "confirmed",
                "ioc_type": "registry_key",
                "ioc_value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
                "evidence_links": ["exec-001"],
                "agent": "artifacts_agent",
            }
        ],
        "iocs": [
            {
                "type": "registry_key",
                "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
            }
        ],
        "failed_approaches": [
            {
                "tool": "log2timeline",
                "failure": "timeout after 300s",
                "lesson": "Use targeted parsers",
            }
        ],
        "strategy_pivots": [
            {
                "from": "Broad triage",
                "to": "Focused on Windows artifacts",
                "reason": "Triage revealed Windows event logs",
            }
        ],
        "audit_log": "audit.jsonl",
    }
    report.update(overrides)
    return report


class ReportGeneratorTest(unittest.TestCase):
    def test_markdown_contains_all_sections(self):
        gen = ReportGenerator(_make_report())
        md = gen._render_markdown()

        self.assertIn("# Forensic Investigation Report", md)
        self.assertIn("## Executive Summary", md)
        self.assertIn("## Hypotheses", md)
        self.assertIn("## Findings", md)
        self.assertIn("## Indicators of Compromise", md)
        self.assertIn("## Failed Approaches", md)
        self.assertIn("## Strategy Pivots", md)
        self.assertIn("## Accuracy Metadata", md)
        self.assertIn("## Audit Trail", md)

    def test_markdown_includes_finding_details(self):
        gen = ReportGenerator(_make_report())
        md = gen._render_markdown()

        self.assertIn("Run key evil.exe added", md)
        self.assertIn("confirmed", md)
        self.assertIn("artifacts_agent", md)

    def test_finding_renders_command_and_exec_id(self):
        report = _make_report(
            findings=[
                {
                    "finding_id": "F-001",
                    "description": "d",
                    "confidence": "confirmed",
                    "verified": True,
                    "verification_verdict": "confirmed",
                    "ioc_type": "",
                    "ioc_value": "",
                    "agent": "disk_agent",
                    "evidence_links": ["e1"],
                }
            ],
            executions={
                "e1": {
                    "tool": "/usr/bin/fls",
                    "args": ["-r", "/cases/img.E01"],
                    "exit_code": 0,
                    "execution_id": "e1",
                },
            },
        )
        md = ReportGenerator(report)._render_markdown()
        self.assertIn("/usr/bin/fls", md)
        self.assertIn("e1", md)

    def test_empty_findings_omits_section(self):
        gen = ReportGenerator(_make_report(findings=[], iocs=[]))
        md = gen._render_markdown()

        self.assertNotIn("## Findings", md)
        self.assertNotIn("## Indicators of Compromise", md)

    def test_empty_hypotheses_omits_section(self):
        gen = ReportGenerator(_make_report(hypotheses=[]))
        md = gen._render_markdown()

        self.assertNotIn("## Hypotheses", md)

    def test_accuracy_metadata_counts(self):
        gen = ReportGenerator(_make_report())
        md = gen._render_markdown()

        self.assertIn("Total findings: 1", md)
        self.assertIn("Confirmed (direct evidence): 1", md)

    def test_write_markdown_creates_file(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        output = Path(td.name) / "report.md"

        gen = ReportGenerator(_make_report())
        gen.write_markdown(output)

        self.assertTrue(output.exists())
        content = output.read_text()
        self.assertIn("Forensic Investigation Report", content)

    def test_render_timeline_section(self):
        report = _make_report()
        report["correlation"] = {
            "timeline": [
                {
                    "timestamp": "2018-07-04T14:20:00Z",
                    "description": "File written",
                    "artifact_type": "mft",
                    "finding_ids": ["F-1"],
                    "cluster_id": "C-1",
                },
                {
                    "timestamp": "2018-07-04T14:21:00Z",
                    "description": "Registry key set",
                    "artifact_type": "registry",
                    "finding_ids": ["F-2"],
                    "cluster_id": "C-1",
                },
            ],
            "event_chains": [
                {
                    "chain_id": "CH-1",
                    "description": "File written → Registry key set",
                    "entry_ids": ["F-1", "F-2"],
                    "confidence": "inferred",
                },
            ],
            "timeline_gaps": [
                {
                    "anomaly_id": "A-1",
                    "description": "No events for 6.0 hours",
                    "gap_start": "2018-07-04T14:22:00Z",
                    "gap_end": "2018-07-04T20:22:00Z",
                    "gap_type": "gap",
                },
            ],
        }
        gen = ReportGenerator(report)
        md = gen._render_markdown()
        self.assertIn("## Attack Timeline", md)
        self.assertIn("File written", md)
        self.assertIn("Registry key set", md)
        self.assertIn("Event Chains", md)
        self.assertIn("Timeline Gaps", md)

    def test_render_semantic_clusters(self):
        report = _make_report()
        report["correlation"] = {
            "timeline": [],
            "event_chains": [],
            "timeline_gaps": [],
            "semantic_clusters": [
                {
                    "cluster_id": "SC-1",
                    "label": "evil.exe persistence chain",
                    "finding_ids": ["F-1", "F-2"],
                    "reasoning": "Both findings reference evil.exe",
                },
            ],
        }
        gen = ReportGenerator(report)
        md = gen._render_markdown()
        self.assertIn("Semantic Activity Groups", md)
        self.assertIn("evil.exe persistence chain", md)
        self.assertIn("F-1, F-2", md)
        self.assertIn("Both findings reference evil.exe", md)

    def test_audit_event_counts(self):
        events = [
            {"event_type": "tool_execution", "tool_name": "fls"},
            {"event_type": "tool_execution", "tool_name": "mmls"},
            {"event_type": "agent_message", "from_agent": "orch"},
        ]
        gen = ReportGenerator(_make_report(), audit_events=events)
        md = gen._render_markdown()

        self.assertIn("Tool executions logged: 2", md)
        self.assertIn("Agent messages logged: 1", md)
        self.assertIn("Total audit events: 3", md)

    def test_render_verification_section(self):
        report = _make_report()
        report["findings"][0]["verification_rounds"] = 3
        report["findings"][0]["corroboration_count"] = 1
        report["findings"][0]["corroboration_ids"] = ["F-002"]
        gen = ReportGenerator(report)
        md = gen._render_markdown()

        self.assertIn("## Verification & Self-Correction", md)
        self.assertIn("F-001", md)
        self.assertIn("required multiple rounds", md)

    def test_self_correction_events_rendered(self):
        events = [
            {
                "event_type": "self_correction",
                "finding_id": "F-001",
                "previous_confidence": "confirmed",
                "new_confidence": "inferred",
                "verdict": "downgraded",
                "rounds_taken": 2,
            }
        ]
        gen = ReportGenerator(_make_report(), audit_events=events)
        md = gen._render_markdown()

        self.assertIn("Self-corrections recorded: 1", md)
        self.assertIn("confirmed -> inferred", md)


class RenderScoringTest(unittest.TestCase):
    """The Accuracy & Scoring (vs Ground Truth) section."""

    def _report_with_score(self, **score_overrides) -> dict:
        report = _make_report()
        score = {
            "baseline_id": "case-test",
            "total_agent_findings": 2,
            "total_baseline_findings": 3,
            "required_baseline_findings": 3,
            "precision": 0.5,
            "recall": 0.333,
            "f1": 0.4,
            "hallucination_rate": 0.5,
            "matched_findings": [
                {
                    "finding_id": "F-001",
                    "baseline_id": "B-001",
                    "match_kind": "ioc_exact",
                    "description": "a",
                    "baseline_description": "a",
                    "similarity": 1.0,
                }
            ],
            "missed_baseline_findings": ["B-002", "B-003"],
            "extra_findings": ["F-002"],
            "confirmed_vs_inferred": {
                "confirmed": 1,
                "inferred": 1,
                "possible": 0,
                "other": 0,
            },
            "hallucinations_flagged": [
                {
                    "finding_id": "F-002",
                    "description": "fabricated",
                    "reason": "no evidence_links",
                    "unresolved_links": [],
                }
            ],
            "hallucinations_caught_by_verifier": [
                {
                    "finding_id": "F-purged",
                    "description": "(refuted)",
                    "reason": "verifier verdict=refuted",
                    "unresolved_links": [],
                }
            ],
        }
        score.update(score_overrides)
        report["accuracy_score"] = score
        return report

    def test_section_omitted_without_score(self):
        gen = ReportGenerator(_make_report())
        md = gen._render_markdown()
        self.assertNotIn("Accuracy & Scoring", md)

    def test_section_present_with_score(self):
        gen = ReportGenerator(self._report_with_score())
        md = gen._render_markdown()
        self.assertIn("## Accuracy & Scoring (vs Ground Truth)", md)
        self.assertIn("Baseline: `case-test`", md)
        self.assertIn("Precision: 0.500", md)
        self.assertIn("Recall: 0.333", md)
        self.assertIn("F1: 0.400", md)
        self.assertIn("Hallucination rate (uncaught): 0.500", md)

    def test_confidence_breakdown_rendered(self):
        gen = ReportGenerator(self._report_with_score())
        md = gen._render_markdown()
        self.assertIn("Confidence Breakdown", md)
        self.assertIn("Confirmed (direct evidence): 1", md)
        self.assertIn("Inferred (correlated): 1", md)

    def test_missed_artifacts_listed(self):
        gen = ReportGenerator(self._report_with_score())
        md = gen._render_markdown()
        self.assertIn("Missed Artifacts", md)
        self.assertIn("B-002", md)
        self.assertIn("B-003", md)

    def test_false_positives_listed(self):
        gen = ReportGenerator(self._report_with_score())
        md = gen._render_markdown()
        self.assertIn("False Positives", md)
        self.assertIn("F-002", md)

    def test_hallucinations_flagged_and_caught_rendered(self):
        gen = ReportGenerator(self._report_with_score())
        md = gen._render_markdown()
        self.assertIn("Hallucinated Claims", md)
        self.assertIn("F-002", md)
        self.assertIn("no evidence_links", md)
        self.assertIn("Hallucinations Caught by Verifier (credit): 1", md)
        self.assertIn("F-purged", md)

    def test_comparison_section_rendered_when_present(self):
        report = self._report_with_score()
        report["baseline_comparison"] = {
            "subject_baseline_id": "case-test",
            "reference_baseline_id": "case-test",
            "subject_hallucination_rate": 0.1,
            "reference_hallucination_rate": 0.3,
            "subject_precision": 0.8,
            "reference_precision": 0.6,
            "subject_recall": 0.7,
            "reference_recall": 0.5,
            "subject_f1": 0.75,
            "reference_f1": 0.55,
            "hallucination_delta": 0.2,
            "precision_delta": 0.2,
            "recall_delta": 0.2,
            "f1_delta": 0.2,
            "passes": True,
        }
        gen = ReportGenerator(report)
        md = gen._render_markdown()
        self.assertIn("Head-to-Head", md)
        self.assertIn("PASS", md)
        self.assertIn("0.100", md)
        self.assertIn("0.300", md)

    def test_comparison_section_shows_fail(self):
        report = self._report_with_score()
        report["baseline_comparison"] = {
            "subject_baseline_id": "x",
            "reference_baseline_id": "x",
            "subject_hallucination_rate": 0.4,
            "reference_hallucination_rate": 0.2,
            "subject_precision": 0.5,
            "reference_precision": 0.5,
            "subject_recall": 0.5,
            "reference_recall": 0.5,
            "subject_f1": 0.5,
            "reference_f1": 0.5,
            "hallucination_delta": -0.2,
            "precision_delta": 0.0,
            "recall_delta": 0.0,
            "f1_delta": 0.0,
            "passes": False,
        }
        gen = ReportGenerator(report)
        md = gen._render_markdown()
        self.assertIn("FAIL", md)


class PartialRunRenderTest(unittest.TestCase):
    """A partial (triage-only) run must be flagged with a warning banner and its
    findings must not look like verified findings. A Limitations section is
    rendered only when there are limitations to show."""

    def test_partial_run_shows_triage_banner(self):
        report = _make_report(
            status="timed_out",
            rounds_completed=0,
            findings_unverified=True,
            findings=[
                {
                    "finding_id": "F-1",
                    "description": "d",
                    "confidence": "possible",
                    "verified": False,
                    "verification_verdict": "",
                    "ioc_type": "",
                    "ioc_value": "",
                    "agent": "disk_agent",
                    "evidence_links": [],
                    "verification_state": "triage_only",
                }
            ],
        )
        md = ReportGenerator(report)._render_markdown()
        self.assertIn("TRIAGE-ONLY", md.upper())
        self.assertIn("not verified", md.lower())

    def test_completed_run_has_no_triage_banner(self):
        md = ReportGenerator(_make_report(findings_unverified=False))._render_markdown()
        self.assertNotIn("TRIAGE-ONLY", md.upper())

    def test_limitations_section_rendered(self):
        report = _make_report(
            limitations=[
                "Unbacked claim dropped (no successful evidence): evil at offset 128"
            ],
        )
        md = ReportGenerator(report)._render_markdown()
        self.assertIn("## Limitations", md)
        self.assertIn("offset 128", md)

    def test_no_limitations_section_when_empty(self):
        md = ReportGenerator(_make_report(limitations=[]))._render_markdown()
        self.assertNotIn("## Limitations", md)
