# pyre-strict
"""Tests for the accuracy scorer + hallucination detector."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from accuracy.baseline import Baseline, BaselineFinding, load_baseline
from accuracy.hallucination import detect_hallucinations
from accuracy.scorer import score_report


def _baseline(*findings: BaselineFinding) -> Baseline:
    return Baseline(
        case_id="case-test",
        evidence_image="test.E01",
        evidence_type="disk",
        findings=list(findings),
    )


def _bf(
    id: str,
    description: str = "",
    ioc_type: str = "",
    ioc_value: str = "",
    artifact_type: str = "",
    must_find: bool = True,
) -> BaselineFinding:
    return BaselineFinding(
        id=id,
        description=description or f"baseline {id}",
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        artifact_type=artifact_type,
        must_find=must_find,
    )


def _finding(
    finding_id: str,
    description: str = "",
    confidence: str = "confirmed",
    ioc_type: str = "",
    ioc_value: str = "",
    evidence_links: list[str] | None = None,
) -> dict:
    return {
        "finding_id": finding_id,
        "description": description or f"agent finding {finding_id}",
        "confidence": confidence,
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "evidence_links": evidence_links or [],
    }


def _exec_event(event_id: str, tool_name: str = "fls") -> dict:
    return {
        "event_id": event_id,
        "event_type": "tool_execution",
        "tool_name": tool_name,
        "exit_code": 0,
    }


def _report(*findings: dict) -> dict:
    return {"findings": list(findings)}


class BaselineLoaderTest(unittest.TestCase):
    def test_load_valid_baseline(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "case.json"
        p.write_text(
            json.dumps(
                {
                    "case_id": "case-1",
                    "evidence_image": "x.E01",
                    "findings": [
                        {
                            "id": "B-001",
                            "description": "thing",
                            "ioc_type": "ip",
                            "ioc_value": "1.2.3.4",
                            "must_find": True,
                        }
                    ],
                }
            )
        )
        b = load_baseline(p)
        self.assertEqual(b.case_id, "case-1")
        self.assertEqual(len(b.findings), 1)
        self.assertEqual(b.findings[0].ioc_value, "1.2.3.4")
        self.assertEqual(len(b.required_findings), 1)

    def test_optional_must_find_defaults_true(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "case.json"
        p.write_text(
            json.dumps(
                {
                    "case_id": "c",
                    "evidence_image": "x",
                    "findings": [{"id": "B-1", "description": "d"}],
                }
            )
        )
        b = load_baseline(p)
        self.assertTrue(b.findings[0].must_find)

    def test_must_find_false_excluded_from_required(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "case.json"
        p.write_text(
            json.dumps(
                {
                    "case_id": "c",
                    "evidence_image": "x",
                    "findings": [
                        {"id": "B-1", "description": "d", "must_find": False},
                        {"id": "B-2", "description": "d", "must_find": True},
                    ],
                }
            )
        )
        b = load_baseline(p)
        self.assertEqual(len(b.findings), 2)
        self.assertEqual(len(b.required_findings), 1)
        self.assertEqual(b.required_findings[0].id, "B-2")

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_baseline("/nonexistent/baseline.json")

    def test_missing_required_key_raises(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "case.json"
        p.write_text(json.dumps({"case_id": "c"}))
        with self.assertRaises(ValueError):
            load_baseline(p)

    def test_missing_finding_id_raises(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "case.json"
        p.write_text(
            json.dumps(
                {
                    "case_id": "c",
                    "evidence_image": "x",
                    "findings": [{"description": "no id"}],
                }
            )
        )
        with self.assertRaises(ValueError):
            load_baseline(p)


class ScorerIocMatchTest(unittest.TestCase):
    def test_exact_ioc_match(self):
        bl = _baseline(_bf("B-1", ioc_type="ip", ioc_value="10.0.0.1"))
        rep = _report(
            _finding("F-1", ioc_type="ip", ioc_value="10.0.0.1", evidence_links=["e1"])
        )
        events = [_exec_event("e1")]
        score = score_report(rep, events, bl)
        self.assertEqual(len(score.matched_findings), 1)
        self.assertEqual(score.matched_findings[0].match_kind, "ioc_exact")
        self.assertEqual(score.precision, 1.0)
        self.assertEqual(score.recall, 1.0)
        self.assertEqual(score.f1, 1.0)

    def test_ioc_match_normalizes_casing_and_slashes(self):
        bl = _baseline(_bf("B-1", ioc_type="file_path", ioc_value="C:\\Temp\\evil.exe"))
        rep = _report(
            _finding(
                "F-1",
                ioc_type="file_path",
                ioc_value="c:/temp/EVIL.exe",
                evidence_links=["e1"],
            )
        )
        score = score_report(rep, [_exec_event("e1")], bl)
        self.assertEqual(len(score.matched_findings), 1)

    def test_ioc_type_mismatch_blocks_match(self):
        bl = _baseline(_bf("B-1", ioc_type="ip", ioc_value="10.0.0.1"))
        rep = _report(
            _finding(
                "F-1",
                ioc_type="domain",
                ioc_value="10.0.0.1",
                description="totally unrelated",
                evidence_links=["e1"],
            )
        )
        score = score_report(rep, [_exec_event("e1")], bl)
        self.assertEqual(len(score.matched_findings), 0)
        self.assertEqual(score.extra_findings, ["F-1"])
        self.assertEqual(score.missed_baseline_findings, ["B-1"])


class ScorerDescriptionMatchTest(unittest.TestCase):
    def test_description_fuzzy_match(self):
        bl = _baseline(
            _bf("B-1", description="MFT timestomping on svchost_update.exe (backdated)")
        )
        rep = _report(
            _finding(
                "F-1",
                description="MFT timestomping detected on svchost_update.exe — backdated",
                evidence_links=["e1"],
            )
        )
        score = score_report(rep, [_exec_event("e1")], bl)
        self.assertEqual(len(score.matched_findings), 1)
        self.assertEqual(score.matched_findings[0].match_kind, "description_fuzzy")

    def test_dissimilar_description_does_not_match(self):
        bl = _baseline(_bf("B-1", description="MFT timestomping"))
        rep = _report(
            _finding(
                "F-1",
                description="completely unrelated network traffic analysis",
                evidence_links=["e1"],
            )
        )
        score = score_report(rep, [_exec_event("e1")], bl)
        self.assertEqual(len(score.matched_findings), 0)


class ScorerMetricsTest(unittest.TestCase):
    def test_recall_excludes_bonus_findings(self):
        bl = _baseline(
            _bf("B-1", ioc_type="ip", ioc_value="1.1.1.1", must_find=True),
            _bf("B-2", ioc_type="ip", ioc_value="2.2.2.2", must_find=False),
        )
        rep = _report(
            _finding("F-1", ioc_type="ip", ioc_value="1.1.1.1", evidence_links=["e1"])
        )
        score = score_report(rep, [_exec_event("e1")], bl)
        # Only B-1 counts toward recall; B-2 is bonus.
        self.assertEqual(score.required_baseline_findings, 1)
        self.assertEqual(score.recall, 1.0)

    def test_missing_baseline_lowers_recall(self):
        bl = _baseline(
            _bf("B-1", ioc_type="ip", ioc_value="1.1.1.1"),
            _bf("B-2", ioc_type="ip", ioc_value="2.2.2.2"),
        )
        rep = _report(
            _finding("F-1", ioc_type="ip", ioc_value="1.1.1.1", evidence_links=["e1"])
        )
        score = score_report(rep, [_exec_event("e1")], bl)
        self.assertEqual(score.recall, 0.5)
        self.assertIn("B-2", score.missed_baseline_findings)

    def test_extra_finding_lowers_precision(self):
        bl = _baseline(_bf("B-1", ioc_type="ip", ioc_value="1.1.1.1"))
        rep = _report(
            _finding("F-1", ioc_type="ip", ioc_value="1.1.1.1", evidence_links=["e1"]),
            _finding(
                "F-2",
                ioc_type="ip",
                ioc_value="9.9.9.9",
                description="random extra ip",
                evidence_links=["e2"],
            ),
        )
        score = score_report(rep, [_exec_event("e1"), _exec_event("e2")], bl)
        self.assertEqual(score.precision, 0.5)
        self.assertEqual(score.extra_findings, ["F-2"])

    def test_empty_findings_yields_zero_metrics(self):
        bl = _baseline(_bf("B-1", ioc_type="ip", ioc_value="1.1.1.1"))
        score = score_report({"findings": []}, [], bl)
        self.assertEqual(score.precision, 0.0)
        self.assertEqual(score.recall, 0.0)
        self.assertEqual(score.f1, 0.0)
        self.assertEqual(score.missed_baseline_findings, ["B-1"])

    def test_confidence_breakdown(self):
        bl = _baseline(_bf("B-1", ioc_type="ip", ioc_value="1.1.1.1"))
        rep = _report(
            _finding(
                "F-1",
                ioc_type="ip",
                ioc_value="1.1.1.1",
                confidence="confirmed",
                evidence_links=["e1"],
            ),
            _finding(
                "F-2",
                confidence="inferred",
                description="a",
                evidence_links=["e2"],
            ),
            _finding(
                "F-3",
                confidence="possible",
                description="b",
                evidence_links=["e3"],
            ),
        )
        events = [_exec_event(f"e{i}") for i in (1, 2, 3)]
        score = score_report(rep, events, bl)
        self.assertEqual(score.confirmed_vs_inferred["confirmed"], 1)
        self.assertEqual(score.confirmed_vs_inferred["inferred"], 1)
        self.assertEqual(score.confirmed_vs_inferred["possible"], 1)

    def test_baseline_item_matched_only_once(self):
        bl = _baseline(_bf("B-1", ioc_type="ip", ioc_value="1.1.1.1"))
        rep = _report(
            _finding("F-1", ioc_type="ip", ioc_value="1.1.1.1", evidence_links=["e1"]),
            _finding("F-2", ioc_type="ip", ioc_value="1.1.1.1", evidence_links=["e2"]),
        )
        score = score_report(rep, [_exec_event("e1"), _exec_event("e2")], bl)
        # B-1 is consumed by F-1; F-2 becomes an extra.
        self.assertEqual(len(score.matched_findings), 1)
        self.assertEqual(score.extra_findings, ["F-2"])


class HallucinationDetectorTest(unittest.TestCase):
    def test_finding_with_no_evidence_links_is_flagged(self):
        rep_findings = [_finding("F-1", evidence_links=[])]
        result = detect_hallucinations(rep_findings, [])
        self.assertEqual(len(result.flagged), 1)
        self.assertEqual(result.flagged[0].finding_id, "F-1")
        self.assertIn("no evidence_links", result.flagged[0].reason)

    def test_evidence_link_not_in_audit_is_flagged(self):
        rep_findings = [_finding("F-1", evidence_links=["e-missing"])]
        result = detect_hallucinations(rep_findings, [_exec_event("e-other")])
        self.assertEqual(len(result.flagged), 1)
        self.assertIn("e-missing", result.flagged[0].unresolved_links)

    def test_resolved_evidence_link_is_not_flagged(self):
        rep_findings = [_finding("F-1", evidence_links=["e-1"])]
        result = detect_hallucinations(rep_findings, [_exec_event("e-1")])
        self.assertEqual(len(result.flagged), 0)

    def test_partial_resolution_flags_finding(self):
        rep_findings = [_finding("F-1", evidence_links=["e-1", "e-missing"])]
        result = detect_hallucinations(rep_findings, [_exec_event("e-1")])
        self.assertEqual(len(result.flagged), 1)
        self.assertEqual(result.flagged[0].unresolved_links, ["e-missing"])

    def test_verifier_refuted_finding_counted_as_caught(self):
        events = [
            {
                "event_id": "v-1",
                "event_type": "verification",
                "verdict": "refuted",
                "finding_id": "F-removed",
            }
        ]
        result = detect_hallucinations([], events)
        self.assertEqual(len(result.caught), 1)
        self.assertEqual(result.caught[0].finding_id, "F-removed")

    def test_self_correction_downgrade_counted_as_caught(self):
        events = [
            {
                "event_id": "sc-1",
                "event_type": "self_correction",
                "finding_id": "F-fixed",
                "verdict": "downgraded",
                "previous_confidence": "confirmed",
                "new_confidence": "possible",
            }
        ]
        result = detect_hallucinations([], events)
        self.assertEqual(len(result.caught), 1)
        self.assertEqual(result.caught[0].finding_id, "F-fixed")

    def test_self_correction_with_unchanged_verdict_not_counted(self):
        events = [
            {
                "event_id": "sc-2",
                "event_type": "self_correction",
                "finding_id": "F-x",
                "verdict": "confirmed",
                "previous_confidence": "inferred",
                "new_confidence": "confirmed",
            }
        ]
        result = detect_hallucinations([], events)
        self.assertEqual(len(result.caught), 0)

    def test_failed_tool_execution_is_flagged(self):
        """exit_code != 0 means the tool produced no output to interpret."""
        rep_findings = [_finding("F-1", evidence_links=["e-failed"])]
        failed_event = {
            "event_id": "e-failed",
            "event_type": "tool_execution",
            "tool_name": "mmls",
            "exit_code": -1,
        }
        result = detect_hallucinations(rep_findings, [failed_event])
        self.assertEqual(len(result.flagged), 1)
        self.assertIn("failed or were rejected", result.flagged[0].reason)
        self.assertEqual(result.flagged[0].unresolved_links, ["e-failed"])

    def test_rejected_tool_execution_is_flagged(self):
        """Rejected executions (allowlist/path failures) produced no output."""
        rep_findings = [_finding("F-1", evidence_links=["e-rejected"])]
        rejected_event = {
            "event_id": "e-rejected",
            "event_type": "tool_execution",
            "tool_name": "ewfmount",
            "exit_code": -1,
            "rejected": True,
            "rejection_reason": "Path not under allowed evidence roots",
        }
        result = detect_hallucinations(rep_findings, [rejected_event])
        self.assertEqual(len(result.flagged), 1)
        self.assertIn("failed or were rejected", result.flagged[0].reason)

    def test_successful_execution_not_flagged(self):
        """exit_code == 0 and not rejected => valid backing."""
        rep_findings = [_finding("F-1", evidence_links=["e-ok"])]
        ok_event = {
            "event_id": "e-ok",
            "event_type": "tool_execution",
            "tool_name": "fls",
            "exit_code": 0,
        }
        result = detect_hallucinations(rep_findings, [ok_event])
        self.assertEqual(len(result.flagged), 0)

    def test_mixed_success_and_failure_flags_finding(self):
        """If any link is invalid the finding is flagged with both reasons."""
        rep_findings = [_finding("F-1", evidence_links=["e-ok", "e-fail", "e-miss"])]
        events = [
            {
                "event_id": "e-ok",
                "event_type": "tool_execution",
                "tool_name": "fls",
                "exit_code": 0,
            },
            {
                "event_id": "e-fail",
                "event_type": "tool_execution",
                "tool_name": "mmls",
                "exit_code": -1,
            },
        ]
        result = detect_hallucinations(rep_findings, events)
        self.assertEqual(len(result.flagged), 1)
        flag = result.flagged[0]
        self.assertCountEqual(flag.unresolved_links, ["e-fail", "e-miss"])
        self.assertIn("failed or were rejected", flag.reason)
        self.assertIn("not in", flag.reason)

    def test_missing_exit_code_defaults_to_flagged(self):
        """A tool_execution missing exit_code is treated as not successful.

        Defensive default: only events that EXPLICITLY succeeded count as
        valid backing. Missing-field events are flagged, not silently passed.
        """
        rep_findings = [_finding("F-1", evidence_links=["e-x"])]
        events = [
            {
                "event_id": "e-x",
                "event_type": "tool_execution",
                "tool_name": "fls",
            }
        ]
        result = detect_hallucinations(rep_findings, events)
        self.assertEqual(len(result.flagged), 1)

    def test_same_finding_not_double_counted_in_caught(self):
        events = [
            {
                "event_id": "v",
                "event_type": "verification",
                "verdict": "refuted",
                "finding_id": "F-X",
            },
            {
                "event_id": "sc",
                "event_type": "self_correction",
                "finding_id": "F-X",
                "verdict": "refuted",
                "previous_confidence": "confirmed",
                "new_confidence": "refuted",
            },
        ]
        result = detect_hallucinations([], events)
        self.assertEqual(len(result.caught), 1)


class ScorerHallucinationIntegrationTest(unittest.TestCase):
    def test_scorer_flags_hallucinations_in_output(self):
        bl = _baseline(_bf("B-1", ioc_type="ip", ioc_value="1.1.1.1"))
        rep = _report(
            _finding(
                "F-1", ioc_type="ip", ioc_value="1.1.1.1", evidence_links=["e-real"]
            ),
            _finding("F-fab", description="fabricated", evidence_links=[]),
        )
        score = score_report(rep, [_exec_event("e-real")], bl)
        self.assertEqual(len(score.hallucinations_flagged), 1)
        self.assertEqual(score.hallucinations_flagged[0]["finding_id"], "F-fab")
        self.assertEqual(score.hallucination_rate, 0.5)

    def test_scorer_credits_verifier_caught_in_output(self):
        bl = _baseline(_bf("B-1", ioc_type="ip", ioc_value="1.1.1.1"))
        rep = _report(
            _finding(
                "F-1", ioc_type="ip", ioc_value="1.1.1.1", evidence_links=["e-real"]
            )
        )
        events = [
            _exec_event("e-real"),
            {
                "event_id": "v-1",
                "event_type": "verification",
                "verdict": "refuted",
                "finding_id": "F-purged",
            },
        ]
        score = score_report(rep, events, bl)
        self.assertEqual(len(score.hallucinations_caught_by_verifier), 1)


class ScorerPathIocMatchTest(unittest.TestCase):
    """Path-aware IOC matching: agent paths from a mounted filesystem
    (mount-root-prefixed or drive-relative) and registry key+value paths must
    match the baseline's Windows-absolute / key-only IOCs by aligned path
    segments, not just exact normalized string equality."""

    def _score(self, baseline, *findings):
        return score_report({"findings": list(findings)}, [], baseline)

    def test_relative_path_matches_windows_absolute_baseline(self):
        b = _baseline(
            _bf("B1", ioc_type="file_path", ioc_value="C:\\Program Files\\Network Stumbler")
        )
        f = _finding("F1", ioc_type="file_path", ioc_value="Program Files/Network Stumbler")
        score = self._score(b, f)
        self.assertNotIn("B1", score.missed_baseline_findings)
        self.assertEqual([m.baseline_id for m in score.matched_findings], ["B1"])

    def test_mount_prefixed_path_matches(self):
        b = _baseline(
            _bf("B1", ioc_type="file_path", ioc_value="C:\\Program Files\\mIRC\\mirc.ini")
        )
        f = _finding(
            "F1",
            ioc_type="file_path",
            ioc_value="/tmp/agentic-sift-evidence-x/mnt/vol0/Program Files/mIRC/mirc.ini",
        )
        score = self._score(b, f)
        self.assertNotIn("B1", score.missed_baseline_findings)

    def test_registry_key_value_suffix_matches(self):
        b = _baseline(
            _bf(
                "B1",
                ioc_type="registry_key",
                ioc_value="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            )
        )
        f = _finding(
            "F1",
            ioc_type="registry_key",
            ioc_value="SOFTWARE/Microsoft/Windows NT/CurrentVersion/RegisteredOwner",
        )
        score = self._score(b, f)
        self.assertNotIn("B1", score.missed_baseline_findings)

    def test_different_leaf_does_not_match(self):
        b = _baseline(
            _bf("B1", ioc_type="file_path", ioc_value="C:\\Program Files\\Ethereal")
        )
        f = _finding(
            "F1",
            description="unrelated finding text zzz qqq",
            ioc_type="file_path",
            ioc_value="C:\\Program Files\\Network Stumbler",
        )
        score = self._score(b, f)
        self.assertIn("B1", score.missed_baseline_findings)

    def test_single_common_trailing_segment_does_not_match(self):
        b = _baseline(
            _bf("B1", ioc_type="file_path", ioc_value="C:\\WINDOWS\\system32\\config")
        )
        f = _finding(
            "F1",
            description="unrelated finding text zzz qqq",
            ioc_type="file_path",
            ioc_value="C:\\Program Files\\app\\config",
        )
        score = self._score(b, f)
        self.assertIn("B1", score.missed_baseline_findings)
