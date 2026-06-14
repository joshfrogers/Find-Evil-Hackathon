"""Tests for deterministic finding deduplication.

Sub-agents (and successive rounds) frequently surface the SAME underlying
artifact more than once — e.g. one run reported the identical Dr. Watson
crash-log artifact as six separate findings. Each duplicate is counted as its
own false positive by the scorer (it can't match an already-consumed baseline
item), which depresses precision and clutters the report. `dedupe_findings`
collapses these deterministically (no LLM) before verification/scoring.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.base import Finding  # noqa: E402
from verification.dedup import dedupe_findings  # noqa: E402


def _f(description, confidence="confirmed", ioc_type="", ioc_value="",
       artifact_type="", links=None):
    return Finding.new(
        description=description,
        confidence=confidence,
        evidence_links=links or [],
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        artifact_type=artifact_type,
    )


class DedupeFindingsTest(unittest.TestCase):
    def test_collapses_findings_with_same_ioc(self):
        findings = [
            _f("Dr Watson log present", ioc_type="file_path",
               ioc_value="Documents and Settings/All Users/.../drwtsn32.log",
               links=["e1"]),
            _f("A Dr. Watson crash log exists", ioc_type="file_path",
               ioc_value="Documents and Settings/All Users/.../drwtsn32.log",
               links=["e2"]),
        ]
        out = dedupe_findings(findings)
        self.assertEqual(len(out), 1)

    def test_unions_evidence_links_of_merged_findings(self):
        findings = [
            _f("x", ioc_type="file_path", ioc_value="/a/b", links=["e1"]),
            _f("x again", ioc_type="file_path", ioc_value="/a/b", links=["e2", "e1"]),
        ]
        out = dedupe_findings(findings)
        self.assertEqual(len(out), 1)
        self.assertCountEqual(out[0].evidence_links, ["e1", "e2"])

    def test_keeps_strongest_confidence(self):
        findings = [
            _f("same artifact", confidence="possible", ioc_type="ip",
               ioc_value="192.168.1.111"),
            _f("same artifact restated", confidence="confirmed", ioc_type="ip",
               ioc_value="192.168.1.111"),
        ]
        out = dedupe_findings(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].confidence, "confirmed")

    def test_backslash_and_case_normalized_ioc_collapses(self):
        findings = [
            _f("hive", ioc_type="registry_key",
               ioc_value="SYSTEM\\ControlSet001\\Control\\ComputerName"),
            _f("hive again", ioc_type="registry_key",
               ioc_value="system/controlset001/control/computername"),
        ]
        out = dedupe_findings(findings)
        self.assertEqual(len(out), 1)

    def test_collapses_repeated_artifact_by_description_when_no_ioc(self):
        # The real failure: the same Dr. Watson artifact reported 6x with no IOC,
        # only near-identical prose, same artifact_type.
        base = ("A Dr. Watson crash-logging artifact set is present on the volume: "
                "drwtsn32.log and user.dmp under All Users Application Data Microsoft "
                "Dr Watson")
        findings = [
            _f(base + f" (observed by agent {i})", artifact_type="filesystem")
            for i in range(6)
        ]
        out = dedupe_findings(findings)
        self.assertEqual(len(out), 1)

    def test_distinct_findings_are_preserved(self):
        findings = [
            _f("Network Stumbler installed", ioc_type="file_path",
               ioc_value="C:/Program Files/Network Stumbler"),
            _f("Ethereal installed", ioc_type="file_path",
               ioc_value="C:/Program Files/Ethereal"),
            _f("Registered owner Greg Schardt", ioc_type="registry_key",
               ioc_value="SOFTWARE/Microsoft/Windows NT/CurrentVersion"),
        ]
        out = dedupe_findings(findings)
        self.assertEqual(len(out), 3)

    def test_similar_description_but_different_artifact_type_not_merged(self):
        # Same words, different artifact_type -> not the same artifact; keep both.
        findings = [
            _f("user activity recorded", artifact_type="registry"),
            _f("user activity recorded", artifact_type="prefetch"),
        ]
        out = dedupe_findings(findings)
        self.assertEqual(len(out), 2)

    def test_empty_input(self):
        self.assertEqual(dedupe_findings([]), [])

    def test_order_is_stable(self):
        findings = [
            _f("alpha", ioc_type="ip", ioc_value="1.1.1.1"),
            _f("beta", ioc_type="ip", ioc_value="2.2.2.2"),
            _f("alpha dup", ioc_type="ip", ioc_value="1.1.1.1"),
        ]
        out = dedupe_findings(findings)
        self.assertEqual([f.description for f in out], ["alpha", "beta"])


if __name__ == "__main__":
    unittest.main()
