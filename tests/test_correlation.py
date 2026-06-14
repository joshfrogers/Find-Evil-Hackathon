"""Tests for correlation data models and CorrelationEngine."""

import sys
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.base import Finding
from correlation.engine import (
    TimelineGap,
    EventChain,
    CorrelationEngine,
    CorrelationResult,
    TimelineEntry,
)


def _make_finding(
    description: str = "test",
    timestamp: str = "",
    artifact_type: str = "",
    confidence: str = "confirmed",
    **kwargs,
) -> Finding:
    return Finding.new(
        description=description,
        confidence=confidence,
        evidence_links=kwargs.get("evidence_links", ["E-1"]),
        timestamp=timestamp,
        artifact_type=artifact_type,
    )


class TestCorrelationModels(unittest.TestCase):
    def test_timeline_entry_creation(self):
        entry = TimelineEntry(
            timestamp="2024-01-15T10:30:00Z",
            description="Suspicious login detected",
            artifact_type="auth_log",
            finding_ids=["F001", "F002"],
            cluster_id="CL-1",
        )
        self.assertEqual(entry.timestamp, "2024-01-15T10:30:00Z")
        self.assertEqual(entry.description, "Suspicious login detected")
        self.assertEqual(entry.artifact_type, "auth_log")
        self.assertEqual(entry.finding_ids, ["F001", "F002"])
        self.assertEqual(entry.cluster_id, "CL-1")

        # Verify defaults
        default_entry = TimelineEntry(
            timestamp="2024-01-15T10:30:00Z",
            description="Event",
            artifact_type="generic",
        )
        self.assertEqual(default_entry.finding_ids, [])
        self.assertEqual(default_entry.cluster_id, "")

    def test_event_chain_creation(self):
        chain = EventChain.new(
            index=1,
            description="Lateral movement via SSH",
            entry_ids=["E1", "E2", "E3"],
            confidence="confirmed",
        )
        self.assertEqual(chain.chain_id, "CH-1")
        self.assertEqual(chain.description, "Lateral movement via SSH")
        self.assertEqual(chain.entry_ids, ["E1", "E2", "E3"])
        self.assertEqual(chain.confidence, "confirmed")

        # Verify default confidence
        default_chain = EventChain.new(
            index=2,
            description="Unknown chain",
            entry_ids=["E4"],
        )
        self.assertEqual(default_chain.chain_id, "CH-2")
        self.assertEqual(default_chain.confidence, "inferred")

    def test_timeline_gap_creation(self):
        timeline_gap = TimelineGap.new(
            index=1,
            description="No log entries for 2 hours",
            gap_start="2024-01-15T02:00:00Z",
            gap_end="2024-01-15T04:00:00Z",
            gap_type="gap",
        )
        self.assertEqual(timeline_gap.anomaly_id, "A-1")
        self.assertEqual(timeline_gap.description, "No log entries for 2 hours")
        self.assertEqual(timeline_gap.gap_start, "2024-01-15T02:00:00Z")
        self.assertEqual(timeline_gap.gap_end, "2024-01-15T04:00:00Z")
        self.assertEqual(timeline_gap.gap_type, "gap")

        # Verify default gap_type
        default_gap = TimelineGap.new(
            index=2,
            description="Missing data",
            gap_start="2024-01-15T00:00:00Z",
            gap_end="2024-01-15T01:00:00Z",
        )
        self.assertEqual(default_gap.anomaly_id, "A-2")
        self.assertEqual(default_gap.gap_type, "gap")

    def test_correlation_result_creation(self):
        entry = TimelineEntry(
            timestamp="2024-01-15T10:30:00Z",
            description="Login event",
            artifact_type="auth_log",
        )
        chain = EventChain.new(
            index=1,
            description="Attack chain",
            entry_ids=["E1"],
        )
        timeline_gap = TimelineGap.new(
            index=1,
            description="Log gap",
            gap_start="2024-01-15T02:00:00Z",
            gap_end="2024-01-15T04:00:00Z",
        )

        result = CorrelationResult(
            timeline=[entry],
            event_chains=[chain],
            timeline_gaps=[timeline_gap],
        )
        self.assertEqual(len(result.timeline), 1)
        self.assertEqual(len(result.event_chains), 1)
        self.assertEqual(len(result.timeline_gaps), 1)
        self.assertEqual(result.timeline[0].description, "Login event")

        # Verify defaults
        empty_result = CorrelationResult()
        self.assertEqual(empty_result.timeline, [])
        self.assertEqual(empty_result.event_chains, [])
        self.assertEqual(empty_result.timeline_gaps, [])


class TestTimelineBuilding(unittest.TestCase):
    def test_build_timeline_sorts_by_timestamp(self):
        f1 = _make_finding(
            description="second",
            timestamp="2024-01-15T10:30:00Z",
            artifact_type="auth_log",
        )
        f2 = _make_finding(
            description="first",
            timestamp="2024-01-15T09:00:00Z",
            artifact_type="process",
        )
        f3 = _make_finding(
            description="third",
            timestamp="2024-01-15T11:00:00Z",
            artifact_type="network",
        )
        engine = CorrelationEngine([f1, f2, f3])
        timeline = engine._build_timeline()
        self.assertEqual(len(timeline), 3)
        self.assertEqual(timeline[0].description, "first")
        self.assertEqual(timeline[1].description, "second")
        self.assertEqual(timeline[2].description, "third")

    def test_build_timeline_appends_untimed_findings_at_end(self):
        f_with = _make_finding(
            description="has timestamp",
            timestamp="2024-01-15T10:00:00Z",
            artifact_type="auth_log",
        )
        f_without = _make_finding(
            description="no timestamp",
            timestamp="",
            artifact_type="process",
        )
        engine = CorrelationEngine([f_without, f_with])
        timeline = engine._build_timeline()
        self.assertEqual(len(timeline), 2)
        self.assertEqual(timeline[0].description, "has timestamp")
        self.assertEqual(timeline[0].timestamp, "2024-01-15T10:00:00Z")
        self.assertEqual(timeline[1].description, "no timestamp")
        self.assertEqual(timeline[1].timestamp, "UNKNOWN")

    def test_build_timeline_normalizes_to_utc(self):
        f_utc = _make_finding(
            description="utc event",
            timestamp="2024-01-15T10:00:00Z",
            artifact_type="auth_log",
        )
        f_offset = _make_finding(
            description="offset event",
            timestamp="2024-01-15T17:00:00+05:00",
            artifact_type="process",
        )
        engine = CorrelationEngine([f_offset, f_utc])
        timeline = engine._build_timeline()
        self.assertEqual(timeline[0].timestamp, "2024-01-15T10:00:00Z")
        self.assertEqual(timeline[0].description, "utc event")
        self.assertEqual(timeline[1].timestamp, "2024-01-15T12:00:00Z")
        self.assertEqual(timeline[1].description, "offset event")

    def test_build_timeline_preserves_artifact_type(self):
        f = _make_finding(
            description="event",
            timestamp="2024-01-15T10:00:00Z",
            artifact_type="registry_key",
        )
        engine = CorrelationEngine([f])
        timeline = engine._build_timeline()
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0].artifact_type, "registry_key")


class TestClustering(unittest.TestCase):
    def test_cluster_groups_close_events(self):
        # 3 events within 5 minutes, 1 event 2 hours later
        f1 = _make_finding(
            description="e1",
            timestamp="2024-01-15T10:00:00Z",
            artifact_type="auth_log",
        )
        f2 = _make_finding(
            description="e2",
            timestamp="2024-01-15T10:03:00Z",
            artifact_type="process",
        )
        f3 = _make_finding(
            description="e3",
            timestamp="2024-01-15T10:05:00Z",
            artifact_type="network",
        )
        f4 = _make_finding(
            description="e4",
            timestamp="2024-01-15T12:00:00Z",
            artifact_type="file_system",
        )
        engine = CorrelationEngine([f1, f2, f3, f4])
        timeline = engine._build_timeline()
        clusters = engine._cluster_events(timeline)
        self.assertEqual(len(clusters), 2)
        self.assertEqual(len(clusters[0]), 3)
        self.assertEqual(len(clusters[1]), 1)
        # Check cluster IDs assigned
        self.assertEqual(clusters[0][0].cluster_id, "C-1")
        self.assertEqual(clusters[1][0].cluster_id, "C-2")

    def test_detect_event_chains_requires_two_artifact_types(self):
        entries = [
            TimelineEntry(
                timestamp="2024-01-15T10:00:00Z",
                description="login",
                artifact_type="auth_log",
                finding_ids=["F-1"],
            ),
            TimelineEntry(
                timestamp="2024-01-15T10:01:00Z",
                description="process spawn",
                artifact_type="process",
                finding_ids=["F-2"],
            ),
            TimelineEntry(
                timestamp="2024-01-15T10:02:00Z",
                description="network call",
                artifact_type="network",
                finding_ids=["F-3"],
            ),
        ]
        engine = CorrelationEngine([])
        chains = engine._detect_event_chains(entries, index=1)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].chain_id, "CH-1")
        self.assertIn("login", chains[0].description)
        self.assertIn("network call", chains[0].description)

    def test_no_event_chain_for_single_artifact_type(self):
        entries = [
            TimelineEntry(
                timestamp="2024-01-15T10:00:00Z",
                description="login1",
                artifact_type="auth_log",
                finding_ids=["F-1"],
            ),
            TimelineEntry(
                timestamp="2024-01-15T10:01:00Z",
                description="login2",
                artifact_type="auth_log",
                finding_ids=["F-2"],
            ),
        ]
        engine = CorrelationEngine([])
        chains = engine._detect_event_chains(entries, index=1)
        self.assertEqual(len(chains), 0)


class TimelineGapDetectionTest(unittest.TestCase):
    def test_detect_timeline_gap(self):
        entries = [
            TimelineEntry(
                timestamp="2024-01-15T10:00:00Z",
                description="event1",
                artifact_type="auth_log",
            ),
            TimelineEntry(
                timestamp="2024-01-15T14:00:00Z",
                description="event2",
                artifact_type="process",
            ),
        ]
        engine = CorrelationEngine([])
        timeline_gaps = engine._detect_gaps(entries)
        self.assertEqual(len(timeline_gaps), 1)
        self.assertEqual(timeline_gaps[0].gap_type, "gap")
        self.assertEqual(timeline_gaps[0].gap_start, "2024-01-15T10:00:00Z")
        self.assertEqual(timeline_gaps[0].gap_end, "2024-01-15T14:00:00Z")

    def test_no_gap_for_small_interval(self):
        entries = [
            TimelineEntry(
                timestamp="2024-01-15T10:00:00Z",
                description="event1",
                artifact_type="auth_log",
            ),
            TimelineEntry(
                timestamp="2024-01-15T10:30:00Z",
                description="event2",
                artifact_type="process",
            ),
        ]
        engine = CorrelationEngine([])
        timeline_gaps = engine._detect_gaps(entries)
        self.assertEqual(len(timeline_gaps), 0)


class TestCorrelateEndToEnd(unittest.TestCase):
    def test_correlate_produces_full_result(self):
        # 3 close events (within 10 min), 1 far event (3 hours later)
        f1 = _make_finding(
            description="login",
            timestamp="2024-01-15T10:00:00Z",
            artifact_type="auth_log",
        )
        f2 = _make_finding(
            description="process spawn",
            timestamp="2024-01-15T10:03:00Z",
            artifact_type="process",
        )
        f3 = _make_finding(
            description="file access",
            timestamp="2024-01-15T10:05:00Z",
            artifact_type="file_system",
        )
        f4 = _make_finding(
            description="exfil",
            timestamp="2024-01-15T13:00:00Z",
            artifact_type="network",
        )
        engine = CorrelationEngine([f1, f2, f3, f4])
        result = engine.correlate(use_llm=False)
        self.assertEqual(len(result.timeline), 4)
        self.assertGreaterEqual(len(result.event_chains), 1)
        self.assertGreaterEqual(len(result.timeline_gaps), 1)

    def test_correlate_with_no_timestamped_findings_appends_as_unknown(self):
        f = _make_finding(description="no time", timestamp="", artifact_type="auth_log")
        engine = CorrelationEngine([f])
        result = engine.correlate(use_llm=False)
        self.assertEqual(len(result.timeline), 1)
        self.assertEqual(result.timeline[0].timestamp, "UNKNOWN")
        self.assertEqual(result.event_chains, [])
        self.assertEqual(result.timeline_gaps, [])

    def test_correlate_links_multiple_artifact_types(self):
        f1 = _make_finding(
            description="auth event",
            timestamp="2024-01-15T10:00:00Z",
            artifact_type="auth_log",
        )
        f2 = _make_finding(
            description="proc event",
            timestamp="2024-01-15T10:01:00Z",
            artifact_type="process",
        )
        f3 = _make_finding(
            description="net event",
            timestamp="2024-01-15T10:02:00Z",
            artifact_type="network",
        )
        engine = CorrelationEngine([f1, f2, f3])
        result = engine.correlate(use_llm=False)
        artifact_types = {e.artifact_type for e in result.timeline}
        self.assertGreaterEqual(len(artifact_types), 2)


if __name__ == "__main__":
    unittest.main()
