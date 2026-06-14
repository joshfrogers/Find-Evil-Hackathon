"""Correlation engine for timeline analysis and event chain detection."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agents.base import Finding

logger = logging.getLogger(__name__)

_TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
]


def _parse_timestamp(ts: str) -> datetime | None:
    """Parse a timestamp string and normalize to UTC.

    Supports ``%Y-%m-%dT%H:%M:%SZ``, ``%Y-%m-%dT%H:%M:%S%z``,
    and ``%Y-%m-%d %H:%M:%S``.  Non-UTC timezones are converted to UTC.
    Naive datetimes are assumed UTC.  Returns ``None`` for empty or
    unparseable strings.
    """
    if not ts or not ts.strip():
        return None
    ts = ts.strip()
    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt
        except ValueError:
            continue
    return None


@dataclass
class TimelineEntry:
    timestamp: str
    description: str
    artifact_type: str
    finding_ids: list[str] = field(default_factory=list)
    cluster_id: str = ""


@dataclass
class EventChain:
    chain_id: str
    description: str
    entry_ids: list[str] = field(default_factory=list)
    confidence: str = "inferred"

    @classmethod
    def new(
        cls,
        index: int,
        description: str,
        entry_ids: list[str],
        confidence: str = "inferred",
    ) -> EventChain:
        return cls(
            chain_id=f"CH-{index}",
            description=description,
            entry_ids=entry_ids,
            confidence=confidence,
        )


@dataclass
class TimelineGap:
    anomaly_id: str
    description: str
    gap_start: str
    gap_end: str
    gap_type: str

    @classmethod
    def new(
        cls,
        index: int,
        description: str,
        gap_start: str,
        gap_end: str,
        gap_type: str = "gap",
    ) -> TimelineGap:
        return cls(
            anomaly_id=f"A-{index}",
            description=description,
            gap_start=gap_start,
            gap_end=gap_end,
            gap_type=gap_type,
        )


@dataclass
class CorrelationResult:
    timeline: list[TimelineEntry] = field(default_factory=list)
    event_chains: list[EventChain] = field(default_factory=list)
    timeline_gaps: list[TimelineGap] = field(default_factory=list)
    semantic_clusters: list[Any] = field(default_factory=list)


class CorrelationEngine:
    """Builds timelines, detects event chains, and identifies timeline gaps."""

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings

    def _build_timeline(self) -> list[TimelineEntry]:
        """Build a sorted timeline from findings.

        Findings with valid timestamps are normalized to UTC and sorted
        chronologically.  Findings with missing or unparseable timestamps
        are appended at the end with ``timestamp="UNKNOWN"``.
        """
        timed: list[tuple[datetime, TimelineEntry]] = []
        untimed: list[TimelineEntry] = []
        for finding in self.findings:
            dt = _parse_timestamp(finding.timestamp)
            if dt is None:
                untimed.append(
                    TimelineEntry(
                        timestamp="UNKNOWN",
                        description=finding.description,
                        artifact_type=finding.artifact_type,
                        finding_ids=[finding.finding_id],
                    )
                )
            else:
                timed.append(
                    (
                        dt,
                        TimelineEntry(
                            timestamp=dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            description=finding.description,
                            artifact_type=finding.artifact_type,
                            finding_ids=[finding.finding_id],
                        ),
                    )
                )
        timed.sort(key=lambda pair: pair[0])
        return [entry for _, entry in timed] + untimed

    def _cluster_events(
        self,
        timeline: list[TimelineEntry],
        gap_threshold_seconds: int = 600,
    ) -> list[list[TimelineEntry]]:
        """Group consecutive timeline events separated by <= gap_threshold_seconds."""
        if not timeline:
            return []

        clusters: list[list[TimelineEntry]] = []
        current_cluster: list[TimelineEntry] = [timeline[0]]

        for i in range(1, len(timeline)):
            prev_dt = _parse_timestamp(timeline[i - 1].timestamp)
            curr_dt = _parse_timestamp(timeline[i].timestamp)
            if prev_dt is not None and curr_dt is not None:
                gap = (curr_dt - prev_dt).total_seconds()
                if gap <= gap_threshold_seconds:
                    current_cluster.append(timeline[i])
                else:
                    clusters.append(current_cluster)
                    current_cluster = [timeline[i]]
            else:
                current_cluster.append(timeline[i])

        clusters.append(current_cluster)

        for idx, cluster in enumerate(clusters, start=1):
            cluster_id = f"C-{idx}"
            for entry in cluster:
                entry.cluster_id = cluster_id

        return clusters

    def _detect_event_chains(
        self, cluster: list[TimelineEntry], index: int
    ) -> list[EventChain]:
        """Detect event chains within a cluster.

        An event chain requires >= 2 distinct artifact types in the cluster.
        """
        artifact_types = {e.artifact_type for e in cluster}
        if len(artifact_types) < 2:
            return []

        description = " → ".join(e.description for e in cluster)
        entry_ids: list[str] = []
        for e in cluster:
            entry_ids.extend(e.finding_ids)

        chain = EventChain.new(
            index=index,
            description=description,
            entry_ids=entry_ids,
        )
        return [chain]

    def _detect_gaps(
        self,
        timeline: list[TimelineEntry],
        min_gap_hours: int = 2,
    ) -> list[TimelineGap]:
        """Detect temporal gaps in the timeline that exceed min_gap_hours."""
        gaps: list[TimelineGap] = []
        min_gap_seconds = min_gap_hours * 3600

        for i in range(1, len(timeline)):
            prev_dt = _parse_timestamp(timeline[i - 1].timestamp)
            curr_dt = _parse_timestamp(timeline[i].timestamp)
            if prev_dt is None or curr_dt is None:
                continue
            gap = (curr_dt - prev_dt).total_seconds()
            if gap >= min_gap_seconds:
                hours = gap / 3600
                timeline_gap = TimelineGap.new(
                    index=len(gaps) + 1,
                    description=f"No events for {hours:.1f} hours",
                    gap_start=timeline[i - 1].timestamp,
                    gap_end=timeline[i].timestamp,
                    gap_type="gap",
                )
                gaps.append(timeline_gap)

        return gaps

    def correlate(self, use_llm: bool = True) -> CorrelationResult:
        """Run full correlation: timeline, clustering, event chains, timeline gaps, semantic.

        Args:
            use_llm: If True, run LLM-based semantic correlation after
                temporal analysis. Set to False to skip the LLM call
                (useful for tests and offline runs).
        """
        if not self.findings:
            return CorrelationResult()
        timeline = self._build_timeline()

        clusters = self._cluster_events(timeline)
        event_chains: list[EventChain] = []
        for cluster in clusters:
            event_chains.extend(
                self._detect_event_chains(cluster, index=len(event_chains) + 1)
            )

        timeline_gaps = self._detect_gaps(timeline)

        semantic_clusters: list[Any] = []
        if use_llm and len(self.findings) >= 2:
            try:
                from correlation.semantic import correlate_semantically

                sem_result = correlate_semantically(self.findings)
                semantic_clusters = sem_result.clusters
            except Exception:
                logger.warning("Semantic correlation failed — skipping", exc_info=True)

        return CorrelationResult(
            timeline=timeline,
            event_chains=event_chains,
            timeline_gaps=timeline_gaps,
            semantic_clusters=semantic_clusters,
        )
