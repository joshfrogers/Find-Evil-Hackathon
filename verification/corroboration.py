# pyre-strict
"""Deterministic cross-domain corroboration for forensic findings.

Two findings corroborate when, despite coming from *different* domain
sub-agents, they point at the same underlying activity. This is computed
deterministically (no LLM) so it is fast, auditable, and independent of the
correlation engine.

Finding A corroborates finding B (from a different agent) when ANY of:
  - exact IOC match: same normalized ``ioc_value`` with a compatible ``ioc_type``;
  - same ``artifact_type`` within a time window (default 5 minutes);
  - shared evidence: overlapping ``evidence_links`` (same execution id).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agents.base import Finding

DEFAULT_WINDOW_SECONDS: int = 300


@dataclass(frozen=True)
class Corroboration:
    """Cross-domain support discovered for a single finding."""

    finding_id: str
    corroborating_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.corroborating_ids)


def _normalize_ioc(value: str) -> str:
    return value.strip().lower().replace("\\", "/")


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ioc_match(a: "Finding", b: "Finding") -> bool:
    if not a.ioc_value or not b.ioc_value:
        return False
    if _normalize_ioc(a.ioc_value) != _normalize_ioc(b.ioc_value):
        return False
    # Compatible type: identical, or one side left unspecified.
    return (not a.ioc_type) or (not b.ioc_type) or (a.ioc_type == b.ioc_type)


def _artifact_time_match(a: "Finding", b: "Finding", window_seconds: int) -> bool:
    if not a.artifact_type or a.artifact_type != b.artifact_type:
        return False
    ta, tb = _parse_ts(a.timestamp), _parse_ts(b.timestamp)
    if ta is None or tb is None:
        return False
    return abs((ta - tb).total_seconds()) <= window_seconds


def _evidence_overlap(a: "Finding", b: "Finding") -> bool:
    return bool(set(a.evidence_links) & set(b.evidence_links))


def _match_reason(a: "Finding", b: "Finding", window_seconds: int) -> str | None:
    """Return a human-readable reason A and B corroborate, or None."""
    if _ioc_match(a, b):
        return f"shared IOC {a.ioc_type or 'value'}={a.ioc_value}"
    if _artifact_time_match(a, b, window_seconds):
        return f"same {a.artifact_type} artifact within {window_seconds}s"
    if _evidence_overlap(a, b):
        shared = sorted(set(a.evidence_links) & set(b.evidence_links))
        return f"shared evidence {', '.join(shared)}"
    return None


class CorroborationIndex:
    """Deterministic cross-domain corroboration over a set of findings.

    Usage:
        index = CorroborationIndex(all_findings)
        c = index.for_finding(finding.finding_id)
        if c.count >= 1: ...  # supported by another domain
    """

    def __init__(
        self,
        findings: Iterable["Finding"],
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._window = window_seconds
        self._by_id: dict[str, Corroboration] = self._build(list(findings))

    def _build(self, findings: list["Finding"]) -> dict[str, Corroboration]:
        index: dict[str, Corroboration] = {}
        for a in findings:
            ids: list[str] = []
            reasons: list[str] = []
            for b in findings:
                if a.finding_id == b.finding_id:
                    continue
                # Cross-domain only: same agent is not independent corroboration.
                if a.agent_name and a.agent_name == b.agent_name:
                    continue
                reason = _match_reason(a, b, self._window)
                if reason is not None and b.finding_id not in ids:
                    ids.append(b.finding_id)
                    reasons.append(f"{b.finding_id} ({reason})")
            index[a.finding_id] = Corroboration(a.finding_id, ids, reasons)
        return index

    def for_finding(self, finding_id: str) -> Corroboration:
        return self._by_id.get(finding_id, Corroboration(finding_id))
