# pyre-strict
"""Hallucination detector — cross-checks findings against the audit log.

A finding is flagged as a hallucination when its ``evidence_links`` cannot be
resolved to real ``tool_execution`` events in ``audit.jsonl``. This is the
SANS Criterion 2 "claims with no supporting tool output" check.

The detector also surfaces hallucinations the agent itself caught (verifier
verdicts of ``refuted`` and ``self_correction`` events). These go into a
separate ``caught`` bucket — credit, not penalty.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HallucinationFlag:
    """One flagged finding plus the reason it was flagged."""

    finding_id: str
    description: str
    reason: str
    unresolved_links: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HallucinationReport:
    """Output of ``detect_hallucinations``.

    ``flagged`` are unverified hallucinations (uncaught by the agent).
    ``caught`` are hallucinations the agent's own verifier already removed or
    downgraded — these earn credit under SANS Criterion 2's
    "hallucinations caught & flagged" bullet.
    """

    flagged: list[HallucinationFlag] = field(default_factory=list)
    caught: list[HallucinationFlag] = field(default_factory=list)


def detect_hallucinations(
    findings: list[dict[str, Any]],
    audit_events: list[dict[str, Any]],
) -> HallucinationReport:
    """Flag findings whose evidence_links don't resolve to audit executions.

    ``findings`` is the report's ``findings`` list (each is a dict with
    ``finding_id``, ``description``, ``evidence_links``, ...).
    ``audit_events`` is the raw audit log (list of dicts, one per JSONL line).
    """
    successful_ids = _successful_execution_ids(audit_events)
    all_exec_ids = _execution_ids(audit_events)
    flagged = _flag_unresolved(findings, successful_ids, all_exec_ids)
    caught = _caught_by_verifier(audit_events)
    return HallucinationReport(flagged=flagged, caught=caught)


def _execution_ids(audit_events: list[dict[str, Any]]) -> set[str]:
    """Return event_ids of all tool_execution events in the audit log."""
    return {
        e.get("event_id", "")
        for e in audit_events
        if e.get("event_type") == "tool_execution" and e.get("event_id")
    }


def _successful_execution_ids(audit_events: list[dict[str, Any]]) -> set[str]:
    """Return event_ids of tool_executions that actually produced output.

    A finding is only properly grounded when its backing tool ran to
    completion (``exit_code == 0``) and wasn't rejected by the executor.
    Failed or rejected executions appear in audit.jsonl but produced no
    output the LLM could legitimately interpret — referencing them is a
    hallucination the accuracy & scoring layer catches.
    """
    return {
        e.get("event_id", "")
        for e in audit_events
        if e.get("event_type") == "tool_execution"
        and e.get("event_id")
        and e.get("exit_code", -1) == 0
        and not e.get("rejected", False)
    }


def _flag_unresolved(
    findings: list[dict[str, Any]],
    successful_ids: set[str],
    all_exec_ids: set[str],
) -> list[HallucinationFlag]:
    """Flag any finding with no evidence links or unresolved/failed links.

    A link is "resolved" only when it points at a *successful*
    tool_execution. Links that match a known event_id but the event was
    rejected or exited non-zero are reported separately so the failure
    mode is clear in the human report.
    """
    flagged: list[HallucinationFlag] = []
    for f in findings:
        finding_id = f.get("finding_id", "")
        description = f.get("description", "")
        links = list(f.get("evidence_links", []))

        if not links:
            flagged.append(
                HallucinationFlag(
                    finding_id=finding_id,
                    description=description,
                    reason="no evidence_links — finding has no backing tool execution",
                )
            )
            continue

        bad = [link for link in links if link not in successful_ids]
        if not bad:
            continue

        missing = [link for link in bad if link not in all_exec_ids]
        failed = [link for link in bad if link in all_exec_ids]
        parts: list[str] = []
        if missing:
            parts.append(
                f"{len(missing)}/{len(links)} evidence_links not in "
                f"audit.jsonl tool_execution events"
            )
        if failed:
            parts.append(
                f"{len(failed)}/{len(links)} evidence_links point at tool_executions "
                f"that failed or were rejected (no real output)"
            )
        flagged.append(
            HallucinationFlag(
                finding_id=finding_id,
                description=description,
                reason="; ".join(parts),
                unresolved_links=bad,
            )
        )
    return flagged


def _caught_by_verifier(
    audit_events: list[dict[str, Any]],
) -> list[HallucinationFlag]:
    """Surface findings the verifier refuted or self-corrected (credit)."""
    caught: list[HallucinationFlag] = []
    seen: set[str] = set()

    for e in audit_events:
        if e.get("event_type") == "verification" and e.get("verdict") == "refuted":
            fid = e.get("finding_id", "")
            if fid and fid not in seen:
                seen.add(fid)
                caught.append(
                    HallucinationFlag(
                        finding_id=fid,
                        description="(refuted before reaching final report)",
                        reason="verifier verdict=refuted — agent caught its own hallucination",
                    )
                )

    for e in audit_events:
        if e.get("event_type") != "self_correction":
            continue
        verdict = e.get("verdict", "")
        if verdict not in ("refuted", "downgraded"):
            continue
        fid = e.get("finding_id", "")
        if fid and fid not in seen:
            seen.add(fid)
            caught.append(
                HallucinationFlag(
                    finding_id=fid,
                    description="(self-corrected)",
                    reason=(
                        f"self_correction event: "
                        f"{e.get('previous_confidence', '?')} -> "
                        f"{e.get('new_confidence', '?')} (verdict={verdict})"
                    ),
                )
            )

    return caught
