# pyre-strict
"""Deterministic finding deduplication (no LLM).

Sub-agents and successive rounds often surface the SAME underlying artifact
multiple times (e.g. one Dr. Watson crash log reported as six findings). The
scorer counts each duplicate as its own false positive — a baseline item, once
matched, cannot match a second finding — so duplicates depress precision and
clutter the report. This collapses them deterministically before verification
and scoring.

Two findings are duplicates when EITHER:
  - they carry the same normalized IOC (value + compatible type), OR
  - neither anchors on an IOC, their ``artifact_type`` matches, and their
    descriptions are near-identical (``difflib`` ratio >= threshold).

The first occurrence is kept as the representative; later duplicates merge their
``evidence_links`` into it and upgrade its confidence to the strongest seen.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import TYPE_CHECKING

from verification.corroboration import _normalize_ioc

if TYPE_CHECKING:
    from agents.base import Finding

DESCRIPTION_DUP_THRESHOLD: float = 0.92
_CONFIDENCE_RANK: dict[str, int] = {"confirmed": 3, "inferred": 2, "possible": 1}


def _rank(confidence: str) -> int:
    return _CONFIDENCE_RANK.get(confidence, 0)


def _same_ioc(a: "Finding", b: "Finding") -> bool:
    """Same artifact by IOC: equal normalized value + compatible type."""
    if not a.ioc_value or not b.ioc_value:
        return False
    if _normalize_ioc(a.ioc_value) != _normalize_ioc(b.ioc_value):
        return False
    return (not a.ioc_type) or (not b.ioc_type) or (a.ioc_type == b.ioc_type)


def _same_description(a: "Finding", b: "Finding", threshold: float) -> bool:
    """Same artifact by prose: only when NEITHER side anchors on an IOC (an IOC
    mismatch already means different artifacts), the ``artifact_type`` agrees (so
    similar prose about different artifact kinds is not merged), and the
    descriptions are near-identical."""
    if a.ioc_value or b.ioc_value:
        return False
    if (a.artifact_type or "") != (b.artifact_type or ""):
        return False
    da, db = a.description.strip().lower(), b.description.strip().lower()
    if not da or not db:
        return False
    return SequenceMatcher(None, da, db).ratio() >= threshold


def _is_duplicate(a: "Finding", b: "Finding", threshold: float) -> bool:
    return _same_ioc(a, b) or _same_description(a, b, threshold)


def _merge_into(rep: "Finding", dup: "Finding") -> None:
    # Union evidence links into the representative (stable order, no repeats).
    seen = set(rep.evidence_links)
    for link in dup.evidence_links:
        if link not in seen:
            rep.evidence_links.append(link)
            seen.add(link)
    # Upgrade to the strongest confidence observed across the duplicates.
    if _rank(dup.confidence) > _rank(rep.confidence):
        rep.confidence = dup.confidence
    # Adopt the duplicate's IOC if the representative had none.
    if not rep.ioc_value and dup.ioc_value:
        rep.ioc_type, rep.ioc_value = dup.ioc_type, dup.ioc_value


def dedupe_findings(
    findings: list["Finding"],
    *,
    similarity_threshold: float = DESCRIPTION_DUP_THRESHOLD,
) -> list["Finding"]:
    """Collapse duplicate findings; keep the first occurrence as representative.

    Order-stable: representatives appear in their original first-seen order.
    """
    kept: list["Finding"] = []
    for f in findings:
        rep = next(
            (k for k in kept if _is_duplicate(k, f, similarity_threshold)), None
        )
        if rep is None:
            kept.append(f)
        else:
            _merge_into(rep, f)
    return kept
