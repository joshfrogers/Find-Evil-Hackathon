# pyre-strict
"""Accuracy scorer — compares an investigation report to a ground-truth baseline.

Implements SANS Find Evil! Criterion 2 (IR Accuracy) by reporting:

- False positives: findings the agent reported that aren't in the baseline.
- Missed artifacts: ``must_find`` baseline items the agent failed to surface.
- Hallucinated claims: findings whose evidence_links don't resolve to real
  tool_execution events in ``audit.jsonl`` (see
  ``accuracy/hallucination.py``).
- Confirmed vs inferred breakdown: are direct-evidence findings clearly
  distinguished from inferences? (Criterion 2 calls this out explicitly.)
- Hallucinations caught & flagged: credit for the agent refuting or
  self-correcting its own bad findings.

Matching strategy (in priority order, first match wins):

1. Exact normalized IOC match. Uses the shared
   ``verification.corroboration._normalize_ioc`` helper so the same casing /
   slash normalization that powers cross-domain corroboration also powers
   scoring. IOC type must be compatible (identical, or one side blank).
2. Description fuzzy match via ``difflib.SequenceMatcher`` (stdlib) above a
   configurable ratio threshold. Catches paraphrases of the same finding
   when an IOC isn't present (e.g. timestomping, prefetch execution proof).

Pure-stdlib; no third-party deps.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Any

from accuracy.baseline import Baseline, BaselineFinding
from accuracy.hallucination import detect_hallucinations
from verification.corroboration import _normalize_ioc

logger: logging.Logger = logging.getLogger(__name__)

DESCRIPTION_MATCH_THRESHOLD: float = 0.55

# IOC types that name a path (filesystem or registry). These match by aligned
# path segments — so a mount-root-prefixed or drive-relative agent path
# (e.g. ``/.../mnt/vol0/Program Files/mIRC/mirc.ini``) lines up with a baseline's
# Windows-absolute IOC (``C:\Program Files\mIRC\mirc.ini``), and a registry
# key+value path lines up with the baseline's key-only IOC.
_PATH_IOC_TYPES: set[str] = {"file_path", "registry_key"}
# Minimum aligned contiguous segments for a path match — 2 avoids matching on a
# single common leaf like "config" or "CurrentVersion".
_MIN_PATH_SEGMENTS: int = 2


@dataclass(frozen=True)
class MatchedFinding:
    """A successful match between an agent finding and a baseline item."""

    finding_id: str
    baseline_id: str
    match_kind: str  # ioc_exact | description_fuzzy
    description: str
    baseline_description: str
    similarity: float = 0.0


@dataclass(frozen=True)
class AccuracyScore:
    """Output of ``score_report`` — the SANS-aligned scoring block.

    Numbers are derived from baseline.required_findings (``must_find=True``)
    and the agent's final findings list. Bonus baseline items (``must_find=
    False``) count toward matched_findings but not toward the recall
    denominator.
    """

    baseline_id: str
    total_agent_findings: int
    total_baseline_findings: int
    required_baseline_findings: int
    precision: float
    recall: float
    f1: float
    hallucination_rate: float
    matched_findings: list[MatchedFinding] = field(default_factory=list)
    missed_baseline_findings: list[str] = field(default_factory=list)
    extra_findings: list[str] = field(default_factory=list)
    confirmed_vs_inferred: dict[str, int] = field(default_factory=dict)
    hallucinations_flagged: list[dict[str, Any]] = field(default_factory=list)
    hallucinations_caught_by_verifier: list[dict[str, Any]] = field(
        default_factory=list
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for embedding in ``report.json`` as ``accuracy_score``."""
        out = asdict(self)
        out["matched_findings"] = [asdict(m) for m in self.matched_findings]
        return out


def score_report(
    report: dict[str, Any],
    audit_events: list[dict[str, Any]],
    baseline: Baseline,
) -> AccuracyScore:
    """Score an investigation report against a baseline.

    ``report`` is the report.json dict; ``audit_events`` is the parsed
    audit.jsonl event list; ``baseline`` is from ``load_baseline``.
    """
    findings = list(report.get("findings", []))
    matches, used_baseline_ids = _match_findings(findings, baseline.findings)

    matched_finding_ids = {m.finding_id for m in matches}
    extra = [
        f.get("finding_id", "")
        for f in findings
        if f.get("finding_id", "") not in matched_finding_ids
    ]
    missed = [b.id for b in baseline.required_findings if b.id not in used_baseline_ids]

    halluc = detect_hallucinations(findings, audit_events)
    metrics = _compute_metrics(
        true_positives=len(matches),
        false_positives=len(extra),
        required_total=len(baseline.required_findings),
        agent_total=len(findings),
        flagged_hallucinations=len(halluc.flagged),
    )

    return AccuracyScore(
        baseline_id=baseline.case_id,
        total_agent_findings=len(findings),
        total_baseline_findings=len(baseline.findings),
        required_baseline_findings=len(baseline.required_findings),
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1=metrics["f1"],
        hallucination_rate=metrics["hallucination_rate"],
        matched_findings=matches,
        missed_baseline_findings=missed,
        extra_findings=extra,
        confirmed_vs_inferred=_confidence_breakdown(findings),
        hallucinations_flagged=[asdict(h) for h in halluc.flagged],
        hallucinations_caught_by_verifier=[asdict(h) for h in halluc.caught],
    )


def _match_findings(
    findings: list[dict[str, Any]], baseline_findings: list[BaselineFinding]
) -> tuple[list[MatchedFinding], set[str]]:
    """Match each agent finding to at most one baseline item.

    Greedy first-match-wins across two passes: exact IOC first (high
    precision), then description fuzzy match (handles paraphrases without
    IOCs). A baseline item, once matched, cannot match a second finding.
    """
    matches: list[MatchedFinding] = []
    used: set[str] = set()

    for f in findings:
        m = _try_ioc_match(f, baseline_findings, used)
        if m is None:
            m = _try_path_ioc_match(f, baseline_findings, used)
        if m is None:
            m = _try_description_match(f, baseline_findings, used)
        if m is not None:
            matches.append(m)
            used.add(m.baseline_id)

    return matches, used


def _try_ioc_match(
    finding: dict[str, Any],
    baseline_findings: list[BaselineFinding],
    used: set[str],
) -> MatchedFinding | None:
    ioc_value = (finding.get("ioc_value") or "").strip()
    if not ioc_value:
        return None
    ioc_type = finding.get("ioc_type") or ""
    norm = _normalize_ioc(ioc_value)

    for b in baseline_findings:
        if b.id in used or not b.ioc_value:
            continue
        if _normalize_ioc(b.ioc_value) != norm:
            continue
        if ioc_type and b.ioc_type and ioc_type != b.ioc_type:
            continue
        return MatchedFinding(
            finding_id=finding.get("finding_id", ""),
            baseline_id=b.id,
            match_kind="ioc_exact",
            description=finding.get("description", ""),
            baseline_description=b.description,
            similarity=1.0,
        )
    return None


def _path_segments(value: str) -> list[str]:
    """Normalized path segments: lowercase, ``\\``→``/``, drop a drive letter."""
    norm = re.sub(r"^[a-z]:", "", _normalize_ioc(value))
    return [p for p in norm.split("/") if p]


def _contiguous_sublist(short: list[str], long: list[str]) -> bool:
    n = len(short)
    return any(long[i : i + n] == short for i in range(len(long) - n + 1))


def _path_segments_align(a_value: str, b_value: str) -> bool:
    """True when one path's segments appear as a contiguous run inside the
    other's (>= _MIN_PATH_SEGMENTS). Handles a mount/drive prefix on one side
    (the shorter is a trailing run of the longer) and a registry value suffix on
    one side (the shorter is a leading run of the longer)."""
    sa, sb = _path_segments(a_value), _path_segments(b_value)
    short, long = (sa, sb) if len(sa) <= len(sb) else (sb, sa)
    if len(short) < _MIN_PATH_SEGMENTS:
        return False
    return _contiguous_sublist(short, long)


def _try_path_ioc_match(
    finding: dict[str, Any],
    baseline_findings: list[BaselineFinding],
    used: set[str],
) -> MatchedFinding | None:
    """Match path-like IOCs by aligned segments when exact IOC match failed."""
    ioc_value = (finding.get("ioc_value") or "").strip()
    if not ioc_value:
        return None
    ioc_type = finding.get("ioc_type") or ""
    if ioc_type and ioc_type not in _PATH_IOC_TYPES:
        return None

    for b in baseline_findings:
        if b.id in used or not b.ioc_value:
            continue
        if b.ioc_type and b.ioc_type not in _PATH_IOC_TYPES:
            continue
        if ioc_type and b.ioc_type and ioc_type != b.ioc_type:
            continue
        if _path_segments_align(ioc_value, b.ioc_value):
            return MatchedFinding(
                finding_id=finding.get("finding_id", ""),
                baseline_id=b.id,
                match_kind="ioc_path",
                description=finding.get("description", ""),
                baseline_description=b.description,
                similarity=0.9,
            )
    return None


def _try_description_match(
    finding: dict[str, Any],
    baseline_findings: list[BaselineFinding],
    used: set[str],
) -> MatchedFinding | None:
    desc = (finding.get("description") or "").strip().lower()
    if not desc:
        return None

    best_ratio = 0.0
    best: BaselineFinding | None = None
    for b in baseline_findings:
        if b.id in used:
            continue
        ratio = SequenceMatcher(None, desc, b.description.lower()).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best = b

    if best is None or best_ratio < DESCRIPTION_MATCH_THRESHOLD:
        return None

    return MatchedFinding(
        finding_id=finding.get("finding_id", ""),
        baseline_id=best.id,
        match_kind="description_fuzzy",
        description=finding.get("description", ""),
        baseline_description=best.description,
        similarity=round(best_ratio, 3),
    )


def _compute_metrics(
    true_positives: int,
    false_positives: int,
    required_total: int,
    agent_total: int,
    flagged_hallucinations: int,
) -> dict[str, float]:
    """Standard precision / recall / F1 + hallucination rate."""
    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives)
        else 0.0
    )
    recall = true_positives / required_total if required_total else 0.0
    f1 = (
        (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    )
    halluc_rate = flagged_hallucinations / agent_total if agent_total else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "hallucination_rate": round(halluc_rate, 4),
    }


def _confidence_breakdown(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by confidence — the Criterion 2 'confirmed vs inferred' ask."""
    out = {"confirmed": 0, "inferred": 0, "possible": 0, "other": 0}
    for f in findings:
        conf = f.get("confidence", "")
        if conf in out:
            out[conf] += 1
        else:
            out["other"] += 1
    return out
