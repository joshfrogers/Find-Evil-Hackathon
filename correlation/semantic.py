"""LLM-based semantic correlator for forensic findings.

Analyzes finding descriptions to identify semantically related activity
that temporal clustering alone would miss — e.g., a file written to
C:\\Temp and a registry key referencing the same filename hours apart.

Uses call_claude_json() with the project's global LLM settings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agents.base import Finding
from agents.claude import call_claude_json

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a digital forensics analyst reviewing findings from a disk "
    "image investigation. Your job is to identify semantically related "
    "findings that describe parts of the same activity or attack chain, "
    "even if they occurred at different times or came from different "
    "artifact types."
)


@dataclass
class SemanticCluster:
    cluster_id: str
    label: str
    finding_ids: list[str] = field(default_factory=list)
    reasoning: str = ""


@dataclass
class SemanticCorrelationResult:
    clusters: list[SemanticCluster] = field(default_factory=list)
    unclustered_ids: list[str] = field(default_factory=list)


def _build_prompt(findings: list[Finding]) -> str:
    finding_lines = []
    for f in findings:
        finding_lines.append(
            f"- ID: {f.finding_id} | Type: {f.artifact_type or 'unknown'} "
            f"| Time: {f.timestamp or 'unknown'} | Desc: {f.description}"
        )
    findings_block = "\n".join(finding_lines)

    return f"""Below are forensic findings from a disk image investigation.
Group findings that describe related activity — same file, same actor,
same attack technique, same IOC, or parts of the same intrusion step.

Only group findings that are genuinely related. Do NOT force unrelated
findings into a group. A finding can appear in at most one group.
Findings with no semantic relationship to others should be left ungrouped.

FINDINGS:
{findings_block}

Respond with ONLY this JSON (no markdown fences, no extra text):
{{
  "clusters": [
    {{
      "label": "short descriptive label for this activity group",
      "finding_ids": ["F-xxx", "F-yyy"],
      "reasoning": "why these findings are related"
    }}
  ]
}}

Rules:
- Each cluster must have >= 2 findings
- A finding can appear in at most one cluster
- Only include clusters where the relationship is clear
- If no findings are related, return {{"clusters": []}}"""


def correlate_semantically(
    findings: list[Finding],
    timeout: int = 120,
) -> SemanticCorrelationResult:
    """Use LLM to identify semantically related findings.

    Args:
        findings: List of forensic findings to analyze.
        timeout: LLM call timeout in seconds.

    Returns:
        SemanticCorrelationResult with clusters of related findings
        and a list of unclustered finding IDs.
    """
    if len(findings) < 2:
        return SemanticCorrelationResult(
            unclustered_ids=[f.finding_id for f in findings],
        )

    valid_ids = {f.finding_id for f in findings}
    prompt = _build_prompt(findings)

    response = call_claude_json(prompt, system_prompt=_SYSTEM_PROMPT, timeout=timeout)
    if response is None:
        logger.warning("LLM semantic correlation failed — returning empty result")
        return SemanticCorrelationResult(
            unclustered_ids=[f.finding_id for f in findings],
        )

    return _parse_response(response, valid_ids)


def _parse_response(
    response: dict[str, Any],
    valid_ids: set[str],
) -> SemanticCorrelationResult:
    """Parse and validate LLM response into SemanticCorrelationResult."""
    raw_clusters = response.get("clusters", [])
    if not isinstance(raw_clusters, list):
        return SemanticCorrelationResult(unclustered_ids=list(valid_ids))

    clusters: list[SemanticCluster] = []
    claimed_ids: set[str] = set()

    for i, raw in enumerate(raw_clusters):
        if not isinstance(raw, dict):
            continue

        ids = raw.get("finding_ids", [])
        if not isinstance(ids, list):
            continue

        filtered_ids = [
            fid for fid in ids if fid in valid_ids and fid not in claimed_ids
        ]
        if len(filtered_ids) < 2:
            continue

        cluster = SemanticCluster(
            cluster_id=f"SC-{i + 1}",
            label=str(raw.get("label", f"Semantic cluster {i + 1}")),
            finding_ids=filtered_ids,
            reasoning=str(raw.get("reasoning", "")),
        )
        clusters.append(cluster)
        claimed_ids.update(filtered_ids)

    unclustered = [fid for fid in valid_ids if fid not in claimed_ids]

    return SemanticCorrelationResult(
        clusters=clusters,
        unclustered_ids=sorted(unclustered),
    )
