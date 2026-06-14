# pyre-strict
"""Ground-truth baseline loader for accuracy scoring.

A baseline encodes what an analyst would actually find on a given evidence
image: the known attack chain(s) and every artifact / IOC that should appear
in a correct investigation report. The scorer (``accuracy/scorer.py``)
compares the agent's findings against this list.

Baseline files live under ``tests/fixtures/baselines/<case_id>.json`` and use
the schema described in this module's docstring (also documented in
``tests/fixtures/baselines/sample-case.json`` as the v0 reference).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BaselineFinding:
    """A single ground-truth artifact that should appear in a correct report.

    ``must_find`` controls whether a missed match counts against recall: True
    items are the recall denominator; False items are bonus credit only (the
    agent gets credit for finding them but no penalty for missing them).
    """

    id: str
    description: str
    ioc_type: str = ""
    ioc_value: str = ""
    artifact_type: str = ""
    attack_chain: str = ""
    expected_confidence: str = ""
    must_find: bool = True
    notes: str = ""


@dataclass(frozen=True)
class Baseline:
    """Ground-truth bundle for a single evidence image."""

    case_id: str
    evidence_image: str
    evidence_type: str
    findings: list[BaselineFinding] = field(default_factory=list)
    attack_chains: list[dict[str, str]] = field(default_factory=list)
    source: str = ""

    @property
    def required_findings(self) -> list[BaselineFinding]:
        """Findings that count toward recall (must_find=True)."""
        return [f for f in self.findings if f.must_find]


def load_baseline(path: str | Path) -> Baseline:
    """Load and validate a baseline JSON file.

    Raises ``FileNotFoundError`` if the file is missing, ``ValueError`` if
    required fields are absent. Schema is intentionally minimal so new
    evidence types can be added by dropping in a new JSON file with the same
    shape.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Baseline not found: {p}")

    with open(p) as f:
        data: dict[str, Any] = json.load(f)

    _require(data, ["case_id", "evidence_image", "findings"], str(p))

    findings: list[BaselineFinding] = []
    for entry in data["findings"]:
        _require(entry, ["id", "description"], f"{p}:findings[]")
        findings.append(
            BaselineFinding(
                id=entry["id"],
                description=entry["description"],
                ioc_type=entry.get("ioc_type", ""),
                ioc_value=entry.get("ioc_value", ""),
                artifact_type=entry.get("artifact_type", ""),
                attack_chain=entry.get("attack_chain", ""),
                expected_confidence=entry.get("expected_confidence", ""),
                must_find=bool(entry.get("must_find", True)),
                notes=entry.get("notes", ""),
            )
        )

    return Baseline(
        case_id=data["case_id"],
        evidence_image=data["evidence_image"],
        evidence_type=data.get("evidence_type", "disk"),
        findings=findings,
        attack_chains=list(data.get("attack_chains", [])),
        source=data.get("source", ""),
    )


def _require(obj: dict[str, Any], keys: list[str], where: str) -> None:
    missing = [k for k in keys if k not in obj]
    if missing:
        raise ValueError(f"Baseline {where}: missing required keys {missing}")
