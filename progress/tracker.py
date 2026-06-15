"""Persistent progress tracker for cross-iteration learning.

The orchestrator and all agents read/write this file during an
investigation. It tracks hypotheses, failed approaches, and strategy
pivots so the system learns from earlier failures within the same run.

Addresses SANS "Persistent Learning Loop" starter idea and submission
requirement #8 (iteration-over-iteration traces).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Hypothesis:
    """A forensic hypothesis formed during investigation."""

    id: str
    description: str
    status: str = "active"  # active, supported, refuted, contested, inconclusive
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    formed_at: str = ""
    resolved_at: str = ""
    # Set once a contested hypothesis has had a focused follow-up spawned for it,
    # so it is retired from re-dispatch and never replays identical work
    # (see ProgressTracker.open_hypotheses and Investigator._spawn_contested_followups).
    followup_spawned: bool = False

    def __post_init__(self) -> None:
        if not self.formed_at:
            self.formed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class FailedApproach:
    """A tool execution or strategy that didn't work."""

    tool: str
    args: list[str]
    failure: str
    lesson: str
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class StrategyPivot:
    """A change in investigation strategy."""

    from_strategy: str
    to_strategy: str
    reason: str
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class InvestigationProgress:
    """Full investigation state — serialized to disk."""

    investigation_id: str
    evidence_path: str = ""
    evidence_type: str = ""
    started_at: str = ""
    hypotheses: list[Hypothesis] = field(default_factory=list)
    failed_approaches: list[FailedApproach] = field(default_factory=list)
    strategy_pivots: list[StrategyPivot] = field(default_factory=list)
    findings_summary: list[str] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 5
    # status values: in_progress, completed, timed_out, iteration_limit, errored
    status: str = "in_progress"

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class ProgressTracker:
    """Manages investigation progress state.

    Usage:
        tracker = ProgressTracker("/output/inv-001/progress.json")
        tracker.start("inv-001", "/cases/image.E01", "disk")
        tracker.add_hypothesis("H1", "Ransomware delivery via phishing")
        tracker.record_failure("log2timeline", ["--parsers", "all"], "timeout", "Use targeted parsers")
        tracker.increment_iteration()
        tracker.save()
    """

    def __init__(self, output_path: str | Path) -> None:
        self._path = Path(output_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._progress: Optional[InvestigationProgress] = None
        # Sub-agents run concurrently and record failures into this shared
        # tracker, so the append-then-snapshot write is serialized. Re-entrant so
        # a mutator that holds the lock can call save() (which also locks).
        self._lock = threading.RLock()

    def start(
        self,
        investigation_id: str,
        evidence_path: str,
        evidence_type: str,
        max_iterations: int = 5,
    ) -> None:
        self._progress = InvestigationProgress(
            investigation_id=investigation_id,
            evidence_path=evidence_path,
            evidence_type=evidence_type,
            max_iterations=max_iterations,
        )
        self.save()

    def load(self) -> bool:
        """Load existing progress from disk. Returns True if found."""
        if not self._path.exists():
            return False
        with open(self._path) as f:
            data = json.load(f)
        self._progress = InvestigationProgress(
            investigation_id=data["investigation_id"],
            evidence_path=data.get("evidence_path", ""),
            evidence_type=data.get("evidence_type", ""),
            started_at=data.get("started_at", ""),
            hypotheses=[Hypothesis(**h) for h in data.get("hypotheses", [])],
            failed_approaches=[
                FailedApproach(**fa) for fa in data.get("failed_approaches", [])
            ],
            strategy_pivots=[
                StrategyPivot(**sp) for sp in data.get("strategy_pivots", [])
            ],
            findings_summary=data.get("findings_summary", []),
            iteration=data.get("iteration", 0),
            max_iterations=data.get("max_iterations", 5),
            status=data.get("status", "in_progress"),
        )
        return True

    def save(self) -> None:
        with self._lock:
            if not self._progress:
                return
            fd, tmp = tempfile.mkstemp(
                dir=self._path.parent, suffix=".tmp", prefix=".progress-"
            )
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(asdict(self._progress), f, indent=2)
                os.replace(tmp, self._path)
            except BaseException:
                os.unlink(tmp)
                raise

    @property
    def progress(self) -> InvestigationProgress:
        if not self._progress:
            raise RuntimeError("No investigation started. Call start() first.")
        return self._progress

    def add_hypothesis(self, hypothesis_id: str, description: str) -> Hypothesis:
        h = Hypothesis(id=hypothesis_id, description=description)
        # All read-modify-write mutators take the lock: sub-agents run
        # concurrently and a worker's record_failure -> save() -> asdict() can
        # otherwise iterate a list this thread is appending to ("changed size
        # during iteration"). RLock so the nested save() re-enters cleanly.
        with self._lock:
            self.progress.hypotheses.append(h)
            self.save()
        return h

    def update_hypothesis(
        self,
        hypothesis_id: str,
        status: str,
        evidence_for: Optional[list[str]] = None,
        evidence_against: Optional[list[str]] = None,
    ) -> None:
        with self._lock:
            for h in self.progress.hypotheses:
                if h.id == hypothesis_id:
                    h.status = status
                    if evidence_for:
                        h.evidence_for.extend(evidence_for)
                    if evidence_against:
                        h.evidence_against.extend(evidence_against)
                    if status in ("supported", "refuted", "inconclusive"):
                        h.resolved_at = time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                        )
                    self.save()
                    return
        # A missing id must not crash the orchestrator loop; log and ignore so a
        # diverged hypothesis list degrades gracefully rather than aborting a run.
        logger.warning("update_hypothesis: hypothesis not found: %s", hypothesis_id)

    def record_failure(
        self,
        tool: str,
        args: list[str],
        failure: str,
        lesson: str,
    ) -> None:
        with self._lock:
            self.progress.failed_approaches.append(
                FailedApproach(tool=tool, args=args, failure=failure, lesson=lesson)
            )
            self.save()

    def record_pivot(self, from_strategy: str, to_strategy: str, reason: str) -> None:
        with self._lock:
            self.progress.strategy_pivots.append(
                StrategyPivot(
                    from_strategy=from_strategy, to_strategy=to_strategy, reason=reason
                )
            )
            self.save()

    def add_finding_summary(self, summary: str) -> None:
        with self._lock:
            self.progress.findings_summary.append(summary)
            self.save()

    def increment_iteration(self) -> bool:
        """Increment iteration counter. Returns False if limit reached."""
        with self._lock:
            self.progress.iteration += 1
            if self.progress.iteration >= self.progress.max_iterations:
                self.progress.status = "iteration_limit"
                self.save()
                return False
            self.save()
            return True

    def complete(self) -> None:
        with self._lock:
            self.progress.status = "completed"
            self.save()

    def timeout(self) -> None:
        with self._lock:
            self.progress.status = "timed_out"
            self.save()

    def error(self) -> None:
        with self._lock:
            self.progress.status = "errored"
            self.save()

    @property
    def iteration(self) -> int:
        return self.progress.iteration

    @property
    def status(self) -> str:
        return self.progress.status

    @property
    def can_continue(self) -> bool:
        return (
            self.progress.status == "in_progress"
            and self.progress.iteration < self.progress.max_iterations
        )

    @property
    def active_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.progress.hypotheses if h.status == "active"]

    @property
    def open_hypotheses(self) -> list[Hypothesis]:
        """Hypotheses still worth investigating: untested ("active") and
        "contested" ones that have not yet had a focused follow-up spawned.

        A "contested" hypothesis (supported by some evidence, contradicted by
        other) is unresolved, so the loop keeps going while it remains — instead
        of silently ending the run with unused round budget. But once a follow-up
        has been spawned to chase the conflict (Investigator._spawn_contested_
        followups), the original is retired from re-dispatch so it never replays
        identical work. Cleanly supported/refuted/inconclusive ones are resolved
        and excluded.
        """
        return [
            h
            for h in self.progress.hypotheses
            if h.status == "active"
            or (h.status == "contested" and not h.followup_spawned)
        ]

    @property
    def failed_tools(self) -> set[str]:
        """Tools that have failed — sub-agents should avoid these."""
        return {fa.tool for fa in self.progress.failed_approaches}

    def get_lessons(self) -> list[str]:
        """Lessons learned from failures — injected into sub-agent prompts."""
        return [fa.lesson for fa in self.progress.failed_approaches]

    def format_for_prompt(self) -> str:
        """Format current progress for injection into orchestrator prompt."""
        lines = [
            f"## Investigation Progress (Round {min(self.iteration + 1, self.progress.max_iterations)}/{self.progress.max_iterations})"
        ]

        if self.progress.hypotheses:
            lines.append("\n### Hypotheses")
            for h in self.progress.hypotheses:
                lines.append(f"- **{h.id}** [{h.status}]: {h.description}")
                if h.evidence_for:
                    lines.append(f"  Evidence for: {', '.join(h.evidence_for)}")
                if h.evidence_against:
                    lines.append(f"  Evidence against: {', '.join(h.evidence_against)}")

        if self.progress.failed_approaches:
            lines.append("\n### Failed Approaches (avoid these)")
            for fa in self.progress.failed_approaches:
                lines.append(f"- `{fa.tool} {' '.join(fa.args)}` — {fa.failure}")
                lines.append(f"  Lesson: {fa.lesson}")

        if self.progress.strategy_pivots:
            lines.append("\n### Strategy Pivots")
            for sp in self.progress.strategy_pivots:
                lines.append(f"- From: {sp.from_strategy}")
                lines.append(f"  To: {sp.to_strategy}")
                lines.append(f"  Reason: {sp.reason}")

        if self.progress.findings_summary:
            lines.append("\n### Findings So Far")
            for f in self.progress.findings_summary:
                lines.append(f"- {f}")

        return "\n".join(lines)
