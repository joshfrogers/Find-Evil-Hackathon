"""Structured JSON audit logger.

Every tool execution, agent message, finding, and verification is logged
with timestamps and unique IDs. This produces the agent execution logs
required by SANS submission requirement #8.

For multi-agent submissions, SANS requires agent-to-agent message logs
with timestamps. The agent_message event type captures this.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class AuditEvent:
    """Base audit event with common fields."""

    timestamp: str = ""
    event_type: str = ""
    event_id: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not self.event_id:
            self.event_id = f"{self.event_type}-{uuid.uuid4().hex[:12]}"


@dataclass
class ToolExecutionEvent(AuditEvent):
    """Logged every time a SIFT tool is executed or rejected."""

    tool_name: str = ""
    argv: list[str] = field(default_factory=list)
    cwd: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    stdout_hash: str = ""  # integrity: detect if persisted output was altered
    stderr_hash: str = ""
    stdout_path: str = ""  # traceability: where the raw output was persisted
    stderr_path: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    rejected: bool = False
    rejection_reason: str = ""

    def __post_init__(self) -> None:
        self.event_type = "tool_execution"
        super().__post_init__()


@dataclass
class AgentMessageEvent(AuditEvent):
    """Logged for every inter-agent communication."""

    from_agent: str = ""
    to_agent: str = ""
    message_type: str = ""  # task, finding, challenge, verdict
    content_summary: str = ""
    token_count: int = 0

    def __post_init__(self) -> None:
        self.event_type = "agent_message"
        super().__post_init__()


@dataclass
class AgentDecisionEvent(AuditEvent):
    """Logged when an agent decides which tool to use."""

    agent_name: str = ""
    task: str = ""
    tools_considered: list[str] = field(default_factory=list)
    tool_chosen: str = ""
    reasoning: str = ""
    expected_outcome: str = ""

    def __post_init__(self) -> None:
        self.event_type = "agent_decision"
        super().__post_init__()


@dataclass
class FindingEvent(AuditEvent):
    """Logged when an agent produces a forensic finding."""

    agent_name: str = ""
    finding_id: str = ""
    description: str = ""
    confidence: str = ""  # confirmed, inferred, possible
    evidence_links: list[str] = field(default_factory=list)  # execution IDs
    ioc_type: str = ""
    ioc_value: str = ""
    verified_by: str = ""

    def __post_init__(self) -> None:
        self.event_type = "finding"
        super().__post_init__()


@dataclass
class VerificationEvent(AuditEvent):
    """Logged when a verifier agent challenges or confirms a finding."""

    verifier_agent: str = ""
    finding_id: str = ""
    verdict: str = ""  # confirmed, downgraded, refuted
    counter_evidence: list[str] = field(default_factory=list)
    corroboration: list[str] = field(default_factory=list)
    rounds_taken: int = 0

    def __post_init__(self) -> None:
        self.event_type = "verification"
        super().__post_init__()


@dataclass
class SelfCorrectionEvent(AuditEvent):
    """Logged when verification changes a finding (downgrade, refute, recalibrate).

    This is the auditable proof of self-correction — the SANS tiebreaker. Each
    event ties a finding to the verdict + confidence change and the number of
    verification rounds it took to get there.
    """

    finding_id: str = ""
    correction_reason: str = ""
    previous_confidence: str = ""
    new_confidence: str = ""
    verdict: str = ""
    rounds_taken: int = 0

    def __post_init__(self) -> None:
        self.event_type = "self_correction"
        super().__post_init__()


@dataclass
class HypothesisEvent(AuditEvent):
    """Logged when the orchestrator forms, updates, or resolves a hypothesis."""

    hypothesis_id: str = ""
    action: str = ""  # formed, supported, refuted, pivoted
    description: str = ""
    evidence_summary: str = ""

    def __post_init__(self) -> None:
        self.event_type = "hypothesis"
        super().__post_init__()


@dataclass
class OrchestratorPlanEvent(AuditEvent):
    """Logged at the start of each orchestrator investigation round."""

    investigation_round: int = 0
    hypotheses_active: list[str] = field(default_factory=list)
    sub_agents_dispatched: list[str] = field(default_factory=list)
    focus_areas: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.event_type = "orchestrator_plan"
        super().__post_init__()


class AuditLogger:
    """Writes structured audit events to a JSON-lines file.

    Usage:
        logger = AuditLogger("/output/investigation-001/audit.jsonl")
        logger.log_tool_execution(result)
        logger.log_agent_message("orchestrator", "disk_agent", "task", "Analyze partitions")
    """

    def __init__(self, output_path: str | Path) -> None:
        self._path = Path(output_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def _write(self, event: AuditEvent) -> None:
        record = asdict(event)
        with self._lock:
            with open(self._path, "a") as f:
                f.write(json.dumps(record, default=str) + "\n")
            self._events.append(record)

    def _now(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )

    @staticmethod
    def _hash(content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def log_tool_execution(
        self,
        tool_name: str,
        argv: list[str],
        cwd: str,
        exit_code: int,
        duration_ms: int,
        stdout: str,
        stderr: str,
        stdout_truncated: bool = False,
        stderr_truncated: bool = False,
        rejected: bool = False,
        rejection_reason: str = "",
        execution_id: str = "",
        stdout_path: str = "",
        stderr_path: str = "",
    ) -> str:
        event = ToolExecutionEvent(
            timestamp=self._now(),
            event_id=execution_id or f"exec-{int(time.time() * 1000)}",
            tool_name=tool_name,
            argv=argv,
            cwd=cwd,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_hash=self._hash(stdout) if stdout else "",
            stderr_hash=self._hash(stderr) if stderr else "",
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            rejected=rejected,
            rejection_reason=rejection_reason,
        )
        self._write(event)
        return event.event_id

    def log_tool_execution_from_result(self, result: Any) -> str:
        """Convenience: log directly from an ExecutionResult."""
        return self.log_tool_execution(
            tool_name=result.tool,
            argv=result.argv,
            cwd=result.cwd,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            stdout=result.stdout,
            stderr=result.stderr,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            rejected=result.rejected,
            rejection_reason=result.rejection_reason or "",
            execution_id=result.execution_id,
            stdout_path=getattr(result, "stdout_path", "") or "",
            stderr_path=getattr(result, "stderr_path", "") or "",
        )

    def log_agent_message(
        self,
        from_agent: str,
        to_agent: str,
        message_type: str,
        content_summary: str,
        token_count: int = 0,
    ) -> str:
        event = AgentMessageEvent(
            timestamp=self._now(),
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            content_summary=content_summary,
            token_count=token_count,
        )
        self._write(event)
        return event.event_id

    def log_agent_decision(
        self,
        agent_name: str,
        task: str,
        tools_considered: list[str],
        tool_chosen: str,
        reasoning: str,
        expected_outcome: str = "",
    ) -> str:
        event = AgentDecisionEvent(
            timestamp=self._now(),
            agent_name=agent_name,
            task=task,
            tools_considered=tools_considered,
            tool_chosen=tool_chosen,
            reasoning=reasoning,
            expected_outcome=expected_outcome,
        )
        self._write(event)
        return event.event_id

    def log_finding(
        self,
        agent_name: str,
        finding_id: str,
        description: str,
        confidence: str,
        evidence_links: list[str],
        ioc_type: str = "",
        ioc_value: str = "",
    ) -> str:
        event = FindingEvent(
            timestamp=self._now(),
            agent_name=agent_name,
            finding_id=finding_id,
            description=description,
            confidence=confidence,
            evidence_links=evidence_links,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
        )
        self._write(event)
        return event.event_id

    def log_verification(
        self,
        verifier_agent: str,
        finding_id: str,
        verdict: str,
        counter_evidence: list[str] | None = None,
        corroboration: list[str] | None = None,
        rounds_taken: int = 1,
    ) -> str:
        event = VerificationEvent(
            timestamp=self._now(),
            verifier_agent=verifier_agent,
            finding_id=finding_id,
            verdict=verdict,
            counter_evidence=counter_evidence or [],
            corroboration=corroboration or [],
            rounds_taken=rounds_taken,
        )
        self._write(event)
        return event.event_id

    def log_self_correction(
        self,
        finding_id: str,
        correction_reason: str,
        previous_confidence: str,
        new_confidence: str,
        verdict: str,
        rounds_taken: int = 1,
    ) -> str:
        event = SelfCorrectionEvent(
            timestamp=self._now(),
            finding_id=finding_id,
            correction_reason=correction_reason,
            previous_confidence=previous_confidence,
            new_confidence=new_confidence,
            verdict=verdict,
            rounds_taken=rounds_taken,
        )
        self._write(event)
        return event.event_id

    def log_hypothesis(
        self,
        hypothesis_id: str,
        action: str,
        description: str,
        evidence_summary: str = "",
    ) -> str:
        event = HypothesisEvent(
            timestamp=self._now(),
            hypothesis_id=hypothesis_id,
            action=action,
            description=description,
            evidence_summary=evidence_summary,
        )
        self._write(event)
        return event.event_id

    def log_orchestrator_plan(
        self,
        investigation_round: int,
        hypotheses_active: list[str],
        sub_agents_dispatched: list[str],
        focus_areas: list[str],
    ) -> str:
        event = OrchestratorPlanEvent(
            timestamp=self._now(),
            investigation_round=investigation_round,
            hypotheses_active=hypotheses_active,
            sub_agents_dispatched=sub_agents_dispatched,
            focus_areas=focus_areas,
        )
        self._write(event)
        return event.event_id

    @property
    def event_count(self) -> int:
        return len(self._events)

    def get_events(self, event_type: Optional[str] = None) -> list[dict[str, Any]]:
        if event_type:
            return [e for e in self._events if e["event_type"] == event_type]
        return list(self._events)
