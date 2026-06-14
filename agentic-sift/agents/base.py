"""Base classes for forensic sub-agents and verifier agents.

Sub-agents exist to prevent context rot: each agent holds only its
relevant tools and output, not the full tool catalogue. Each agent gets a
focused task, a tool list narrowed by the deterministic catalogue gates,
and returns a concise summary. The predefined domains provide forensic
expertise via system prompts.

Verifier agents challenge findings by seeking counter-evidence.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agents.claude import call_claude_json
from agents.domains import AgentDomain
from tools.advisor import ToolAdvisor

if TYPE_CHECKING:
    from audit.logger import AuditLogger
    from executor.runner import Executor
    from progress.tracker import ProgressTracker


# Standard forensic-report items (host/network identity, accounts, config-file
# contents) are atomic FACTS, not hypothesis conclusions — so a hypothesis-driven
# agent tends to treat them as background and summarize them away. This directive,
# injected into both the plan and interpret prompts, makes them first-class
# findings regardless of the hypothesis. (Measured on NIST-HACKING: the host IP,
# *.ini contents, and email addresses were captured by tools but emitted in zero
# of 99 findings.)
_IDENTITY_FINDINGS_DIRECTIVE = (
    "STANDARD SYSTEM-IDENTITY & ACCOUNT FACTS — emit each as its OWN finding, even "
    "when it is background to your hypothesis (these are required items in any "
    "forensic report; do not summarize them away as context):\n"
    "- Host network identity: the IP address (ioc_type=ip), the MAC address (put "
    "it in the description), DHCP server, and hostname.\n"
    "- User accounts and usernames/handles, and email addresses (ioc_type=domain "
    "for an email address or domain).\n"
    "- When you identify a configuration or application-data file (e.g. a *.ini, a "
    "mailbox, or an app config), PARSE its contents and emit the specific facts "
    "inside it (accounts, IP/server addresses, install paths) as findings — do NOT "
    "merely report that the file exists."
)


@dataclass
class Finding:
    """A forensic finding produced by a sub-agent."""

    finding_id: str
    description: str
    confidence: str  # confirmed, inferred, possible
    evidence_links: list[str] = field(default_factory=list)
    ioc_type: str = ""
    ioc_value: str = ""
    agent_name: str = ""
    hypothesis_id: str = ""
    timestamp: str = ""
    artifact_type: str = ""
    verified: bool = False
    verification_verdict: str = ""

    @classmethod
    def new(
        cls,
        description: str,
        confidence: str,
        evidence_links: list[str],
        agent_name: str = "",
        ioc_type: str = "",
        ioc_value: str = "",
        timestamp: str = "",
        artifact_type: str = "",
    ) -> "Finding":
        return cls(
            finding_id=f"F-{uuid.uuid4().hex[:8]}",
            description=description,
            confidence=confidence,
            evidence_links=evidence_links,
            agent_name=agent_name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            timestamp=timestamp,
            artifact_type=artifact_type,
        )


@dataclass
class AgentResult:
    """Result returned by a sub-agent to the orchestrator."""

    agent_name: str
    domain: str
    findings: list[Finding] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    execution_outputs: list[dict] = field(default_factory=list)
    summary: str = ""
    errors: list[str] = field(default_factory=list)
    # Evidence links the sub-agent claimed that had no backing execution — a
    # hallucination signal (see reconcile_evidence_links).
    hallucinated_links: list[str] = field(default_factory=list)
    # Claims dropped because no successful (exit 0) execution backed them, plus
    # tool/environment limitations — surfaced in the report's Limitations section
    # rather than presented as findings.
    limitations: list[str] = field(default_factory=list)


def reconcile_evidence_links(
    claimed: list[str], real_ids: list[str]
) -> tuple[list[str], list[str]]:
    """Split claimed evidence links into (backed, unbacked).

    A finding may only cite execution IDs that actually ran. ``backed`` keeps the
    claimed IDs that appear in ``real_ids`` (in the order claimed); ``unbacked``
    collects the rest — links the model invented, which are a hallucination
    signal rather than real evidence.
    """
    real = set(real_ids)
    backed = [c for c in claimed if c in real]
    unbacked = [c for c in claimed if c not in real]
    return backed, unbacked


def _successful_execution_ids(execution_outputs: list[dict]) -> set[str]:
    """Execution IDs whose tool ran to completion (exit code 0).

    A finding may only cite an execution that actually produced output. Rejected
    commands never reach ``execution_outputs`` (skipped before append), and
    failed commands are appended with a non-zero ``exit_code``; filtering on
    ``exit_code == 0`` is what separates evidence-backed claims from failures
    narrated as findings. Local creation-time check over the per-agent output
    dicts — distinct from the after-the-fact audit scoring in accuracy code.
    """
    return {
        o["execution_id"]
        for o in execution_outputs
        if o.get("exit_code", -1) == 0 and "execution_id" in o
    }


@dataclass
class ChallengeResult:
    """Outcome of a single verifier challenge round.

    Produced by ``VerifierAgent.challenge_once``; the multi-round loop in
    ``verification.multi_round`` consumes these to decide when a verdict is
    final. No verification verdict is logged at this level (the caller logs
    once the loop terminates), though tool executions are still audited.
    """

    verdict: str  # confirmed | downgraded | refuted
    supports_claim: bool
    analysis: str = ""
    alternative_explanation: str = ""
    counter_evidence: list[str] = field(default_factory=list)
    counter_results: list[dict] = field(default_factory=list)
    llm_failed: bool = False


class DomainAgent:
    """A forensic sub-agent with domain expertise and dynamically-assigned tools.

    The domain provides forensic expertise (system prompt).
    The tools are filtered by categories assigned at dispatch time.

    Usage:
        agent = DomainAgent(domain, executor, audit, progress, tools)
        result = agent.investigate(task, evidence_path, hypothesis)
    """

    # Closed-loop (ReAct) cap: the maximum number of plan→execute turns before a
    # final interpretation. Each turn is one `claude --print` call (the dominant
    # per-agent latency), so keep this tight while leaving room to CHAIN commands
    # (find an inode -> extract it -> parse it) using the previous step's output.
    # 4 covers the common chains (e.g. locate hive -> RegRipper -> read key) in
    # 2-3 steps with one to spare; the no-progress guard stops even sooner when a
    # turn adds nothing new.
    MAX_STEPS = 4
    # No-progress guard: stop early if this many CONSECUTIVE turns issue only
    # commands already run (the model is repeating itself and learning nothing
    # new), rather than burning the full MAX_STEPS budget.
    MAX_NO_PROGRESS_STEPS = 2

    def __init__(
        self,
        domain: AgentDomain,
        executor: "Executor",
        audit_logger: "AuditLogger",
        progress_tracker: "ProgressTracker",
        tools: list[dict],
        advisor: "ToolAdvisor | None" = None,
    ) -> None:
        self.domain = domain
        self.executor = executor
        self.audit = audit_logger
        self.progress = progress_tracker
        self.tools = tools
        # The orchestrator shares one advisor per investigation so the
        # compatibility matrix accumulates across sub-agents; default to a
        # private one so standalone DomainAgent construction still adapts.
        self.advisor = advisor or ToolAdvisor()
        self.name = f"{domain.name}_agent"

    def investigate(
        self,
        task: str,
        evidence_path: str,
        hypothesis: str = "",
        mount_roots: list[str] | None = None,
        primary_offset: int | None = None,
    ) -> AgentResult:
        """Run an investigation for this sub-agent.

        1. Build prompt with domain expertise, tools, and task
        2. Ask Claude to propose tool commands (LLM call #1)
        3. Validate and execute each command via the executor
        4. Feed results back to Claude for interpretation (LLM call #2)
        5. Return structured findings

        ``mount_roots`` are read-only filesystem paths where the evidence image
        is mounted, when it is a mountable disk image. When present, the agent is
        told to read live files directly under those paths with ordinary tools,
        and to fall back to the raw image only for deleted/inode-addressed files.
        Empty (the default) means there is no mounted filesystem — the agent
        works against the raw ``evidence_path`` alone (e.g. memory, captures).
        """
        result = AgentResult(agent_name=self.name, domain=self.domain.name)

        lessons = self.progress.get_lessons()
        lessons_text = ""
        if lessons:
            lessons_text = "\n\nLessons from prior failures (avoid these):\n"
            lessons_text += "\n".join(f"- {lesson}" for lesson in lessons)

        self.audit.log_agent_message(
            "orchestrator",
            self.name,
            "task",
            task,
        )

        # Closed-loop (ReAct): plan the next command(s), execute, FEED THE REAL
        # OUTPUT BACK into the next planning turn, and repeat — so a value found
        # in one step (an inode, a path) is substituted into the next command
        # instead of a placeholder. The model returns "findings" (and no
        # commands) to finish; otherwise we stop at MAX_STEPS and interpret what
        # we have. observations accumulates the executed-command outputs that are
        # echoed into each subsequent prompt.
        execution_outputs: list[dict] = []
        observations: list[dict] = []
        findings_data: list[dict] | None = None
        seen_cmds: set[tuple] = set()
        no_progress = 0

        # The stable preamble (domain prompt + tool menu + schema + rules) is
        # identical every turn, so build it once and send it as a cached system
        # block; only the dynamic tail (with the growing observations) changes.
        preamble = self._stable_preamble()
        # MAX_STEPS is env-overridable (read here, not at import) so the CLI's
        # --fast mode can shorten the per-dispatch plan→execute loop.
        try:
            max_steps = int(os.environ.get("AGENTIC_SIFT_MAX_STEPS") or self.MAX_STEPS)
        except ValueError:
            max_steps = self.MAX_STEPS
        for step in range(max_steps):
            response = call_claude_json(
                self._dynamic_tail(
                    task,
                    evidence_path,
                    hypothesis,
                    lessons_text,
                    mount_roots,
                    primary_offset,
                    observations,
                ),
                system_prompt=preamble,
            )
            if not response:
                # A failed FIRST turn yields no plan at all; later transient
                # failures just end the loop with whatever was gathered.
                if step == 0:
                    result.errors.append("Failed to get execution plan from Claude")
                break

            commands = response.get("commands") or []
            issued_new_cmd = False
            for cmd in commands:
                sig = (cmd.get("tool_path", ""), tuple(cmd.get("args") or []))
                if sig not in seen_cmds:
                    issued_new_cmd = True
                seen_cmds.add(sig)
                before = len(execution_outputs)
                self._run_command_with_fallback(
                    cmd, task, result, execution_outputs
                )
                # Echo only the newly-produced output(s) back into the next turn.
                observations.extend(execution_outputs[before:])

            # Terminate on a NON-EMPTY findings list. The model echoes an empty
            # "findings": [] alongside its commands every turn (it is in the
            # response schema), which must NOT be read as "done" — only real
            # findings end the loop.
            findings_payload = response.get("findings")
            if findings_payload:
                findings_data = findings_payload
                break
            if not commands:
                # Nothing to run and no findings: the agent is done (or had
                # nothing to do).
                break

            # No-progress guard: a turn that only re-issues commands already run
            # advances nothing. After MAX_NO_PROGRESS_STEPS such turns, stop and
            # interpret what we have rather than spinning up to the MAX_STEPS cap.
            if issued_new_cmd:
                no_progress = 0
            else:
                no_progress += 1
                if no_progress >= self.MAX_NO_PROGRESS_STEPS:
                    result.errors.append(
                        "Stopped early: no new commands (no-progress guard)"
                    )
                    break

        # Surface the raw tool outputs so the orchestrator can hand the verifier
        # the actual evidence behind each finding (keyed by execution_id).
        result.execution_outputs = execution_outputs

        # If the loop ended without the model returning findings (e.g. it hit the
        # step cap), interpret the accumulated outputs in one final call.
        if findings_data is None and execution_outputs:
            findings_data = self._interpret_results(
                task, hypothesis, execution_outputs
            )

        if findings_data:
            self._build_findings_from_data(findings_data, execution_outputs, result)

        result.summary = (
            f"Ran {len(execution_outputs)} tools, found {len(result.findings)} findings"
        )
        self.audit.log_agent_message(
            self.name,
            "orchestrator",
            "finding",
            result.summary,
        )

        return result

    def _build_findings_from_data(
        self,
        findings: list[dict],
        execution_outputs: list[dict],
        result: AgentResult,
    ) -> None:
        """Turn interpreted finding dicts into Findings, dropping unbacked claims.

        Keeps only evidence links backed by a SUCCESSFUL (exit 0) execution;
        records links citing an execution that never ran as hallucinations, and
        drops findings with no successful backing to Limitations. (Unchanged
        reconciliation logic, factored out of the closed loop above.)
        """
        successful_ids = _successful_execution_ids(execution_outputs)
        # Every execution that actually ran, successful or not — used to tell an
        # invented ID (model hallucination) apart from the ID of a real execution
        # that merely failed (unsuccessful evidence).
        all_ids = {
            o["execution_id"] for o in execution_outputs if "execution_id" in o
        }
        for f_data in findings:
            backed, unbacked = reconcile_evidence_links(
                f_data.get("evidence_links", []), list(successful_ids)
            )
            invented = [link for link in unbacked if link not in all_ids]
            result.hallucinated_links.extend(invented)
            if not backed:
                desc = (f_data.get("description") or "").strip() or "(no description)"
                result.limitations.append(
                    f"Unbacked claim dropped (no successful evidence): {desc}"
                )
                continue
            finding = Finding.new(
                description=f_data.get("description", ""),
                confidence=f_data.get("confidence", "possible"),
                evidence_links=backed,
                agent_name=self.name,
                ioc_type=f_data.get("ioc_type", ""),
                ioc_value=f_data.get("ioc_value", ""),
                timestamp=f_data.get("timestamp", ""),
                artifact_type=f_data.get("artifact_type", ""),
            )
            result.findings.append(finding)
            self.audit.log_finding(
                agent_name=self.name,
                finding_id=finding.finding_id,
                description=finding.description,
                confidence=finding.confidence,
                evidence_links=finding.evidence_links,
                ioc_type=finding.ioc_type,
                ioc_value=finding.ioc_value,
            )

    def _run_command_with_fallback(
        self,
        cmd: dict,
        task: str,
        result: AgentResult,
        execution_outputs: list[dict],
    ) -> None:
        """Run one planned command, recovering via fallbacks when it fails.

        Each attempt is gated through the advisor: known-bad tools are skipped,
        pre-validation catches tools that cannot run on this host/evidence (e.g.
        a .NET parser on Linux, or a parser handed a raw image), and on
        rejection or non-zero exit the advisor routes to the next working
        alternative, bounded by ToolAdvisor.MAX_FALLBACKS. Fallbacks are
        like-for-like, so the original args are reused verbatim — no extra LLM
        call. Only the successful (or final) attempt's output is forwarded to
        interpretation; every attempt is recorded to the advisor and progress
        tracker.
        """
        tool_path = cmd.get("tool_path", "")
        args = cmd.get("args", [])
        expected = cmd.get("expected_outcome", "")

        self.audit.log_agent_decision(
            agent_name=self.name,
            task=task,
            tools_considered=cmd.get("alternatives_considered", []),
            tool_chosen=tool_path,
            reasoning=cmd.get("reasoning", ""),
            expected_outcome=expected,
        )

        final_output: dict | None = None
        for _ in range(self.advisor.MAX_FALLBACKS + 1):
            if not tool_path:
                break
            tool_dict = self._tool_for_path(tool_path)
            tool_name = self._tool_label(tool_dict, tool_path)

            # Correct argument-level problems a like-for-like fallback cannot fix
            # (invalid flags, missing writable output dirs) before spending a
            # slot — otherwise every alternative reuses the same args and fails
            # identically, turning a fixable invocation into a hard failure.
            args = self.advisor.normalize_args(tool_dict, tool_path, args)

            # Gate 1: skip tools already known bad on this image.
            if self.advisor.is_known_bad(tool_path):
                result.errors.append(f"Skipped known-bad tool: {tool_name}")
                tool_path = self._route_fallback(
                    tool_path,
                    tool_dict,
                    args,
                    "already failed on this image",
                    record=False,
                )
                continue

            # Gate 2: pre-validate before spending an execution slot.
            reason = self.advisor.blocking_reason(tool_dict, tool_path, args)
            if reason:
                self.advisor.record_result(tool_path, success=False, error=reason)
                result.errors.append(f"Pre-validation failed: {tool_name} — {reason}")
                tool_path = self._route_fallback(tool_path, tool_dict, args, reason)
                continue

            # Gate 3: execute. Run from the writable scratch directory so a tool
            # that writes a relative output path lands in an allowlisted location
            # rather than an un-allowlisted /tmp (which the executor rejects).
            exec_result = self.executor.run(
                tool_path=tool_path, args=args, cwd=self._scratch_dir() or "/tmp"
            )
            self.audit.log_tool_execution_from_result(exec_result)
            result.tools_used.append(tool_path)

            if exec_result.rejected:
                self.advisor.record_result(
                    tool_path, success=False, error=exec_result.rejection_reason
                )
                result.errors.append(
                    f"Rejected: {tool_path} — {exec_result.rejection_reason}"
                )
                tool_path = self._route_fallback(
                    tool_path,
                    tool_dict,
                    args,
                    f"rejected ({exec_result.rejection_reason})",
                )
                continue

            if exec_result.exit_code != 0:
                self.advisor.record_result(
                    tool_path, success=False, error=exec_result.stderr[:200]
                )
                result.errors.append(
                    f"Failed: {tool_path} exit={exec_result.exit_code}"
                )
                final_output = self._execution_output(
                    tool_path, args, expected, exec_result
                )
                tool_path = self._route_fallback(
                    tool_path,
                    tool_dict,
                    args,
                    f"exit code {exec_result.exit_code}: {exec_result.stderr[:200]}",
                )
                continue

            # Success: record it, forward the output, and stop the chain.
            self.advisor.record_result(tool_path, success=True)
            execution_outputs.append(
                self._execution_output(tool_path, args, expected, exec_result)
            )
            return

        # Chain exhausted without success: forward only the final attempt's
        # output (if a tool actually ran) so the interpreter sees the failure
        # context — fixes the latent bug where every attempt was appended.
        if final_output is not None:
            execution_outputs.append(final_output)

    def _route_fallback(
        self,
        tool_path: str,
        tool_dict: dict | None,
        args: list,
        failure: str,
        record: bool = True,
    ) -> str:
        """Pick the next working alternative and record the failure + lesson.

        Returns the alternative's path to retry, or "" when none remains.
        ``record=False`` skips the progress entry for tools already recorded as
        failed (the known-bad skip path).
        """
        alt = self.advisor.suggest_fallback(tool_path, tool_dict, self.tools)
        tool_name = self._tool_label(tool_dict, tool_path)
        if record:
            if alt is not None:
                alt_name = self._tool_label(alt, alt.get("path", ""))
                lesson = f"{tool_name} failed ({failure}) — falling back to {alt_name}"
            else:
                lesson = (
                    f"{tool_name} failed ({failure}) — no working alternative available"
                )
            self.progress.record_failure(
                tool=tool_path, args=args, failure=failure, lesson=lesson
            )
        return alt["path"] if alt is not None else ""

    def _tool_for_path(self, tool_path: str) -> dict | None:
        """Find this agent's tool dict for a path (matches path or symlink)."""
        for tool in self.tools:
            if tool.get("path") == tool_path or tool.get("symlink") == tool_path:
                return tool
        return None

    @staticmethod
    def _tool_label(tool_dict: dict | None, tool_path: str) -> str:
        if tool_dict and tool_dict.get("name"):
            return tool_dict["name"]
        return os.path.basename(tool_path.rstrip("/")) or tool_path

    @staticmethod
    def _execution_output(
        tool_path: str, args: list, expected: str, exec_result
    ) -> dict:
        return {
            "tool": tool_path,
            "args": args,
            "exit_code": exec_result.exit_code,
            "stdout": exec_result.stdout[:5000],
            "stderr": exec_result.stderr[:1000],
            "expected": expected,
            "execution_id": exec_result.execution_id,
        }

    def _scratch_dir(self) -> str | None:
        """The executor's writable scratch directory, or None if it has none."""
        return getattr(self.executor, "scratch_dir", None)

    def _stable_preamble(self) -> list[dict]:
        """System content blocks that are identical on every turn of this
        sub-agent (same evidence), returned as Anthropic content blocks with a
        cache breakpoint on the last one.

        The domain expertise, the tool menu, the response schema and the rules
        do not change between the plan turns of one dispatch, so they form a
        single cached region (``cache_control`` on the final block caches
        everything before it). The per-turn context (task / hypothesis / evidence
        / accumulated observations / lessons) is the user message — see
        ``_dynamic_tail`` — so it stays out of the cache and the (now
        un-keyword-gated, larger) tool menu is read from cache on every turn but
        the first.
        """
        return [
            {"type": "text", "text": self.domain.system_prompt},
            {
                "type": "text",
                "text": self._plan_instructions(),
                "cache_control": {"type": "ephemeral"},
            },
        ]

    def _plan_instructions(self) -> str:
        """The stable instruction body: tool menu + response schema + rules.

        Stable across a sub-agent's turns, so it lives in the cached preamble
        (and is reused verbatim by ``_build_plan_prompt`` for direct callers).
        """
        tool_list = self._format_tools()
        return f"""Available tools (use ONLY these — the executor rejects anything else):
{tool_list}

You are in an iterative loop. Each turn, EITHER issue the next tool command(s) to
run, OR — once you have enough evidence — return your "findings" to finish.

Respond with:
{{
  "commands": [
    {{
      "tool_path": "/path/to/tool",
      "args": ["arg1", "arg2"],
      "reasoning": "why this tool",
      "expected_outcome": "what I expect if the hypothesis is correct",
      "alternatives_considered": ["/path/to/alt"]
    }}
  ],
  "findings": [
    {{
      "description": "evidence-backed conclusion about the SUBJECT system",
      "confidence": "confirmed|inferred|possible",
      "evidence_links": ["execution_id"],
      "ioc_type": "file_path|ip|domain|hash|registry_key|",
      "ioc_value": "the IOC value or empty",
      "timestamp": "event time ISO-8601 UTC, or empty",
      "artifact_type": "registry|prefetch|evtx|mft|network|filesystem|... or empty"
    }}
  ]
}}

Rules:
- Use exact tool paths from the list above.
- CRITICAL: substitute the REAL values from "Results so far" into your next
  command (e.g. an inode number or path you just discovered). NEVER emit a
  placeholder like <inode> or <SOFTWARE_hive_inode> — a literal placeholder is
  passed verbatim to the tool and fails.
- Issue at most 3 commands per turn; prefer ONE focused command when chaining
  (find -> extract -> parse), so you can use each result in the next step.
- Return "findings" with NO commands as soon as the hypothesis is answered — do
  not keep running tools once you have the evidence.
- A finding MUST cite an evidence_link whose command succeeded (exit 0). Tool
  failures / environment limitations are NOT findings — omit them.

{_IDENTITY_FINDINGS_DIRECTIVE}"""

    def _dynamic_tail(
        self,
        task: str,
        evidence_path: str,
        hypothesis: str,
        lessons_text: str,
        mount_roots: list[str] | None = None,
        primary_offset: int | None = None,
        observations: list[dict] | None = None,
    ) -> str:
        """The per-turn user message: task, hypothesis, evidence, observations.

        Everything here changes turn-to-turn (observations grow) or per-dispatch,
        so it is sent uncached as the user message while ``_stable_preamble``
        carries the cached tool menu + schema + rules.
        """
        evidence_block = self._evidence_block(
            evidence_path, mount_roots, self._scratch_dir(), primary_offset
        )
        observations_block = self._observations_block(observations)
        return f"""Investigate step by step. Respond with ONLY valid JSON.

Task: {task}
Hypothesis: {hypothesis}

{evidence_block}
{observations_block}{lessons_text}"""

    def _build_plan_prompt(
        self,
        task: str,
        evidence_path: str,
        hypothesis: str,
        lessons_text: str,
        mount_roots: list[str] | None = None,
        primary_offset: int | None = None,
        observations: list[dict] | None = None,
    ) -> str:
        """Full single-string plan prompt (dynamic tail + stable instructions).

        Retained as the combined form for direct callers/tests; ``investigate``
        instead sends the two halves separately so the stable half is cached.
        """
        return (
            self._dynamic_tail(
                task,
                evidence_path,
                hypothesis,
                lessons_text,
                mount_roots,
                primary_offset,
                observations,
            )
            + "\n\n"
            + self._plan_instructions()
        )

    @staticmethod
    def _observations_block(observations: list[dict] | None) -> str:
        """Echo prior command outputs so the next turn can use their real values.

        Empty on the first turn (and for direct prompt-content tests), so the
        opening prompt is unchanged from a single-shot plan.
        """
        if not observations:
            return ""
        lines = [
            "\nResults so far (use these REAL values in your next command, and "
            "cite the execution_id in a finding's evidence_links):"
        ]
        for o in observations:
            args = " ".join(o.get("args", []))
            code = o.get("exit_code")
            stdout = (o.get("stdout") or "")[:1500]
            stderr = (o.get("stderr") or "")[:300]
            eid = o.get("execution_id", "")
            lines.append(f"\n[execution_id: {eid}] $ {o.get('tool', '')} {args}  (exit={code})")
            if stdout:
                lines.append(stdout)
            if stderr and code != 0:
                lines.append(f"[stderr] {stderr}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _evidence_block(
        evidence_path: str,
        mount_roots: list[str] | None,
        scratch_dir: str | None = None,
        primary_offset: int | None = None,
    ) -> str:
        """Describe how to reach the evidence in the plan prompt.

        When the image is mounted, the agent is steered to read live files
        directly from the read-only mount with ordinary tools, and to use the
        raw image only for deleted or inode-addressed files that are not present
        in the mounted tree. With nothing mounted, the agent is given just the
        raw path (e.g. a memory dump or packet capture analyzed whole). When a
        scratch directory is configured, the agent is also told where tool output
        may be written (the evidence itself is read-only and allowlist-guarded).
        """
        if mount_roots:
            roots = "\n".join(f"  - {r}" for r in mount_roots)
            block = (
                "The evidence filesystem is MOUNTED READ-ONLY at:\n"
                f"{roots}\n"
                "Read live files directly under these paths with ordinary tools "
                "and file parsers — no offset arithmetic or per-file extraction "
                "is needed for files that exist on disk.\n"
                f"The raw image is also available at: {evidence_path}\n"
                "Use the raw image only to recover DELETED or inode-addressed "
                "files (e.g. with Sleuth Kit fls/icat) that are not present in "
                "the mounted tree."
            )
        else:
            block = f"Evidence: {evidence_path}"
        return (
            block
            + DomainAgent._offset_block(primary_offset)
            + DomainAgent._scratch_block(scratch_dir)
        )

    @staticmethod
    def _offset_block(primary_offset: int | None) -> str:
        """Tell the agent the partition offset for raw-image Sleuth Kit tools.

        Sleuth Kit tools that read a filesystem inside a raw image (fls, fsstat,
        icat, tsk_recover) need the partition's start sector via -o. The
        orchestrator already determined it; passing it stops the agent guessing a
        wrong value (e.g. 2048 on a single-volume image, which fails "Cannot
        determine file system type"). Empty when the offset is unknown.
        """
        if primary_offset is None:
            return ""
        return (
            f"\n\nThe filesystem to analyze starts at SECTOR OFFSET "
            f"{primary_offset}. For Sleuth Kit tools that take -o (fls, fsstat, "
            f"icat, tsk_recover), pass exactly `-o {primary_offset}` — do not "
            f"guess a different offset. (Offset 0 = a single-volume image with "
            f"no partition table.)"
        )

    @staticmethod
    def _scratch_block(scratch_dir: str | None) -> str:
        """Tell the agent where tool OUTPUT may be written.

        The evidence is read-only and every path a tool touches is checked
        against an allowlist, so output files (super-timelines, carved files,
        extracted hives, redirected stdout) must be written to this one writable
        scratch directory. Output written anywhere else — notably /tmp — is
        rejected by the executor before the tool runs. Empty when no scratch
        directory is configured.
        """
        if not scratch_dir:
            return ""
        return (
            "\n\nWritable scratch directory — write ALL tool output here "
            "(super-timelines, carved files, extracted hives, redirected "
            f"stdout):\n  {scratch_dir}\n"
            "Do NOT write tool output anywhere else: a path that is neither the "
            "evidence nor this scratch directory is rejected before the tool runs."
        )

    def _format_tools(self) -> str:
        lines = []
        for t in self.tools:
            name = t.get("display_name") or t.get("name", "")
            lines.append(
                f"- {name} (`{t.get('path', '')}`): {t.get('description', '')}"
            )
            for ex in (t.get("usage_examples") or [])[:2]:
                lines.append(f"    Example: {self._format_example(ex)}")
        return "\n".join(lines)

    @staticmethod
    def _format_example(ex) -> str:
        """Render one usage example. Tolerates both shapes a catalog may carry:
        a plain command string (locally-built catalogs) or a
        ``{"command", "title"}`` dict (older/seed catalogs)."""
        if isinstance(ex, dict):
            cmd = ex.get("command", "")
            title = ex.get("title", "")
            return f"`{cmd}` — {title}" if title else f"`{cmd}`"
        return f"`{ex}`"

    def _build_interpret_prompt(
        self,
        task: str,
        hypothesis: str,
        execution_outputs: list[dict],
    ) -> str:
        outputs_text = json.dumps(execution_outputs, indent=2)

        return f"""Analyze these forensic tool outputs. Respond with ONLY valid JSON.

Task: {task}
Hypothesis: {hypothesis}

Tool outputs:
{outputs_text}

For each finding, compare expected vs actual.

Respond with:
{{
  "findings": [
    {{
      "description": "what was found",
      "confidence": "confirmed|inferred|possible",
      "evidence_links": ["execution_id_1"],
      "expected_vs_actual": "expected X, found Y",
      "ioc_type": "file_path|ip|domain|hash|registry_key|",
      "ioc_value": "the IOC value or empty",
      "timestamp": "event time from the output in ISO-8601 UTC, or empty",
      "artifact_type": "the artifact this came from (e.g. registry, prefetch, evtx, mft, network), or empty"
    }}
  ]
}}

Set "timestamp" to the time the event itself occurred (parsed from the tool
output), not the time of analysis; leave it empty if the output has no event time.
Set "artifact_type" to the kind of artifact the finding came from. These two
fields are what lets findings be placed on a single cross-tool timeline.

RULES FOR FINDINGS:
- A finding is an evidence-backed forensic conclusion about the SUBJECT system.
- Do NOT report a tool failure, a non-zero exit, or a failed command as a finding.
- Do NOT report tool/environment limitations (e.g. "strings returned noise",
  "ClamAV signature db is stale", "tool X not installed") as a finding.
  Put those under "limitations".
- Every finding MUST cite an evidence_link that produced real output (exit 0).

{_IDENTITY_FINDINGS_DIRECTIVE}

CRITICAL: Only report what the tool output actually shows."""

    def _interpret_results(
        self,
        task: str,
        hypothesis: str,
        execution_outputs: list[dict],
    ) -> list[dict]:
        prompt = self._build_interpret_prompt(task, hypothesis, execution_outputs)
        result = call_claude_json(prompt, system_prompt=self.domain.system_prompt)
        if result and "findings" in result:
            return result["findings"]
        return []


class VerifierAgent:
    """Challenges findings by seeking counter-evidence.

    The verifier re-reads raw tool output, runs additional tools to
    look for contradictions, and proposes alternative explanations.
    ``challenge_once`` runs a single round; ``verification.multi_round``
    drives the iterative (up to MAX_ROUNDS) challenge/response loop.
    """

    MAX_ROUNDS = 3

    def __init__(
        self,
        executor: "Executor",
        audit_logger: "AuditLogger",
        all_tools: list[dict],
    ) -> None:
        self.executor = executor
        self.audit = audit_logger
        self.all_tools = all_tools
        self.name = "verifier"

    def verify(
        self,
        finding: Finding,
        original_outputs: list[dict],
        evidence_path: str,
    ) -> str:
        """Single-round challenge (backward-compatible entry point).

        Runs one challenge round and logs a single verification event. The
        iterative loop lives in ``verification.multi_round.MultiRoundVerifier``.
        """
        result = self.challenge_once(finding, original_outputs, evidence_path)
        self.audit.log_verification(
            self.name,
            finding.finding_id,
            result.verdict,
            counter_evidence=result.counter_evidence,
            rounds_taken=1,
        )
        return result.verdict

    def challenge_once(
        self,
        finding: Finding,
        original_outputs: list[dict],
        evidence_path: str,
        prior_context: str = "",
    ) -> ChallengeResult:
        """Run ONE challenge round and return a structured result.

        Does not log a verification verdict (the multi-round caller logs once
        the loop terminates), but tool executions are still audited.
        ``prior_context`` carries a summary of earlier rounds so the LLM can
        refine its challenge instead of repeating it.
        """
        verification = call_claude_json(
            self._challenge_tail(
                finding, original_outputs, evidence_path, prior_context
            ),
            system_prompt=self._verifier_preamble(),
        )
        if not verification:
            return ChallengeResult(
                verdict="confirmed", supports_claim=True, llm_failed=True
            )

        if not verification.get("output_supports_claim", True):
            analysis = verification.get("output_analysis", "")
            return ChallengeResult(
                verdict="refuted",
                supports_claim=False,
                analysis=analysis,
                counter_evidence=[analysis] if analysis else [],
            )

        counter_results = self._run_counter_commands(
            verification.get("counter_evidence_commands", [])
        )
        if counter_results:
            verdict = self._render_verdict(finding, counter_results)
        else:
            verdict = "confirmed"

        return ChallengeResult(
            verdict=verdict,
            supports_claim=True,
            analysis=verification.get("output_analysis", ""),
            alternative_explanation=verification.get("alternative_explanation", ""),
            counter_evidence=[str(cr) for cr in counter_results],
            counter_results=counter_results,
        )

    def _run_counter_commands(self, counter_commands: list[dict]) -> list[dict]:
        """Execute up to 3 counter-evidence commands; return non-rejected results."""
        counter_results: list[dict] = []
        for cmd in counter_commands[:3]:
            exec_result = self.executor.run(
                tool_path=cmd.get("tool_path", ""),
                args=cmd.get("args", []),
            )
            self.audit.log_tool_execution_from_result(exec_result)
            if not exec_result.rejected:
                counter_results.append(
                    {
                        "tool": cmd.get("tool_path", ""),
                        "looking_for": cmd.get("looking_for", ""),
                        "stdout": exec_result.stdout[:3000],
                        "exit_code": exec_result.exit_code,
                    }
                )
        return counter_results

    def _verifier_preamble(self) -> list[dict]:
        """Cached system blocks for the verifier: framing + tool menu + schema.

        The counter-evidence tool menu and the challenge instructions are the
        same for every finding in a run, so they sit in one cached region rather
        than being re-sent per finding in the user turn. The ``[:50]`` size guard
        is kept (out of scope to retune); the cache makes the re-send cheap.
        """
        tool_list = "\n".join(
            f"- {t.get('display_name', t['name'])} (`{t['path']}`): {t['description']}"
            for t in self.all_tools[:50]
        )
        text = f"""You are a forensic evidence verifier. Your job is to CHALLENGE findings.

Available tools for counter-evidence:
{tool_list}

For the finding in the user message, address:
1. Does the original output actually support the claim?
2. What tools would find COUNTER-EVIDENCE disproving this?
3. What's a benign alternative explanation?

Respond with ONLY valid JSON:
{{
  "output_supports_claim": true/false,
  "output_analysis": "how output does/doesn't support the claim",
  "counter_evidence_commands": [
    {{
      "tool_path": "/path/to/tool",
      "args": ["arg1"],
      "looking_for": "what would disprove the finding"
    }}
  ],
  "alternative_explanation": "benign explanation",
  "how_to_rule_out": "what would rule out the benign explanation"
}}"""
        return [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]

    def _challenge_tail(
        self,
        finding: Finding,
        original_outputs: list[dict],
        evidence_path: str,
        prior_context: str = "",
    ) -> str:
        """The per-finding user message: the finding, its outputs, prior rounds.

        Dynamic (changes per finding / per round), so it stays out of the cached
        verifier preamble.
        """
        prior = ""
        if prior_context:
            prior = (
                "\n\nEarlier challenge rounds (refine further, do not repeat):\n"
                + prior_context
            )
        outputs = (
            json.dumps(original_outputs, indent=2)
            if original_outputs
            else "Not available."
        )
        return f"""CHALLENGE this finding.

Finding: {finding.description}
Claimed confidence: {finding.confidence}
IOC: {finding.ioc_type}={finding.ioc_value}
Evidence: {evidence_path}
{prior}
Original tool outputs:
{outputs}"""

    def _build_challenge_prompt(
        self,
        finding: Finding,
        original_outputs: list[dict],
        evidence_path: str,
        prior_context: str = "",
    ) -> str:
        """Full single-string challenge prompt (tail + verifier instructions).

        Retained as the combined form for direct callers/tests; ``challenge_once``
        instead sends the two halves separately so the menu/schema is cached.
        """
        preamble = self._verifier_preamble()[0]["text"]
        return (
            self._challenge_tail(
                finding, original_outputs, evidence_path, prior_context
            )
            + "\n\n"
            + preamble
        )

    def _render_verdict(self, finding: Finding, counter_results: list[dict]) -> str:
        prompt = f"""Issue a verdict on this finding based on counter-evidence.

Finding: {finding.description}
Confidence: {finding.confidence}

Counter-evidence results:
{json.dumps(counter_results, indent=2)}

Respond with ONLY valid JSON:
{{
  "verdict": "confirmed|downgraded|refuted",
  "reasoning": "why"
}}"""

        VALID_VERDICTS = {"confirmed", "downgraded", "refuted"}
        result = call_claude_json(prompt)
        if result and result.get("verdict") in VALID_VERDICTS:
            return result["verdict"]
        return "confirmed"
