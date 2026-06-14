"""Hypothesis-driven forensic investigation orchestrator.

The orchestrator thinks like a senior analyst:
  1. Run initial triage to understand the evidence
  2. Form hypotheses based on triage results
  3. Dispatch specialized sub-agents to test hypotheses
  4. Collect findings and dispatch verifiers for high-value results
  5. Evaluate hypotheses — pivot if refuted
  6. Repeat until convergence or iteration limit
  7. Generate the final report
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Optional

from accuracy.baseline import load_baseline
from accuracy.scorer import score_report
from agents.base import AgentResult, Finding, DomainAgent, VerifierAgent
from agents.claude import call_claude_json, ClaudeError
from agents.domains import AGENT_DOMAINS, AgentDomain
from audit.logger import AuditLogger
from correlation.engine import CorrelationEngine
from correlation.semantic import correlate_semantically, SemanticCorrelationResult
from evidence.view import (
    close_evidence,
    EvidenceSpec,
    EvidenceView,
    open_evidence,
    TeardownResult,
)
from executor.runner import Executor
from progress.tracker import ProgressTracker
from report.generator import ReportGenerator
from tools.advisor import ToolAdvisor
from verification.confidence import recalibrate
from verification.corroboration import CorroborationIndex
from verification.dedup import dedupe_findings
from verification.multi_round import DEFAULT_MAX_ROUNDS, MultiRoundVerifier

from catalog.gates import gate_tools


logger = logging.getLogger(__name__)

# Max sub-agents dispatched concurrently within a round. Each sub-agent is
# dominated by serial `claude --print` calls (~95% of round wall-clock), so
# running the independent ones in parallel is the main latency win; the cap keeps
# concurrent claude/SSH load bounded so auth and the tool VM are not overwhelmed.
# Set to 10 so a typical round's hypothesis×domain work (≈8-10 items) runs in a
# SINGLE wave instead of two — measured ~10 min of round wall-clock was lost to a
# second wave at the old cap of 6. Kept well below the point where the model
# gateway began truncating output under high concurrency.
_MAX_PARALLEL_SUB_AGENTS = 10


def _int_env(name: str, default: int) -> int:
    """Read an int from the environment, falling back to ``default``.

    Speed/scale limits are env-overridable (read at USE time, not import time)
    so the CLI's ``--fast`` flag — which sets these vars at runtime — takes
    effect, and so an operator can dial thoroughness vs. speed per run without
    code changes. Defaults preserve the original behavior.
    """
    try:
        return int(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


def _bool_env(name: str) -> bool:
    """True iff env var ``name`` is set to a truthy token (1/true/yes/on)."""
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _is_high_value(finding) -> bool:
    """A finding worth the verification budget: it carries an IOC, or it is a
    confident conclusion. Low-signal/low-confidence findings are the ones the
    ``--fast`` / high-value-only mode accepts unverified to skip the long
    verification tail."""
    if getattr(finding, "ioc_value", ""):
        return True
    return getattr(finding, "confidence", "") in ("confirmed", "inferred")


# Bounds that keep the deepen/pivot loop converging instead of thrashing: a hard
# ceiling on how many hypotheses an investigation may hold, and a round after
# which no *new* hypotheses are formed (later rounds only resolve open ones).
MAX_HYPOTHESES = 8
NEW_HYPOTHESIS_CUTOFF_ROUND = 3

# Always-on system-characterization pass. Standard forensic-report identity facts
# (host, owner, OS, timezone, accounts, network identity) are atomic facts, not
# hypothesis conclusions, so a purely hypothesis-driven dispatch under-reports
# them (measured on NIST-HACKING: the host IP/MAC, *.ini contents, and email
# addresses were captured by tools but emitted in zero findings). This pass runs
# once per MOUNTABLE evidence item, independent of any hypothesis, with a fixed
# mission, so those facts are always emitted as findings and verified like any
# other.
_CHARACTERIZATION_ID = "characterization"
_CHARACTERIZATION_MISSION = (
    "Establish the IDENTITY of this system and its accounts, and emit EACH fact as "
    "its own finding. This is the standard 'system information' section of a "
    "forensic report — produce it regardless of any specific hypothesis. Using the "
    "OS-appropriate identity sources, determine and report:\n"
    "- The computer / host name.\n"
    "- The registered owner / organization, the OS product name and version, and "
    "the install date.\n"
    "- The system time zone.\n"
    "- The local user accounts and their SIDs/UIDs (and which is the primary "
    "user).\n"
    "- The network identity: the IP address(es) and the MAC address(es).\n"
    "Emit each as a finding with the correct ioc_type (registry_key for a Windows "
    "registry-sourced fact, ip for an IP address, domain for an email/domain), "
    "citing the tool execution that produced it."
)

# Which evidence kinds each domain's tools can actually read, in preference
# order. An investigation may hold several evidence items (e.g. a disk image and
# a memory capture of one host); a domain is routed only to items it can analyze
# so a memory agent never runs against a disk image and vice versa. The first
# kind in the tuple that is present wins; network falls back to disk because
# network artifacts (browser history, connection logs) also live on disk. A
# domain absent from this table sees every item.
DOMAIN_EVIDENCE_AFFINITY: dict[str, tuple[str, ...]] = {
    "memory": ("memory",),
    "network": ("pcap", "disk"),
    "disk": ("disk",),
    "timeline": ("disk",),
    "artifacts": ("disk",),
    "malware": ("disk",),
}


def domains_for_evidence_kinds(kinds: set[str]) -> list[str]:
    """Domains to dispatch, derived from the evidence kinds present in the case.

    Inverts ``DOMAIN_EVIDENCE_AFFINITY``: a domain is selected when its affinity
    tuple contains any evidence kind present in the investigation. This replaces
    hypothesis-text keyword matching for domain *selection* — the hypothesis text
    is the agent's mission, not a filter. For a disk image this yields
    ``{disk, timeline, artifacts, malware, network}`` (network lists disk too);
    ``memory`` yields ``{memory}``; ``pcap`` yields ``{network}``. With no known
    kinds it fails open to every domain. Order follows ``DOMAIN_EVIDENCE_AFFINITY``
    so the fan-out is deterministic.
    """
    if not kinds:
        return list(DOMAIN_EVIDENCE_AFFINITY)
    selected = [
        domain
        for domain, affinity in DOMAIN_EVIDENCE_AFFINITY.items()
        if any(k in affinity for k in kinds)
    ]
    return selected or list(DOMAIN_EVIDENCE_AFFINITY)


def _normalize_hypothesis(description: str) -> str:
    # Reduce to lowercase alphanumeric words so trivially-different phrasings of
    # the same idea ("RDP-based lateral movement" vs "lateral movement via RDP "
    # with punctuation) compare as the same string.
    return " ".join(re.sub(r"[^a-z0-9 ]", " ", description.lower()).split())


def is_novel_hypothesis(description: str, existing_descriptions: list[str]) -> bool:
    """True when `description` is not a near-duplicate of any existing hypothesis.

    Comparison is on a normalized form (case/punctuation/spacing-insensitive) so
    the re-hypothesize step does not keep re-adding the same idea in new words.
    """
    seen = {_normalize_hypothesis(d) for d in existing_descriptions}
    return _normalize_hypothesis(description) not in seen


class Investigator:
    """Orchestrates a full forensic investigation.

    Usage:
        inv = Investigator(executor, registry_tools, output_dir)
        report = inv.investigate(evidence_path, evidence_type)
    """

    def __init__(
        self,
        executor: Executor,
        registry_tools: list[dict],
        output_dir: str | Path,
        max_rounds: int = 5,
        evidence_opener: Callable[..., EvidenceView] = open_evidence,
        runner=None,
        baseline_path: str | Path | None = None,
    ) -> None:
        self.executor = executor
        self.registry_tools = registry_tools
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_rounds = max_rounds
        # Opening evidence is injectable so tests can supply a view without
        # mounting anything; the default mounts disk images for real runs.
        self._evidence_opener = evidence_opener
        # Privileged runner used by the default opener to mount disk images;
        # None lets the opener construct the real one lazily.
        self._runner = runner
        # Set by close at the end of the run; carries the integrity check of the
        # primary (first) evidence item, kept for single-evidence callers.
        self._teardown: TeardownResult = TeardownResult()
        # The opened evidence items (spec + view) and their teardown results,
        # aligned by index — used to build the report's per-item evidence list.
        self._evidence_items: list[tuple[EvidenceSpec, EvidenceView]] = []
        self._item_teardowns: list[TeardownResult] = []
        self.baseline_path = Path(baseline_path) if baseline_path else None

        self.audit = AuditLogger(self.output_dir / "audit.jsonl")
        self.progress = ProgressTracker(self.output_dir / "progress.json")
        # One advisor per investigation (per image): the compatibility matrix
        # accumulates across triage and every dispatched sub-agent.
        self.advisor = ToolAdvisor()
        self.investigation_id = f"inv-{uuid.uuid4().hex[:8]}"

        # Populated only if a run crashes partway through; surfaced in the
        # report so a failed run still explains why instead of vanishing.
        self._run_error = ""
        self.all_findings: list[Finding] = []
        self.accepted_findings: list[Finding] = []
        # Every tool execution output seen across all rounds, keyed by execution
        # id. Carried into the report so each finding can be traced back to the
        # exact command, exit code, and output that produced it.
        self._all_exec_outputs: dict[str, dict] = {}
        # Claims a sub-agent could not back with a successful tool execution,
        # plus tool/environment notes. Surfaced in the report's Limitations
        # section rather than presented as findings.
        self._limitations: list[str] = []
        # Evidence kinds present in this investigation (e.g. {"disk", "memory"}),
        # set when the run starts. Drives gate-based domain selection — see
        # domains_for_evidence_kinds. Empty until investigate_evidence runs.
        self._evidence_kinds: set[str] = set()
        # The OS and kind of the evidence item the current dispatch targets, set
        # serially per (hypothesis, domain, item) in _build_dispatch_work /
        # _characterize_systems just before the tool gate runs. Threaded via
        # instance state so _filter_tools_for_domain keeps its (domain,
        # hypothesis_id) signature (still stubbed by tests).
        self._dispatch_evidence_os: Optional[str] = None
        self._dispatch_evidence_kind: str = ""
        # Cache of raw-image path -> primary filesystem sector offset, so the
        # partition table is read with mmls at most once per image rather than on
        # every sub-agent dispatch.
        self._offset_cache: dict[str, int] = {}
        self.correlation_result = None
        # Groups of findings that describe the same activity, identified by
        # reasoning over finding descriptions rather than timestamps alone.
        self.semantic_result: SemanticCorrelationResult = SemanticCorrelationResult()
        # Per-finding verification metadata (rounds, corroboration,
        # reasoning chain, recalibration) for the report layer.
        self._verification_meta: dict[str, dict] = {}

    def investigate(
        self,
        evidence_path: str,
        evidence_type: str = "disk",
        focus: Optional[list[str]] = None,
        brief: Optional[str] = None,
    ) -> dict:
        """Run a single-evidence investigation. Returns the report as a dict.

        This is the backward-compatible entry point; it delegates to
        ``investigate_evidence`` with one evidence item.
        """
        return self.investigate_evidence(
            [EvidenceSpec(path=evidence_path, evidence_type=evidence_type)],
            focus=focus,
            brief=brief,
        )

    def investigate_evidence(
        self,
        specs: list[EvidenceSpec],
        focus: Optional[list[str]] = None,
        brief: Optional[str] = None,
    ) -> dict:
        """Run an investigation over one or more evidence items.

        Several items (e.g. a disk image and a memory capture of the same host)
        are opened together so their findings can be correlated. Each item is
        opened once for the whole run, triaged, and made available to the domains
        whose tools can read it; all items are closed in the finally below, which
        releases mounts and runs each closing integrity check even if the
        investigation raises partway through.
        """
        self._brief = brief

        primary = specs[0]
        combined_type = "+".join(dict.fromkeys(s.evidence_type for s in specs))
        # The kinds present drive gate-based domain selection (see
        # domains_for_evidence_kinds), so record them before any dispatch.
        self._evidence_kinds = {s.evidence_type for s in specs}

        self.progress.start(
            investigation_id=self.investigation_id,
            evidence_path=primary.path,
            evidence_type=combined_type,
            max_iterations=self.max_rounds,
        )

        # Open each item INSIDE the try so that if one item's open fails, the
        # finally still closes the items already opened (opening in a list
        # comprehension before the try would leak those earlier mounts).
        items: list[tuple[EvidenceSpec, EvidenceView]] = []
        self._evidence_items = items
        try:
            for spec in specs:
                view = self._evidence_opener(
                    spec.path,
                    spec.evidence_type,
                    executor=self.executor,
                    runner=self._runner,
                )
                items.append((spec, view))

            # Phase 1: Triage each item; combine into one view of the evidence.
            triage_result = self._run_triage_all(items)

            # Phase 2: Form hypotheses
            self._form_hypotheses(triage_result, combined_type, focus)

            # Phase 2.5: Always-on system characterization. Emit the standard
            # forensic-report identity facts (host/owner/OS/timezone/accounts/
            # network) independent of any hypothesis, then verify them like any
            # other findings, so they are reported even when no hypothesis would
            # surface them.
            char_findings, char_outputs = self._characterize_systems(items)
            if char_findings:
                self._verify_round(char_findings, char_outputs, primary.path)
                self.all_findings.extend(char_findings)

            # Phase 3: Investigation loop
            while self.progress.can_continue:
                round_num = self.progress.iteration + 1

                active = self.progress.active_hypotheses
                if not active:
                    break

                self.audit.log_orchestrator_plan(
                    investigation_round=round_num,
                    hypotheses_active=[h.id for h in active],
                    sub_agents_dispatched=[],
                    focus_areas=[h.description for h in active],
                )

                # Dispatch sub-agents for each active hypothesis, routing each
                # domain to the evidence items its tools can read.
                round_findings, exec_outputs = self._dispatch_sub_agents(
                    active,
                    items,
                    combined_type,
                )

                # Verify high-value findings: multi-round adversarial
                # verification with deterministic cross-domain corroboration +
                # recalibration.
                self._verify_round(round_findings, exec_outputs, primary.path)

                self.all_findings.extend(round_findings)

                # Evaluate hypotheses based on findings
                self._evaluate_hypotheses(round_findings)

                # Deepen/pivot: form new hypotheses from what this round revealed
                # and record pivots away from refuted ones. This is what makes
                # the later rounds mean something — the loop follows the evidence
                # instead of only re-testing the initial guesses. It is bounded
                # (see _rehypothesize) so it converges.
                self._rehypothesize(round_findings, round_num)

                # Check if we should continue
                if not self.progress.increment_iteration():
                    break

                # Done once no hypotheses remain open and none were proposed.
                if not self.progress.active_hypotheses:
                    break

            # The investigation itself (triage, hypothesis loop, verification,
            # finding acceptance) is finished here, so mark the run complete
            # before post-processing.
            self.progress.complete()

            # Phase 4: Correlate findings. Temporal correlation (timeline,
            # event chains, gaps) runs first; semantic grouping is a separate
            # step owned by the orchestrator so the LLM call happens once.
            # Correlation is post-processing/enrichment: a failure here must NOT
            # downgrade a finished investigation to "errored". Record it as a
            # post-processing error but keep the completed status, so the
            # terminal status reflects what actually succeeded.
            try:
                self._phase(
                    "Correlating findings (temporal + one semantic LLM call) — "
                    "no per-tool audit events during this step"
                )
                correlation_engine = CorrelationEngine(self.accepted_findings)
                self.correlation_result = correlation_engine.correlate(use_llm=False)
                self._correlate_semantically()
            except Exception as exc:
                self._run_error = f"Post-processing (correlation) failed: {exc}"
                logger.warning(
                    "Post-processing (correlation) failed — keeping completed status",
                    exc_info=True,
                )
        except Exception as exc:
            # A crash anywhere in the investigation must still yield a report
            # rather than discarding all partial work and leaving the run stuck
            # at "in_progress". Record a terminal status and the error, then fall
            # through to teardown and report generation below.
            self.progress.error()
            self._run_error = str(exc)
            logger.warning(
                "Investigation run failed — emitting report with errored status",
                exc_info=True,
            )
        finally:
            # Release every item's mounts and capture its closing integrity
            # hash. Done in a finally so a mid-run failure still unmounts. This
            # re-hashes the full image (SHA-256) for the integrity bracket, which
            # can take a while on a large image and emits no audit events.
            self._phase(
                "Releasing evidence + re-hashing image(s) for the integrity "
                "bracket — this can take a minute on a large image"
            )
            self._item_teardowns = [close_evidence(view) for _, view in items]
            self._teardown = (
                self._item_teardowns[0] if self._item_teardowns else TeardownResult()
            )

        # Phase 5: Generate and write the report (both JSON and Markdown). Done
        # after teardown so the report can include the closing integrity check,
        # and on every path (success or failure) so a run always leaves a report.
        # Generation builds an in-memory dict (no IO) and is always returned; the
        # disk write is wrapped so an IO failure in this final step is surfaced
        # rather than propagated — otherwise a failure here would discard the
        # whole report and defeat the "always write a report" guarantee.
        self._phase("Scoring vs baseline + writing report (report.json/report.md)")
        report = self._generate_report(primary.path, combined_type)
        try:
            self._write_reports(report)
        except Exception as exc:
            write_error = f"Report write failed: {exc}"
            self._run_error = (
                f"{self._run_error}; {write_error}" if self._run_error else write_error
            )
            report["error"] = self._run_error
            logger.warning(
                "Report write failed — returning in-memory report", exc_info=True
            )

        return report

    def _phase(self, message: str) -> None:
        """Announce a post-round phase to stdout AND the audit log.

        The end-of-run steps (correlation, evidence teardown/re-hash, scoring,
        report write) emit no per-tool audit events, so a monitor watching
        ``audit.jsonl`` (or the console) sees a multi-minute gap and assumes the
        run hung. Writing a marker here keeps both surfaces active so the run is
        visibly alive. Purely observability — must never raise.
        """
        try:
            print(f"[phase] {message}", flush=True)
        except Exception:
            pass
        try:
            self.audit.log_agent_message(
                "orchestrator", "orchestrator", "phase", message
            )
        except Exception:
            pass

    def _run_triage_all(self, items: list[tuple[EvidenceSpec, EvidenceView]]) -> str:
        """Triage every evidence item and combine the results into one string.

        Each item is labeled with its path and type so hypothesis formation can
        reason across, for example, a disk image and a memory capture together.
        """
        parts = []
        for spec, view in items:
            parts.append(f"=== Evidence: {spec.path} (type={spec.evidence_type}) ===")
            parts.append(self._run_triage(view, spec.evidence_type))
        return "\n".join(parts)

    def _correlate_semantically(self) -> None:
        """Group accepted findings that describe the same activity.

        Reasons over finding descriptions to link related findings that a
        purely time-based correlation would miss (for example, a file written
        in one place and a registry key referencing the same file hours later).
        Stores the result on the instance. Resilient by design: with fewer than
        two findings, or when the grouping step returns nothing, it produces an
        empty result instead of raising.
        """
        self.semantic_result = correlate_semantically(self.accepted_findings)

    def _write_reports(self, report: dict) -> None:
        """Write the report to disk in both machine- and human-readable form.

        Emits ``report.json`` (the structured report) and ``report.md`` (a
        formatted Markdown rendering of the same data plus the audit trail) to
        the investigation output directory.
        """
        if self.baseline_path:
            self._score_and_attach(report)

        report_path = self.output_dir / "report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        ReportGenerator(report, self.audit.get_events()).write_markdown(
            self.output_dir / "report.md"
        )

    def _score_and_attach(self, report: dict) -> None:
        """Score the report against the configured baseline and attach results."""
        try:
            baseline = load_baseline(self.baseline_path)
        except (FileNotFoundError, ValueError) as e:
            report["accuracy_score_error"] = str(e)
            return
        score = score_report(report, self.audit.get_events(), baseline)
        report["accuracy_score"] = score.to_dict()

    def _run_triage(self, view: EvidenceView, evidence_type: str) -> str:
        """Run lightweight triage tools to understand the evidence.

        Triage tools read the raw container (partition layout, filesystem type,
        image metadata), so they are pointed at the raw image path even when the
        image is also mounted. When the image is mounted, the mounted roots and
        the auto-detected OS are appended to the triage output so that
        hypothesis formation knows the filesystem is browsable and what it is —
        no extra tool run is needed to discover that.
        """

        triage_tools = {
            "disk": ["mmls", "fsstat", "img_stat", "fls"],
            "memory": ["vol"],
            "pcap": ["tcpdump"],
            "logs": ["file"],
        }

        tool_names = triage_tools.get(evidence_type, ["file"])
        results = []

        # Sector offset of the filesystem within the raw image, for tools that
        # take one (fls/fsstat). For a mounted image the partitions were already
        # enumerated, so the offset is known without a tool run. For a raw-only
        # image it is derived from this triage's own mmls run below (mmls is
        # first in the order, before fsstat/fls need it) and cached, so neither
        # triage nor sub-agent dispatch re-runs mmls just to learn the offset.
        offset = self._primary_offset(view) if view.session is not None else 0

        for tool_name in tool_names:
            tool = self._find_tool_by_name(tool_name)
            if not tool:
                continue

            # Build basic triage command
            args = self._triage_args(tool_name, view.raw_path, offset)

            # Pre-validate to seed the compatibility matrix and skip tools that
            # cannot run on this host/evidence (e.g. .NET parsers on Linux).
            reason = self.advisor.blocking_reason(tool, tool["path"], args, evidence_type)
            if reason:
                self.advisor.record_result(tool["path"], success=False, error=reason)
                results.append(
                    {
                        "tool": tool_name,
                        "exit_code": None,
                        "stdout": "",
                        "stderr": f"skipped: {reason}",
                    }
                )
                continue

            exec_result = self.executor.run(
                tool_path=tool["path"],
                args=args,
            )
            self.audit.log_tool_execution_from_result(exec_result)
            # Credit a tool that worked, but do NOT record a triage exit-code
            # failure as a compatibility failure. Triage uses fixed arguments
            # (for example a fixed partition offset) that can simply be wrong for
            # this image; recording that as a failure would mark the tool
            # "known-bad" in the advisor shared with the sub-agents, so they
            # would skip the very tool they need even when called with correct
            # arguments. Genuine capability failures are still recorded above by
            # pre-validate; sub-agents record their own real attempts.
            if exec_result.exit_code == 0:
                self.advisor.record_result(tool["path"], success=True)

            # On a raw-only image, learn the filesystem's start sector from this
            # mmls run (it precedes fsstat/fls in the order) and cache it, so the
            # remaining triage tools and every sub-agent target the real
            # partition (e.g. NTFS at sector 63) instead of sector 0.
            if (
                view.session is None
                and tool_name == "mmls"
                and exec_result.exit_code == 0
            ):
                offset = self._parse_first_fs_offset(exec_result.stdout)
                self._offset_cache[view.raw_path] = offset

            results.append(
                {
                    "tool": tool_name,
                    "exit_code": exec_result.exit_code,
                    "stdout": exec_result.stdout[:3000],
                    "stderr": exec_result.stderr[:500],
                }
            )

        if view.is_mounted:
            detected_os = getattr(view.session, "os", None)
            results.append(
                {
                    "mounted_filesystems": view.mount_roots,
                    "detected_os": detected_os or "unknown",
                    "note": (
                        "The evidence filesystem is mounted read-only at the "
                        "paths above. Files inside it can be read with ordinary "
                        "tools; deleted files still require Sleuth Kit on the "
                        "raw image."
                    ),
                }
            )

        return json.dumps(results, indent=2)

    def _primary_offset(self, view: EvidenceView) -> int:
        """Sector offset of the image's first filesystem partition.

        A mounting session already enumerated the partitions (with their start
        sectors) to mount them, so its first volume's start is used when present.
        With no session (a raw-only view — e.g. mounting was unavailable), the
        partition table is read with mmls instead, so a partitioned image targets
        its real filesystem rather than sector 0. Only a genuinely single-volume
        image (no partition table) resolves to 0. The result is cached per image
        so mmls runs at most once. Tools that take a partition offset (fls,
        fsstat, icat, tsk_recover) reuse this value.
        """
        if view.raw_path in self._offset_cache:
            return self._offset_cache[view.raw_path]
        offset = self._compute_primary_offset(view)
        self._offset_cache[view.raw_path] = offset
        return offset

    def _compute_primary_offset(self, view: EvidenceView) -> int:
        session = view.session
        if session is not None:
            try:
                volumes = session.volumes()
            except Exception:
                volumes = []
            if volumes:
                return getattr(volumes[0], "start_sector", 0) or 0
        return self._offset_from_mmls(view.raw_path)

    def _offset_from_mmls(self, raw_path: str) -> int:
        """Read the partition table with mmls and return the first FS offset.

        Returns 0 when mmls is unavailable, is rejected, fails, or finds no
        partition table (a single-volume image whose filesystem starts at 0).
        """
        tool = self._find_tool_by_name("mmls")
        if not tool:
            return 0
        result = self.executor.run(tool_path=tool["path"], args=[raw_path])
        if result.rejected or result.exit_code != 0:
            return 0
        return self._parse_first_fs_offset(result.stdout)

    @staticmethod
    def _parse_first_fs_offset(mmls_stdout: str) -> int:
        """Start sector of the first allocated filesystem partition in mmls output.

        mmls rows look like:
          002:  000:000   0000000063   0009510479   0009510417   NTFS / exFAT (0x07)
        The Start sector of the first row whose slot column is a real address
        (``NNN:NNN``, not ``Meta`` or ``-------``) and whose description is not
        "Unallocated" is the offset. Returns 0 when there is no such row (e.g. a
        single-volume image with no partition table, or empty/error output).
        """
        for line in mmls_stdout.splitlines():
            m = re.match(
                r"^\s*\d{3}:\s+(\d{3}:\d{3})\s+(\d+)\s+\d+\s+\d+\s+(.+?)\s*$",
                line,
            )
            if not m:
                continue
            if "unallocated" in m.group(3).lower():
                continue
            return int(m.group(2))
        return 0

    def _triage_args(
        self, tool_name: str, evidence_path: str, offset: int = 0
    ) -> list[str]:
        """Build triage arguments for common tools.

        ``offset`` is the partition's start sector for tools that address a
        filesystem inside a raw image (fls/fsstat); it defaults to 0 for images
        whose filesystem starts at the beginning.
        """
        triage_commands = {
            "mmls": [evidence_path],
            "fsstat": ["-o", str(offset), evidence_path],
            "img_stat": [evidence_path],
            "fls": ["-o", str(offset), evidence_path],
            "vol": ["-f", evidence_path, "windows.info"],
            "tcpdump": ["-r", evidence_path, "-c", "100", "-nn"],
            "file": [evidence_path],
        }
        return triage_commands.get(tool_name, [evidence_path])

    def _form_hypotheses(
        self,
        triage_result: str,
        evidence_type: str,
        focus: Optional[list[str]],
    ) -> list[dict]:
        """Ask Claude to form hypotheses from triage results."""

        focus_text = ""
        if focus:
            focus_text = f"\nInvestigation focus areas: {', '.join(focus)}"

        brief_text = ""
        if self._brief:
            brief_text = f"\n\nCase briefing from the analyst:\n{self._brief}"

        prompt = f"""Based on this initial triage of a {evidence_type} forensic image, form 1-3 hypotheses about what may have happened.
{brief_text}

Triage results:
{triage_result}
{focus_text}

Distinguish TOOL problems from EVIDENCE facts. A triage entry with a nonzero exit_code or a stderr message is a tool/execution problem (a wrong partition offset, a localized image read gap, or an inapplicable tool) — it is NOT itself evidence of what happened on the host. Do not form hypotheses about image corruption, acquisition failure, or anti-forensic wiping solely because a triage tool errored. In particular, mmls returning a nonzero exit code or empty output normally just means the image is a single-volume filesystem with no partition table (read at offset 0) — that is routine, not corruption. Treat tool failures as obstacles to work around in later rounds, and base hypotheses on what the evidence positively shows (filesystem type, detected OS, files present, timestamps).

Respond with ONLY valid JSON:
{{
  "hypotheses": [
    {{
      "id": "H1",
      "description": "what you think happened",
      "domains_to_investigate": ["disk", "windows_artifacts", "timeline"],
      "reasoning": "why this hypothesis based on triage"
    }}
  ]
}}

Available investigation domains: {", ".join(AGENT_DOMAINS.keys())}

Form hypotheses like a senior analyst would — based on what the triage reveals, not generic guesses."""

        result = call_claude_json(prompt, timeout=300)
        hypotheses = []
        if result and "hypotheses" in result:
            for h in result["hypotheses"]:
                self.progress.add_hypothesis(h["id"], h["description"])
                self.audit.log_hypothesis(
                    h["id"],
                    "formed",
                    h["description"],
                    h.get("reasoning", ""),
                )
                hypotheses.append(h)

        return hypotheses

    def _rehypothesize(self, round_findings: list[Finding], round_num: int) -> int:
        """Form new hypotheses from the round's findings and record any pivots.

        Returns the number of genuinely new hypotheses added. Bounded so the loop
        converges rather than thrashing: no new hypotheses after the cutoff
        round, never more than the total cap, and proposals that duplicate an
        existing hypothesis are dropped.
        """
        if round_num > NEW_HYPOTHESIS_CUTOFF_ROUND:
            return 0
        # Snapshot the starting count: add_hypothesis() appends to this same
        # live list, so re-reading its length mid-loop would double-count each
        # addition against the cap.
        existing = self.progress.progress.hypotheses
        base = len(existing)
        cap = _int_env("AGENTIC_SIFT_MAX_HYPOTHESES", MAX_HYPOTHESES)
        if base >= cap:
            return 0

        result = call_claude_json(self._build_rehypothesize_prompt(round_findings))
        if not result:
            return 0

        existing_desc = [h.description for h in existing]
        added = 0
        for proposed in result.get("new_hypotheses", []):
            if base + added >= cap:
                break
            desc = (proposed.get("description") or "").strip()
            if not desc or not is_novel_hypothesis(desc, existing_desc):
                continue
            # A unique id, so a newly-formed hypothesis never collides with an
            # existing one or with another added in the same pass.
            hid = f"H-{uuid.uuid4().hex[:8]}"
            self.progress.add_hypothesis(hid, desc)
            self.audit.log_hypothesis(
                hid, "formed", desc, proposed.get("reasoning", "")
            )
            existing_desc.append(desc)
            added += 1

        for pivot in result.get("pivots", []):
            frm = (pivot.get("from") or "").strip()
            to = (pivot.get("to") or "").strip()
            if frm and to:
                self.progress.record_pivot(frm, to, pivot.get("reason", ""))

        return added

    def _build_rehypothesize_prompt(self, round_findings: list[Finding]) -> str:
        findings_text = (
            "\n".join(f"- [{f.confidence}] {f.description}" for f in round_findings)
            or "(no findings this round)"
        )
        return f"""Given the investigation so far, decide whether to form NEW
hypotheses or pivot away from refuted ones. Propose only genuinely new
directions grounded in what has been learned; do not restate hypotheses that
already exist.

{self.progress.format_for_prompt()}

Findings from the latest round:
{findings_text}

Respond with ONLY valid JSON:
{{
  "new_hypotheses": [{{"description": "...", "reasoning": "why, from the evidence"}}],
  "pivots": [{{"from": "refuted hypothesis", "to": "new direction", "reason": "..."}}]
}}

If nothing new is warranted, return empty lists."""

    def _evidence_for_domain(
        self,
        domain_name: str,
        items: list[tuple[EvidenceSpec, EvidenceView]],
    ) -> list[tuple[EvidenceSpec, EvidenceView]]:
        """Pick the evidence items a domain's tools can actually read.

        Uses DOMAIN_EVIDENCE_AFFINITY: the first evidence kind in the domain's
        preference order that is present among ``items`` wins. A domain with no
        matching evidence returns an empty list and is skipped (so a memory agent
        never runs against a disk-only case). A domain absent from the table sees
        every item.
        """
        affinity = DOMAIN_EVIDENCE_AFFINITY.get(domain_name)
        if affinity is None:
            return list(items)
        for etype in affinity:
            matched = [(s, v) for (s, v) in items if s.evidence_type == etype]
            if matched:
                return matched
        return []

    def _build_dispatch_work(
        self,
        hypotheses: list,
        items: list[tuple[EvidenceSpec, EvidenceView]],
    ) -> list[dict]:
        """Build the independent sub-agent work items for a round.

        One item per (hypothesis, domain, evidence target). Resolving domains/
        tools/targets and the partition offset here — serially, on the calling
        thread — keeps the per-image offset cache writes off the worker threads,
        so the concurrent dispatch only touches thread-safe shared sinks.
        """
        work: list[dict] = []
        for hypothesis in hypotheses:
            for domain_name in self._domains_for_hypothesis(hypothesis):
                domain = AGENT_DOMAINS.get(domain_name)
                if not domain:
                    continue
                targets = self._evidence_for_domain(domain_name, items)
                if not targets:
                    continue
                for spec, view in targets:
                    # Gate per target so the tool menu reflects THIS item's OS and
                    # kind (target = the evidence image, not the host platform).
                    self._dispatch_evidence_os = self._evidence_os(view)
                    self._dispatch_evidence_kind = spec.evidence_type
                    tools = self._filter_tools_for_domain(domain, hypothesis.id)
                    if not tools:
                        continue
                    work.append(
                        {
                            "hypothesis": hypothesis,
                            "domain": domain,
                            "domain_name": domain_name,
                            "tools": tools,
                            "task": self._build_sub_agent_task(hypothesis, spec, items),
                            "view": view,
                            "primary_offset": self._primary_offset(view),
                        }
                    )
        return work

    @staticmethod
    def _evidence_os(view: EvidenceView) -> Optional[str]:
        """The detected OS of an evidence item (``windows``/``macos``/``linux``),
        or None when undetected/unmounted. Read from the mounting session, which
        ran OS detection at mount time; None feeds the OS gate's fail-open path.
        """
        session = getattr(view, "session", None)
        return getattr(session, "os", None) if session is not None else None

    def _dispatch_sub_agents(
        self,
        hypotheses: list,
        items: list[tuple[EvidenceSpec, EvidenceView]],
        evidence_type: str,
    ) -> tuple[list[Finding], dict[str, dict]]:
        """Dispatch sub-agents to test active hypotheses.

        Each hypothesis maps to one or more domains; each domain is routed to the
        evidence items its tools can read (see _evidence_for_domain) and run once
        per matching item. Returns the findings plus a map of execution_id ->
        tool output, so the verifier can be handed the *actual* outputs behind
        each finding (via finding.evidence_links) instead of an empty list.
        """

        # Build the independent units of work first (cheap, serial), then run them
        # concurrently and merge results single-threaded below.
        work = self._build_dispatch_work(hypotheses, items)

        all_findings: list[Finding] = []
        exec_outputs: dict[str, dict] = {}
        if not work:
            return all_findings, exec_outputs

        # Run the sub-agents concurrently: each is dominated by serial
        # `claude --print` calls, so the independent ones overlap instead of
        # summing. The sinks they share are thread-safe (AuditLogger,
        # ProgressTracker, ToolAdvisor locks); results are merged below by this
        # single thread, in submission order.
        max_workers = min(
            _int_env("AGENTIC_SIFT_MAX_PARALLEL", _MAX_PARALLEL_SUB_AGENTS), len(work)
        )
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            results = list(pool.map(self._run_sub_agent, work))

        for item, result in results:
            if result is None:
                continue
            hypothesis = item["hypothesis"]
            for finding in result.findings:
                finding.hypothesis_id = hypothesis.id
            all_findings.extend(result.findings)
            # Carry any dropped-claim / tool-limitation notes through to the
            # report so they are visible without being reported as findings.
            self._limitations.extend(result.limitations)
            for out in result.execution_outputs:
                eid = out.get("execution_id")
                if eid:
                    exec_outputs[eid] = out
                    # Keep a run-wide copy so the report can resolve any finding's
                    # evidence link to its command, not just this round's links.
                    self._all_exec_outputs[eid] = out
            self.audit.log_orchestrator_plan(
                investigation_round=self.progress.iteration + 1,
                hypotheses_active=[hypothesis.id],
                sub_agents_dispatched=[result.agent_name],
                focus_areas=[hypothesis.description],
            )

        # Collapse duplicate findings the parallel sub-agents surfaced for the
        # same artifact (e.g. the same crash log found by several domains) before
        # verification and scoring — each duplicate would otherwise be a separate
        # false positive and waste a verifier pass.
        all_findings = dedupe_findings(all_findings)

        return all_findings, exec_outputs

    def _characterize_systems(
        self, items: list[tuple[EvidenceSpec, EvidenceView]]
    ) -> tuple[list[Finding], dict[str, dict]]:
        """Always-on system characterization: emit the standard identity facts.

        Runs once per MOUNTABLE item (identity lives on the filesystem),
        independent of any hypothesis, so host / owner / OS / timezone / accounts /
        network identity are reported even when no hypothesis would surface them —
        the section every forensic report opens with. Reuses the sub-agent
        machinery via a fixed mission and an identity-scoped tool menu. Returns its
        findings plus an execution_id -> output map so the caller can verify them
        exactly like a round's findings.
        """
        findings: list[Finding] = []
        exec_outputs: dict[str, dict] = {}
        domain = AGENT_DOMAINS.get("artifacts")
        if domain is None:
            return findings, exec_outputs
        mission = SimpleNamespace(
            id=_CHARACTERIZATION_ID, description=_CHARACTERIZATION_MISSION
        )
        for _spec, view in items:
            if not view.mount_roots:
                # Identity comes from the mounted filesystem; a raw-only item
                # (e.g. a memory dump or packet capture) has nothing to characterize.
                continue
            # Hand the agent the gated menu for THIS item (installed + OS- and
            # input-compatible) — the OS gate keeps Windows registry parsers on a
            # Windows image and drops them on a non-Windows one; the mission +
            # the artifacts domain prompt scope it to identity.
            self._dispatch_evidence_os = self._evidence_os(view)
            self._dispatch_evidence_kind = _spec.evidence_type
            tools = self._filter_tools_for_domain(domain, _CHARACTERIZATION_ID)
            if not tools:
                continue
            item = {
                "hypothesis": mission,
                "domain": domain,
                "domain_name": "artifacts",
                "tools": tools,
                "task": _CHARACTERIZATION_MISSION,
                "view": view,
                "primary_offset": self._primary_offset(view),
            }
            _, result = self._run_sub_agent(item)
            if result is None:
                continue
            for f in result.findings:
                f.hypothesis_id = _CHARACTERIZATION_ID
            findings.extend(result.findings)
            self._limitations.extend(result.limitations)
            for out in result.execution_outputs:
                eid = out.get("execution_id")
                if eid:
                    exec_outputs[eid] = out
                    self._all_exec_outputs[eid] = out
        return findings, exec_outputs

    def _build_sub_agent_task(
        self,
        hypothesis,
        spec: EvidenceSpec,
        items: list[tuple[EvidenceSpec, EvidenceView]],
    ) -> str:
        """Build the task string handed to one sub-agent dispatch."""
        task = f"Test hypothesis: {hypothesis.description}"
        if self._brief:
            task = f"Case context: {self._brief}\n\n{task}"
        if len(items) > 1:
            # Name the specific item so the agent does not confuse one host's
            # disk with another's memory capture.
            task = (
                f"{task}\n\nEvidence under analysis: {spec.path} "
                f"(type={spec.evidence_type})"
            )
        return task

    def _run_sub_agent(self, item: dict) -> tuple[dict, Optional["AgentResult"]]:
        """Run one sub-agent dispatch; return ``(item, result_or_None)``.

        This is the concurrent unit (one per work item). It only touches
        thread-safe shared sinks (audit/progress/advisor); the caller merges the
        returned result single-threaded. A transient ClaudeError on this single
        dispatch is recorded as a failed approach and swallowed (returns None) so
        one flaky AI reasoning call never aborts the whole round.
        """
        view = item["view"]
        agent = DomainAgent(
            domain=item["domain"],
            executor=self.executor,
            audit_logger=self.audit,
            progress_tracker=self.progress,
            tools=item["tools"],
            advisor=self.advisor,
        )
        try:
            result = agent.investigate(
                task=item["task"],
                evidence_path=view.raw_path,
                hypothesis=item["hypothesis"].description,
                mount_roots=view.mount_roots,
                primary_offset=item["primary_offset"],
            )
        except ClaudeError as exc:
            self.progress.record_failure(
                tool=item["domain_name"],
                args=[],
                failure=(
                    f"AI planning/interpretation call failed for "
                    f"domain {item['domain_name']}: {exc}"
                ),
                lesson="Transient Claude failure; degraded this dispatch and continued.",
            )
            return item, None
        except Exception as exc:
            # Any other failure in one sub-agent (a bad tool arg, an unexpected
            # parse/IO error) must degrade ONLY that dispatch — never abort the
            # whole investigation. One agent crashing the run is the failure mode
            # that turned a single bad command into a 0-finding errored run.
            self.progress.record_failure(
                tool=item["domain_name"],
                args=[],
                failure=(
                    f"Sub-agent dispatch crashed for domain "
                    f"{item['domain_name']}: {exc}"
                ),
                lesson="Unexpected sub-agent error; degraded this dispatch and continued.",
            )
            return item, None
        return item, result

    def _domains_for_hypothesis(self, hypothesis) -> list[str]:
        """Domains to dispatch for a hypothesis.

        Domain *selection* is driven by the evidence kinds present in the case
        (see ``domains_for_evidence_kinds``), not by matching keywords against the
        hypothesis text — the hypothesis is the agent's mission, not a tool
        filter. Deterministic, no LLM call. The ``hypothesis`` argument is kept
        for the call-site/stub contract; every active hypothesis fans out to the
        same evidence-derived domain set.
        """
        return domains_for_evidence_kinds(self._evidence_kinds)

    def _verify_round(
        self,
        round_findings: list[Finding],
        exec_outputs: dict[str, dict],
        evidence_path: str,
    ) -> None:
        """Verify a round's findings: multi-round challenge + recalibration.

        Builds a deterministic cross-domain corroboration index over the round,
        runs up to MAX_ROUNDS of adversarial verification per high-confidence
        finding (handing it the real tool outputs behind that finding), then
        recalibrates confidence and records any self-correction.
        """
        if not round_findings:
            return

        # Speed lever: in high-value-only mode, skip the (long, serial)
        # verification tail for low-signal findings — accept them unverified
        # (still flagged as such in the report) and spend the verifier budget
        # only on IOC-bearing / confident findings. Default off (verify all).
        if _bool_env("AGENTIC_SIFT_VERIFY_HIGH_VALUE_ONLY"):
            low_value = [f for f in round_findings if not _is_high_value(f)]
            self.accepted_findings.extend(low_value)
            round_findings = [f for f in round_findings if _is_high_value(f)]
            if not round_findings:
                return

        corroboration = CorroborationIndex(round_findings)
        verifier = MultiRoundVerifier(
            VerifierAgent(
                executor=self.executor,
                audit_logger=self.audit,
                all_tools=self.registry_tools,
            ),
            self.audit,
            max_rounds=_int_env("AGENTIC_SIFT_VERIFIER_ROUNDS", DEFAULT_MAX_ROUNDS),
        )

        # Verify findings concurrently. Each finding's verification is
        # independent — it runs its own adversarial rounds of claude +
        # counter-evidence tool calls — and was the serial tail once dispatch was
        # parallelized. The verifier shares only thread-safe sinks (executor,
        # audit) and the read-only corroboration index; every orchestrator-state
        # write (recalibration, finding mutation, meta, accepted list) happens in
        # the single-writer merge loop below, in finding order.
        max_workers = min(
            _int_env("AGENTIC_SIFT_MAX_PARALLEL", _MAX_PARALLEL_SUB_AGENTS),
            len(round_findings),
        )
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            results = list(
                pool.map(
                    lambda f: self._verify_one(
                        f, corroboration, exec_outputs, evidence_path, verifier
                    ),
                    round_findings,
                )
            )

        for finding, outcome, corr, exc in results:
            if exc is not None:
                # A transient failure of the AI verification call must not abort
                # the run. Keep the finding unverified (do not mark it verified
                # or recalibrate its confidence) but keep it rather than silently
                # dropping it, and record the failure so it is visible.
                self.progress.record_failure(
                    tool="verifier",
                    args=[],
                    failure=(
                        f"AI verification call failed for finding "
                        f"{finding.finding_id}: {exc}"
                    ),
                    lesson=(
                        "Transient Claude failure during verification; kept "
                        "finding unverified."
                    ),
                )
                self.accepted_findings.append(finding)
                continue

            previous_confidence = finding.confidence
            new_confidence, reason = recalibrate(
                previous_confidence, outcome.verdict, corr.count
            )
            finding.verified = True
            finding.verification_verdict = outcome.verdict
            finding.confidence = new_confidence

            self._verification_meta[finding.finding_id] = {
                "rounds_taken": outcome.rounds_taken,
                "verdict": outcome.verdict,
                "corroboration_ids": corr.corroborating_ids,
                "corroboration_count": corr.count,
                "reasoning_chain": outcome.reasoning_chain,
                "recalibration_reason": reason,
                "previous_confidence": previous_confidence,
                "final_confidence": new_confidence,
            }

            if outcome.verdict in ("refuted", "downgraded") or (
                new_confidence != previous_confidence
            ):
                self.audit.log_self_correction(
                    finding_id=finding.finding_id,
                    correction_reason=reason,
                    previous_confidence=previous_confidence,
                    new_confidence=new_confidence,
                    verdict=outcome.verdict,
                    rounds_taken=outcome.rounds_taken,
                )

            if outcome.verdict != "refuted":
                self.accepted_findings.append(finding)

    def _verify_one(
        self,
        finding: Finding,
        corroboration: CorroborationIndex,
        exec_outputs: dict[str, dict],
        evidence_path: str,
        verifier: MultiRoundVerifier,
    ):
        """Verify one finding — the concurrent unit of ``_verify_round``.

        Returns ``(finding, outcome_or_None, corr, exc_or_None)`` for the caller
        to merge single-threaded. Only reads the shared (read-only) corroboration
        index and exec outputs and drives the thread-safe verifier; performs no
        orchestrator-state writes itself. Every finding is challenged, including
        low-confidence ones — those are exactly the claims most likely to be
        wrong, and verifying them keeps unsupported findings out of the report.
        """
        original_outputs = [
            exec_outputs[eid] for eid in finding.evidence_links if eid in exec_outputs
        ]
        corr = corroboration.for_finding(finding.finding_id)
        try:
            outcome = verifier.verify(
                finding,
                original_outputs,
                evidence_path,
                corroboration_count=corr.count,
                corroboration_ids=corr.corroborating_ids,
            )
        except ClaudeError as exc:
            return finding, None, corr, exc
        return finding, outcome, corr, None

    def _evaluate_hypotheses(self, findings: list[Finding]) -> None:
        """Update hypothesis status based on findings tagged to each hypothesis."""

        if not findings:
            return

        for hypothesis in self.progress.active_hypotheses:
            h_findings = [f for f in findings if f.hypothesis_id == hypothesis.id]
            if not h_findings:
                continue
            supporting = [
                f
                for f in h_findings
                if f.confidence in ("confirmed", "inferred")
                and f.verification_verdict != "refuted"
            ]
            contradicting = [
                f for f in h_findings if f.verification_verdict == "refuted"
            ]

            if not supporting and not contradicting:
                # Findings exist but none are decisive (e.g. all low-confidence
                # and unrefuted); leave the hypothesis open.
                continue

            # Always record BOTH sides so contradicting evidence is never
            # dropped from the report, even when a hypothesis also has support.
            # A hypothesis with both is "contested" rather than cleanly
            # supported, which would hide the conflict.
            if supporting and contradicting:
                status = "contested"
            elif supporting:
                status = "supported"
            else:
                status = "refuted"

            self.progress.update_hypothesis(
                hypothesis.id,
                status=status,
                evidence_for=[f.description for f in supporting],
                evidence_against=[f.description for f in contradicting],
            )
            self.audit.log_hypothesis(
                hypothesis.id,
                status,
                hypothesis.description,
                f"{len(supporting)} supporting, {len(contradicting)} contradicting findings",
            )

    def _find_tool_by_name(self, name: str) -> Optional[dict]:
        """Find a tool in the registry by name (partial match)."""
        for tool in self.registry_tools:
            if name.lower() in tool["name"].lower():
                return tool
            if tool["path"].endswith(f"/{name}"):
                return tool
        return None

    def _filter_tools_for_domain(
        self, domain: AgentDomain, hypothesis_id: str = ""
    ) -> list[dict]:
        """Gate the registry tools for the current dispatch target.

        Returns every tool that passes the three deterministic, fail-open gates
        (installed AND OS-compatible AND input-compatible) for the evidence item
        this dispatch targets — there is no category filter and no ``[:30]`` cap.
        The full gated menu is handed to the sub-agent, whose domain system prompt
        provides the specialization and whose planning LLM picks from the menu.

        ``hypothesis_id`` is unused (kept for the call-site and test stub
        contract). The evidence OS and kind come from instance state set by the
        caller (``_build_dispatch_work`` / ``_characterize_systems``) just before
        this runs, so the menu reflects the targeted image, not the host. The
        domain name additionally scopes the menu to this agent's specialty via
        the fail-open domain gate (untagged/``any`` tools still pass, so older
        catalogs without a ``domains`` field behave exactly as before).
        """
        return gate_tools(
            self.registry_tools,
            self._dispatch_evidence_os,
            self._dispatch_evidence_kind,
            getattr(domain, "name", None),
        )

    def _finding_report_dict(self, f: Finding, partial: bool = False) -> dict:
        """Serialize a finding for the report, including verification metadata.

        ``partial`` is True when the run was cut short (no rounds completed,
        timed out, hit the iteration cap, errored, or nothing was verified). In
        that case every finding is labelled triage-only so a reader does not
        treat it at parity with a finding from a completed, verified run.
        """
        meta = self._verification_meta.get(f.finding_id, {})
        d = {
            "finding_id": f.finding_id,
            "description": f.description,
            "confidence": f.confidence,
            "verified": f.verified,
            "verification_verdict": f.verification_verdict,
            "verification_rounds": meta.get("rounds_taken", 1 if f.verified else 0),
            "corroboration_count": meta.get("corroboration_count", 0),
            "corroboration_ids": meta.get("corroboration_ids", []),
            "recalibration_reason": meta.get("recalibration_reason", ""),
            "ioc_type": f.ioc_type,
            "ioc_value": f.ioc_value,
            "evidence_links": f.evidence_links,
            "agent": f.agent_name,
        }
        d["verification_state"] = (
            "triage_only" if partial else ("verified" if f.verified else "unverified")
        )
        return d

    def _integrity_section(self, teardown: TeardownResult) -> dict:
        """Summarize one evidence item's integrity check for the report.

        ``checked`` is False when nothing was mounted (no before/after hash was
        taken — e.g. raw memory or pcap evidence). When checked, ``verified`` is
        True only if the image hash was identical before and after the run; a
        non-empty ``spoliation`` message means the image changed during analysis
        and the report is not forensically sound.
        """
        if teardown.integrity is None:
            return {"checked": False}
        rec = teardown.integrity
        return {
            "checked": True,
            "image_path": rec.image_path,
            "before_sha256": rec.before_sha256,
            "after_sha256": rec.after_sha256,
            "verified": rec.verified,
            "spoliation": teardown.spoliation or "",
        }

    def _evidence_section(self) -> list[dict]:
        """List every analyzed evidence item with its integrity check.

        One entry per opened item, in the order given to the investigation, so a
        multi-evidence report shows the disk image and the memory capture (and
        their individual integrity results) side by side.
        """
        section = []
        for (spec, _view), teardown in zip(self._evidence_items, self._item_teardowns):
            section.append(
                {
                    "path": spec.path,
                    "evidence_type": spec.evidence_type,
                    "integrity": self._integrity_section(teardown),
                }
            )
        return section

    def _generate_report(self, evidence_path: str, evidence_type: str) -> dict:
        """Generate the final investigation report."""

        cr = self.correlation_result

        # A run is partial when no rounds completed, it ended in a non-completed
        # terminal state (timed out / hit the iteration cap / errored /
        # incomplete), or it produced findings none of which were verified.
        # Partial runs label every finding triage-only so they are not presented
        # at parity with verified findings. A run that completes normally and
        # legitimately finds nothing is NOT partial: with no findings there is
        # nothing to verify, so the absence of verified findings only signals a
        # cut-short run when findings actually exist.
        status = self.progress.progress.status
        rounds_completed = self.progress.iteration
        has_findings = bool(self.accepted_findings)
        any_verified = any(f.verified for f in self.accepted_findings)
        partial = (
            rounds_completed == 0
            or status in ("timed_out", "iteration_limit", "errored", "incomplete")
            or (has_findings and not any_verified)
        )

        return {
            "investigation_id": self.investigation_id,
            "evidence_path": evidence_path,
            "evidence_type": evidence_type,
            "brief": self._brief or "",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "integrity": self._integrity_section(self._teardown),
            "evidence": self._evidence_section(),
            "rounds_completed": self.progress.iteration,
            "hypotheses": [
                {
                    "id": h.id,
                    "description": h.description,
                    "status": h.status,
                    "evidence_for": h.evidence_for,
                    "evidence_against": h.evidence_against,
                }
                for h in self.progress.progress.hypotheses
            ],
            "findings": [
                self._finding_report_dict(f, partial) for f in self.accepted_findings
            ],
            # True when the run was cut short; the report banner and per-finding
            # labels warn the reader the findings were not verified.
            "findings_unverified": partial,
            # Dropped-claim / tool-limitation notes gathered during the run.
            "limitations": self._limitations,
            # Per-execution outputs keyed by execution id, so the report can show
            # the command, exit code, and output behind each finding.
            "executions": self._all_exec_outputs,
            "iocs": [
                {"type": f.ioc_type, "value": f.ioc_value}
                for f in self.accepted_findings
                if f.ioc_type and f.ioc_value
            ],
            "correlation": {
                "timeline": [
                    {
                        "timestamp": e.timestamp,
                        "description": e.description,
                        "artifact_type": e.artifact_type,
                        "finding_ids": e.finding_ids,
                        "cluster_id": e.cluster_id,
                    }
                    for e in (cr.timeline if cr else [])
                ],
                "event_chains": [
                    {
                        "chain_id": c.chain_id,
                        "description": c.description,
                        "entry_ids": c.entry_ids,
                        "confidence": c.confidence,
                    }
                    for c in (cr.event_chains if cr else [])
                ],
                "timeline_gaps": [
                    {
                        "anomaly_id": a.anomaly_id,
                        "description": a.description,
                        "gap_start": a.gap_start,
                        "gap_end": a.gap_end,
                        "gap_type": a.gap_type,
                    }
                    for a in (cr.timeline_gaps if cr else [])
                ],
                "semantic_clusters": [
                    {
                        "cluster_id": sc.cluster_id,
                        "label": sc.label,
                        "finding_ids": sc.finding_ids,
                        "reasoning": sc.reasoning,
                    }
                    for sc in self.semantic_result.clusters
                ],
            },
            "failed_approaches": [
                {"tool": fa.tool, "failure": fa.failure, "lesson": fa.lesson}
                for fa in self.progress.progress.failed_approaches
            ],
            "strategy_pivots": [
                {"from": sp.from_strategy, "to": sp.to_strategy, "reason": sp.reason}
                for sp in self.progress.progress.strategy_pivots
            ],
            "status": self.progress.progress.status,
            # Empty on a clean run; populated with the failure message when the
            # run crashed partway through so the report explains why.
            "error": getattr(self, "_run_error", ""),
            "tool_compatibility": self.advisor.matrix(),
            "audit_log": str(self.output_dir / "audit.jsonl"),
        }
