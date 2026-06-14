"""Generates structured forensic reports from investigation results.

Produces both JSON (machine-readable) and Markdown (human-readable)
reports. Every finding includes evidence links traceable to specific
tool executions in the audit log.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportGenerator:
    """Renders investigation results into formatted reports.

    Usage:
        gen = ReportGenerator(report_data, audit_events)
        gen.write_markdown("/output/report.md")
    """

    def __init__(
        self,
        report: dict[str, Any],
        audit_events: list[dict[str, Any]] | None = None,
    ) -> None:
        self.report = report
        self.audit_events = audit_events or []

    @classmethod
    def from_files(
        cls,
        report_path: str | Path,
        audit_path: str | Path | None = None,
    ) -> "ReportGenerator":
        with open(report_path) as f:
            report = json.load(f)

        events = []
        if audit_path and Path(audit_path).exists():
            with open(audit_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))

        return cls(report, events)

    def write_markdown(self, output_path: str | Path) -> None:
        """Write a human-readable Markdown report."""
        md = self._render_markdown()
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(md)

    def _render_markdown(self) -> str:
        r = self.report
        lines: list[str] = []
        self._render_header(r, lines)
        self._render_summary(r, lines)
        self._render_hypotheses(r, lines)
        self._render_findings(r, lines)
        self._render_verification(r, lines)
        self._render_iocs(r, lines)
        self._render_timeline(r, lines)
        self._render_failed_approaches(r, lines)
        self._render_limitations(r, lines)
        self._render_pivots(r, lines)
        self._render_accuracy(r, lines)
        self._render_scoring(r, lines)
        self._render_audit_trail(r, lines)
        return "\n".join(lines)

    def _render_header(self, r: dict, lines: list[str]) -> None:
        lines.append("# Forensic Investigation Report")
        lines.append("")
        lines.append(f"**Investigation ID:** {r.get('investigation_id', 'N/A')}")
        lines.append(f"**Evidence:** `{r.get('evidence_path', 'N/A')}`")
        lines.append(f"**Evidence Type:** {r.get('evidence_type', 'N/A')}")
        lines.append(f"**Timestamp:** {r.get('timestamp', 'N/A')}")
        lines.append(f"**Status:** {r.get('status', 'N/A')}")
        lines.append(f"**Rounds Completed:** {r.get('rounds_completed', 0)}")
        lines.append("")
        if r.get("findings_unverified"):
            lines.append(
                "> **WARNING - TRIAGE-ONLY:** This is a partial run. The findings "
                "below were not verified and must not be relied on at parity with "
                "a completed, verified investigation."
            )
            lines.append("")

    def _render_summary(self, r: dict, lines: list[str]) -> None:
        findings = r.get("findings", [])
        iocs = r.get("iocs", [])
        confirmed = [f for f in findings if f.get("confidence") == "confirmed"]
        inferred = [f for f in findings if f.get("confidence") == "inferred"]
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(
            f"Investigation analyzed `{r.get('evidence_path')}` over "
            f"{r.get('rounds_completed', 0)} rounds. "
            f"Found {len(findings)} findings ({len(confirmed)} confirmed, "
            f"{len(inferred)} inferred) and {len(iocs)} IOCs."
        )
        lines.append("")

    def _render_hypotheses(self, r: dict, lines: list[str]) -> None:
        hypotheses = r.get("hypotheses", [])
        if not hypotheses:
            return
        lines.append("## Hypotheses")
        lines.append("")
        status_labels = {
            "supported": "SUPPORTED",
            "refuted": "REFUTED",
            "active": "ACTIVE",
            "inconclusive": "INCONCLUSIVE",
        }
        for h in hypotheses:
            label = status_labels.get(h["status"], h["status"].upper())
            lines.append(f"### {h['id']}: {h['description']}")
            lines.append(f"**Status:** {label}")
            if h.get("evidence_for"):
                lines.append("**Evidence for:**")
                for e in h["evidence_for"]:
                    lines.append(f"- {e}")
            if h.get("evidence_against"):
                lines.append("**Evidence against:**")
                for e in h["evidence_against"]:
                    lines.append(f"- {e}")
            lines.append("")

    def _render_findings(self, r: dict, lines: list[str]) -> None:
        findings = r.get("findings", [])
        if not findings:
            return
        lines.append("## Findings")
        lines.append("")
        for i, f in enumerate(findings, 1):
            # A triage-only finding (run cut short before/around verification) is
            # always rendered as not-verified, even if its serialized ``verified``
            # flag is True from a verification pass the partial run later
            # invalidated. Suppressing the "(verified: ...)" suffix here keeps the
            # heading tag and the confidence line telling one consistent story.
            is_triage_only = f.get("verification_state") == "triage_only"
            verified_text = ""
            if f.get("verified") and not is_triage_only:
                verified_text = f" (verified: {f.get('verification_verdict', 'N/A')})"
            triage_tag = ""
            if is_triage_only:
                triage_tag = " **[TRIAGE-ONLY - not verified]**"
            lines.append(f"### Finding {i}: {f['description']}{triage_tag}")
            lines.append(f"**Confidence:** {f['confidence']}{verified_text}")
            lines.append(f"**Agent:** {f.get('agent', 'N/A')}")
            if f.get("ioc_type"):
                lines.append(f"**IOC:** {f['ioc_type']} = `{f.get('ioc_value', '')}`")
            if f.get("evidence_links"):
                lines.append(
                    f"**Evidence:** execution IDs {', '.join(f['evidence_links'])}"
                )
                # Show the exact command, exit code, and execution id behind each
                # evidence link so a reviewer can reproduce how the finding was
                # made. The per-execution dict stores the tool path and args
                # separately; join them into a runnable command line.
                for link in f.get("evidence_links", []):
                    ex = r.get("executions", {}).get(link)
                    if ex:
                        cmd = " ".join([ex.get("tool", "")] + ex.get("args", []))
                        lines.append(
                            f"- `{cmd}`  (exit {ex.get('exit_code', '?')}, exec {link})"
                        )
                    else:
                        lines.append(f"- exec {link}")
            lines.append("")

    def _render_verification(self, r: dict, lines: list[str]) -> None:
        findings = r.get("findings", [])
        verified = [f for f in findings if f.get("verified")]
        self_corrections = [
            e for e in self.audit_events if e.get("event_type") == "self_correction"
        ]
        if not verified and not self_corrections:
            return
        lines.append("## Verification & Self-Correction")
        lines.append("")
        if verified:
            lines.append("| Finding | Verdict | Rounds | Cross-domain corroboration |")
            lines.append("|---------|---------|--------|----------------------------|")
            for f in verified:
                corro = f.get("corroboration_count", 0)
                corro_ids = ", ".join(f.get("corroboration_ids", [])) or "—"
                lines.append(
                    f"| {f.get('finding_id', 'N/A')} "
                    f"| {f.get('verification_verdict', 'N/A')} "
                    f"| {f.get('verification_rounds', 1)} "
                    f"| {corro} ({corro_ids}) |"
                )
            lines.append("")
        multi = [f for f in verified if f.get("verification_rounds", 1) > 1]
        lines.append(
            f"- Findings challenged: {len(verified)} "
            f"({len(multi)} required multiple rounds)"
        )
        lines.append(f"- Self-corrections recorded: {len(self_corrections)}")
        for e in self_corrections:
            lines.append(
                f"  - {e.get('finding_id')}: {e.get('previous_confidence')} -> "
                f"{e.get('new_confidence')} (verdict {e.get('verdict')}, "
                f"{e.get('rounds_taken')} rounds)"
            )
        lines.append("")

    def _render_iocs(self, r: dict, lines: list[str]) -> None:
        iocs = r.get("iocs", [])
        if not iocs:
            return
        lines.append("## Indicators of Compromise")
        lines.append("")
        lines.append("| Type | Value |")
        lines.append("|------|-------|")
        for ioc in iocs:
            lines.append(f"| {ioc['type']} | `{ioc['value']}` |")
        lines.append("")

    def _render_timeline(self, r: dict, lines: list[str]) -> None:
        correlation = r.get("correlation", {})
        timeline = correlation.get("timeline", [])
        chains = correlation.get("event_chains", [])
        timeline_gaps = correlation.get("timeline_gaps", [])
        semantic = correlation.get("semantic_clusters", [])

        if not timeline and not chains and not timeline_gaps and not semantic:
            return

        lines.append("## Attack Timeline")
        lines.append("")

        if timeline:
            lines.append("| Time (UTC) | Artifact | Description |")
            lines.append("|------------|----------|-------------|")
            for entry in timeline:
                lines.append(
                    f"| {entry['timestamp']} | {entry['artifact_type']} "
                    f"| {entry['description']} |"
                )
            lines.append("")

        if chains:
            lines.append("### Event Chains")
            lines.append("")
            for chain in chains:
                lines.append(
                    f"- **{chain['chain_id']}** ({chain['confidence']}): "
                    f"{chain['description']}"
                )
            lines.append("")

        if timeline_gaps:
            lines.append("### Timeline Gaps")
            lines.append("")
            for gap in timeline_gaps:
                lines.append(
                    f"- **{gap['anomaly_id']}** [{gap['gap_type']}]: "
                    f"{gap['description']} "
                    f"({gap['gap_start']} — {gap['gap_end']})"
                )
            lines.append("")

        if semantic:
            lines.append("### Semantic Activity Groups")
            lines.append("")
            for sc in semantic:
                ids = ", ".join(sc["finding_ids"])
                lines.append(f"- **{sc['label']}** ({ids})")
                if sc.get("reasoning"):
                    lines.append(f"  - {sc['reasoning']}")
            lines.append("")

    def _render_failed_approaches(self, r: dict, lines: list[str]) -> None:
        failed = r.get("failed_approaches", [])
        if not failed:
            return
        lines.append("## Failed Approaches")
        lines.append("")
        for fa in failed:
            lines.append(f"- **{fa['tool']}**: {fa['failure']}")
            lines.append(f"  Lesson: {fa['lesson']}")
        lines.append("")

    def _render_limitations(self, r: dict, lines: list[str]) -> None:
        """Render claims that could not be backed by a successful tool execution
        and tool/environment notes, so they are visible without being presented
        as findings. Omitted entirely when there are none."""
        lims = r.get("limitations", [])
        if not lims:
            return
        lines.append("## Limitations")
        lines.append("")
        for lim in lims:
            lines.append(f"- {lim}")
        lines.append("")

    def _render_pivots(self, r: dict, lines: list[str]) -> None:
        pivots = r.get("strategy_pivots", [])
        if not pivots:
            return
        lines.append("## Strategy Pivots")
        lines.append("")
        for sp in pivots:
            lines.append(f"- From: {sp['from']}")
            lines.append(f"  To: {sp['to']}")
            lines.append(f"  Reason: {sp['reason']}")
        lines.append("")

    def _render_accuracy(self, r: dict, lines: list[str]) -> None:
        findings = r.get("findings", [])
        confirmed = [f for f in findings if f.get("confidence") == "confirmed"]
        inferred = [f for f in findings if f.get("confidence") == "inferred"]
        possible = [f for f in findings if f.get("confidence") == "possible"]
        verified = [f for f in findings if f.get("verified")]
        refuted = [f for f in findings if f.get("verification_verdict") == "refuted"]
        lines.append("## Accuracy Metadata")
        lines.append("")
        lines.append(f"- Total findings: {len(findings)}")
        lines.append(f"- Confirmed (direct evidence): {len(confirmed)}")
        lines.append(f"- Inferred (correlated): {len(inferred)}")
        lines.append(f"- Possible (weak signal): {len(possible)}")
        lines.append(f"- Verified by challenger agent: {len(verified)}")
        lines.append(f"- Refuted by challenger (removed from report): {len(refuted)}")
        lines.append("")

    def _render_scoring(self, r: dict, lines: list[str]) -> None:
        score = r.get("accuracy_score")
        if not score:
            return
        self._render_scoring_header(score, lines)
        self._render_scoring_confidence(score, lines)
        self._render_scoring_misses(score, lines)
        self._render_scoring_extras(score, lines)
        self._render_scoring_hallucinations(score, lines)
        self._render_scoring_comparison(r, lines)

    def _render_scoring_header(self, score: dict, lines: list[str]) -> None:
        lines.append("## Accuracy & Scoring (vs Ground Truth)")
        lines.append("")
        lines.append(f"- Baseline: `{score.get('baseline_id', 'N/A')}`")
        lines.append(
            f"- Agent findings: {score.get('total_agent_findings', 0)}; "
            f"baseline required: {score.get('required_baseline_findings', 0)}"
        )
        lines.append(f"- Precision: {score.get('precision', 0):.3f}")
        lines.append(f"- Recall: {score.get('recall', 0):.3f}")
        lines.append(f"- F1: {score.get('f1', 0):.3f}")
        lines.append(
            f"- Hallucination rate (uncaught): {score.get('hallucination_rate', 0):.3f}"
        )
        lines.append("")

    def _render_scoring_confidence(self, score: dict, lines: list[str]) -> None:
        breakdown = score.get("confirmed_vs_inferred", {}) or {}
        if not breakdown:
            return
        lines.append("### Confidence Breakdown (Criterion 2: direct vs inferred)")
        lines.append("")
        lines.append(f"- Confirmed (direct evidence): {breakdown.get('confirmed', 0)}")
        lines.append(f"- Inferred (correlated): {breakdown.get('inferred', 0)}")
        lines.append(f"- Possible (weak signal): {breakdown.get('possible', 0)}")
        if breakdown.get("other"):
            lines.append(f"- Other: {breakdown['other']}")
        lines.append("")

    def _render_scoring_misses(self, score: dict, lines: list[str]) -> None:
        missed = score.get("missed_baseline_findings", []) or []
        if not missed:
            return
        lines.append("### Missed Artifacts (in ground truth, agent did not find)")
        lines.append("")
        for bid in missed:
            lines.append(f"- {bid}")
        lines.append("")

    def _render_scoring_extras(self, score: dict, lines: list[str]) -> None:
        extras = score.get("extra_findings", []) or []
        if not extras:
            return
        lines.append("### False Positives (agent reported, not in ground truth)")
        lines.append("")
        for fid in extras:
            lines.append(f"- {fid}")
        lines.append("")

    def _render_scoring_hallucinations(self, score: dict, lines: list[str]) -> None:
        flagged = score.get("hallucinations_flagged", []) or []
        caught = score.get("hallucinations_caught_by_verifier", []) or []
        if not flagged and not caught:
            return
        lines.append(
            "### Hallucinated Claims (no backing tool_execution in audit.jsonl)"
        )
        lines.append("")
        if flagged:
            for h in flagged:
                lines.append(f"- {h.get('finding_id', 'N/A')}: {h.get('reason', '')}")
        else:
            lines.append("- None (every finding traces back to a real tool execution)")
        lines.append("")
        lines.append(f"### Hallucinations Caught by Verifier (credit): {len(caught)}")
        lines.append("")
        for h in caught:
            lines.append(f"- {h.get('finding_id', 'N/A')}: {h.get('reason', '')}")
        if caught:
            lines.append("")

    def _render_scoring_comparison(self, r: dict, lines: list[str]) -> None:
        comp = r.get("baseline_comparison")
        if not comp:
            return
        verdict = "PASS" if comp.get("passes") else "FAIL"
        lines.append("### Head-to-Head vs Reference Agent")
        lines.append("")
        lines.append(f"**Result:** {verdict} (lower hallucination rate wins)")
        lines.append("")
        lines.append(
            "| Metric | Subject | Reference | Delta (subject - reference) |"
        )
        lines.append("|--------|---------|-----------|------------------------|")
        lines.append(
            f"| Hallucination rate | {comp.get('subject_hallucination_rate', 0):.3f} "
            f"| {comp.get('reference_hallucination_rate', 0):.3f} "
            f"| {-comp.get('hallucination_delta', 0):.3f} |"
        )
        lines.append(
            f"| Precision | {comp.get('subject_precision', 0):.3f} "
            f"| {comp.get('reference_precision', 0):.3f} "
            f"| {comp.get('precision_delta', 0):+.3f} |"
        )
        lines.append(
            f"| Recall | {comp.get('subject_recall', 0):.3f} "
            f"| {comp.get('reference_recall', 0):.3f} "
            f"| {comp.get('recall_delta', 0):+.3f} |"
        )
        lines.append(
            f"| F1 | {comp.get('subject_f1', 0):.3f} "
            f"| {comp.get('reference_f1', 0):.3f} "
            f"| {comp.get('f1_delta', 0):+.3f} |"
        )
        lines.append("")

    def _render_audit_trail(self, r: dict, lines: list[str]) -> None:
        lines.append("## Audit Trail")
        lines.append("")
        lines.append(f"Full execution log: `{r.get('audit_log', 'audit.jsonl')}`")
        lines.append("")
        exec_events = [
            e for e in self.audit_events if e.get("event_type") == "tool_execution"
        ]
        msg_events = [
            e for e in self.audit_events if e.get("event_type") == "agent_message"
        ]
        lines.append(f"- Tool executions logged: {len(exec_events)}")
        lines.append(f"- Agent messages logged: {len(msg_events)}")
        lines.append(f"- Total audit events: {len(self.audit_events)}")
        lines.append("")
