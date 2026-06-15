"""CLI entry point for agentic-sift.

Usage:
    python -m cli.main investigate --evidence /cases/image.E01 --type disk
    python -m cli.main score --report report.json --baseline baselines/sample-case.json
    python -m cli.main compare-agents --report subject/report.json --reference-report reference/report.json
    python -m cli.main refresh  # build/update the local tool catalog for this box
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Cap on concurrent enrichment workers during `refresh`. Enrichment is one
# independent, LLM-bound (~2-4s) call per tool, so running them concurrently
# turns a ~30-min serial first build (~277 tools) into ~3-6 min. Mirrors the
# orchestrator's _MAX_PARALLEL_SUB_AGENTS so claude/auth load stays bounded.
_MAX_ENRICH_WORKERS = 10

# sys.path setup required for standalone execution on SIFT workstations
# (standalone project — no build system on the analysis host).
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from accuracy.baseline import load_baseline
from accuracy.baseline_comparator import compare_against_baseline
from accuracy.scorer import AccuracyScore, score_report
from evidence.ssh_runner import SshPrivilegedRunner
from evidence.view import EvidenceSpec
from executor.runner import LocalExecutor, SSHExecutor
from orchestrator.investigator import Investigator
from report.generator import ReportGenerator
from tool_registry import catalog as catalog_mod

logger = logging.getLogger(__name__)


def _today_iso() -> str:
    """UTC date as YYYY-MM-DD (for staleness reporting)."""
    return time.strftime("%Y-%m-%d", time.gmtime())


def _now_iso() -> str:
    """UTC timestamp as an ISO-8601 string (for catalog/provenance stamps)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _missing_catalog_message(cat_path: Path) -> str:
    """Instruct-then-exit copy for a missing catalog (names the cwd path)."""
    return (
        f"No tool catalog found. Looked for: {cat_path} (current directory).\n"
        "Run `agentic-sift refresh` first — it scans the forensic tools "
        "installed on this machine and builds a local tool catalog "
        "(./tool_catalog.json) here in the current directory. This is a one-time "
        "setup; re-run `refresh` whenever the installed tools change.\n"
        "(Or point at a catalog elsewhere with `--catalog PATH` on both "
        "`refresh` and `investigate`.)"
    )


def load_catalog_tools(catalog_arg: str | None) -> tuple[list[dict], Path]:
    """Resolve the catalog path and return ``(tools, catalog_path)``.

    The catalog is CWD-relative by default (``./tool_catalog.json``), overridable
    with ``--catalog``. On a missing catalog this prints the instruct-then-exit
    message and exits non-zero — there is NO shipped seed to fall back on.
    """
    cat_path = catalog_mod.catalog_path(catalog_arg)
    try:
        tools = catalog_mod.load_tool_inventory(cat_path)
    except catalog_mod.CatalogMissing:
        print(_missing_catalog_message(cat_path), file=sys.stderr)
        sys.exit(2)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    return tools, cat_path


def _print_staleness(cat_path: Path) -> None:
    """Best-effort 'tools last refreshed ...' line; never fatal."""
    try:
        meta = catalog_mod.load_catalog(cat_path).get("metadata", {})
        st = catalog_mod.staleness(meta, today_iso=_today_iso())
    except Exception:
        return
    if not st.get("refreshed_at"):
        return
    days = st.get("days_since")
    when = st["refreshed_at"]
    suffix = f" ({days} days ago)" if days is not None else ""
    print(f"tools last refreshed {when}{suffix}")


def build_executor(
    tools: list[dict],
    evidence_roots: list[str],
    remote: str | None = None,
    output_dir: str | None = None,
    remote_user: str | None = None,
    scratch_dir: str | None = None,
) -> LocalExecutor | SSHExecutor:
    """Build the appropriate executor based on mode.

    The default is the local, single-machine run (``remote`` unset). Remote
    execution is an optional development convenience: it requires the caller to
    supply every connection detail explicitly — ``remote`` as ``HOST:PORT`` (the
    port is mandatory; there is no assumed default) and ``remote_user`` (the SSH
    login). No environment-specific host, port, or user is baked in.

    When ``output_dir`` is set, the executor writes each command's raw
    stdout/stderr there, so every finding can be traced back to the exact
    output that produced it. Left unset, no per-command output is persisted.
    """

    allowed = {}
    for t in tools:
        if "path" not in t:
            continue
        allowed[t["path"]] = t["name"]
        if t.get("symlink"):
            allowed[t["symlink"]] = t["name"]

    if remote:
        parts = remote.split(":")
        host = parts[0]
        if len(parts) < 2 or parts[1] == "":
            print(
                f"Error: --remote '{remote}' must include an explicit port "
                "(HOST:PORT). There is no default remote port.",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            port = int(parts[1])
        except ValueError:
            print(
                f"Error: Invalid port in --remote '{remote}'. Expected HOST:PORT.",
                file=sys.stderr,
            )
            sys.exit(1)
        if not remote_user:
            print(
                "Error: remote execution requires --remote-user (the SSH login). "
                "There is no default remote user.",
                file=sys.stderr,
            )
            sys.exit(1)
        return SSHExecutor(
            allowed_tools=allowed,
            evidence_roots=evidence_roots,
            host=host,
            port=port,
            user=remote_user,
            output_dir=output_dir,
            scratch_dir=scratch_dir,
        )
    else:
        return LocalExecutor(
            allowed_tools=allowed,
            evidence_roots=evidence_roots,
            output_dir=output_dir,
            scratch_dir=scratch_dir,
        )


def build_remote_mount_runner(remote: str | None, remote_user: str | None):
    """Build the SSH-backed privileged mount runner for the dev remote mode.

    Returns ``None`` (use the local mount path) unless a remote HOST:PORT is
    given. When present, the read-only mount is performed on the remote tool host
    over SSH instead of on the local machine, so the forensic tools running there
    can see the mounted filesystem. The caller must supply every connection
    detail explicitly — the port (no default) and the SSH login — so no
    environment-specific value is assumed. Development-only scaffolding; the
    shipped single-machine path leaves this ``None`` and mounts locally.
    """
    if not remote:
        return None

    parts = remote.split(":")
    host = parts[0]
    if len(parts) < 2 or parts[1] == "":
        print(
            f"Error: --remote-mount '{remote}' must include an explicit port "
            "(HOST:PORT). There is no default remote port.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        port = int(parts[1])
    except ValueError:
        print(
            f"Error: Invalid port in --remote-mount '{remote}'. Expected HOST:PORT.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not remote_user:
        print(
            "Error: --remote-mount requires --remote-user (the SSH login). "
            "There is no default remote user.",
            file=sys.stderr,
        )
        sys.exit(1)
    return SshPrivilegedRunner(host=host, port=port, user=remote_user)


def build_evidence_specs(
    evidence: list[str], types: list[str] | None
) -> list[EvidenceSpec]:
    """Pair evidence paths with their types into EvidenceSpecs.

    Paths and types are matched by position. Any path without a corresponding
    type defaults to ``disk`` (the common single-image case). Supplying more
    types than paths is a usage error and exits. Several specs let one
    investigation span, for example, a disk image and a memory capture of the
    same host so their findings correlate.
    """
    types = types or []
    if len(types) > len(evidence):
        print(
            "Error: more --type values than --evidence values "
            f"({len(types)} types, {len(evidence)} evidence)",
            file=sys.stderr,
        )
        sys.exit(1)
    specs = []
    for i, path in enumerate(evidence):
        etype = types[i] if i < len(types) else "disk"
        specs.append(EvidenceSpec(path=path, evidence_type=etype))
    return specs


def _print_investigation_summary(report: dict, output_dir: str) -> None:
    """Print the human-readable investigation summary to stdout."""
    print("\n" + "=" * 60)
    print("INVESTIGATION COMPLETE")
    print("=" * 60)
    print(f"Status: {report['status']}")
    print(f"Rounds: {report['rounds_completed']}")
    print(f"Findings: {len(report['findings'])}")
    print(f"IOCs: {len(report['iocs'])}")

    if report["findings"]:
        print("\nFindings:")
        for f in report["findings"]:
            verified = (
                f" [verified: {f['verification_verdict']}]" if f["verified"] else ""
            )
            print(f"  [{f['confidence']}]{verified} {f['description']}")

    if report["iocs"]:
        print("\nIOCs:")
        for ioc in report["iocs"]:
            print(f"  {ioc['type']}: {ioc['value']}")

    print(f"\nFull report: {output_dir}/report.json")
    print(f"Audit log: {output_dir}/audit.jsonl")
    print(f"Progress: {output_dir}/progress.json")

    score = report.get("accuracy_score")
    if score:
        print(
            f"\nAccuracy vs baseline `{score['baseline_id']}`: "
            f"precision={score['precision']:.3f} "
            f"recall={score['recall']:.3f} "
            f"F1={score['f1']:.3f} "
            f"hallucination_rate={score['hallucination_rate']:.3f}"
        )
        print(f"Markdown report: {output_dir}/report.md")


def _apply_fast_mode(args: argparse.Namespace) -> None:
    """Dial the investigation down for a fast run (env read at use-time).

    Sets aggressive speed defaults (overridable by an already-set env var) and
    caps rounds. The big lever is still per-domain tool scoping in the catalog;
    these trim the fan-out, the verification tail, and the stuck-call timeout.
    """
    os.environ.setdefault("AGENTIC_SIFT_MAX_HYPOTHESES", "3")
    os.environ.setdefault("AGENTIC_SIFT_VERIFIER_ROUNDS", "1")
    os.environ.setdefault("AGENTIC_SIFT_MAX_STEPS", "3")
    os.environ.setdefault("AGENTIC_SIFT_MAX_PARALLEL", "16")
    os.environ.setdefault("AGENTIC_SIFT_VERIFY_HIGH_VALUE_ONLY", "1")
    os.environ.setdefault("AGENTIC_SIFT_LLM_TIMEOUT", "120")
    if args.max_rounds > 2:
        args.max_rounds = 2
    print(
        "Fast mode: <=2 rounds, 3 hypotheses, 1 verifier round, "
        "high-value-only verify, 16-wide, 120s LLM timeout"
    )


def _acquire_local_sudo_password() -> str | None:
    """Collect (and verify) a sudo password for the local read-only mount.

    Run as the first step of a local investigation so a password-protected sudo
    (e.g. the SANS SIFT default user, password ``forensics``) is handled up front
    instead of failing deep into the evidence mount. Resolution order:

      1. ``AGENTIC_SIFT_SUDO_PASSWORD`` env var (non-interactive / CI). An empty
         value means "use passwordless sudo".
      2. An interactive ``getpass`` prompt (press Enter to use passwordless sudo).

    The candidate is verified with ``sudo -S -v`` before the run starts; an
    interactive user gets up to 3 attempts. Returns the verified password, or
    None to fall back to passwordless ``sudo -n`` (NOPASSWD sudoers or already
    cached credentials).
    """
    import getpass
    import subprocess

    def _verify(pw: str) -> bool:
        try:
            proc = subprocess.run(
                ["sudo", "-S", "-p", "", "-v"],
                input=(pw + "\n").encode(),
                capture_output=True,
                timeout=30,
            )
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    env_pw = os.environ.get("AGENTIC_SIFT_SUDO_PASSWORD")
    if env_pw is not None:
        if env_pw == "":
            return None
        if _verify(env_pw):
            print("[agentic-sift] sudo password accepted (from environment).")
            return env_pw
        print(
            "[agentic-sift] WARNING: AGENTIC_SIFT_SUDO_PASSWORD was rejected by "
            "sudo; falling back to passwordless sudo.",
            file=sys.stderr,
        )
        return None

    if not sys.stdin.isatty():
        # Non-interactive with no env password: use passwordless sudo.
        return None

    for remaining in (2, 1, 0):
        try:
            pw = getpass.getpass(
                "[agentic-sift] sudo password for the read-only evidence mount "
                "(press Enter for passwordless sudo): "
            )
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if pw == "":
            return None
        if _verify(pw):
            print("[agentic-sift] sudo password accepted.")
            return pw
        if remaining:
            print(
                f"[agentic-sift] Sorry, try again ({remaining} left).",
                file=sys.stderr,
            )
    print(
        "[agentic-sift] WARNING: no valid sudo password; falling back to "
        "passwordless sudo (the evidence mount may fail).",
        file=sys.stderr,
    )
    return None


def cmd_investigate(args: argparse.Namespace) -> None:
    """Run a forensic investigation."""

    if getattr(args, "fast", False):
        _apply_fast_mode(args)

    # First step: for a LOCAL investigation, collect (and verify) any sudo
    # password needed to mount the evidence read-only. The dev remote-mount mode
    # mounts on the remote host over SSH, so this is skipped there.
    local_sudo_password = None
    if not getattr(args, "remote_mount", None):
        local_sudo_password = _acquire_local_sudo_password()

    tools, cat_path = load_catalog_tools(args.catalog)
    _print_staleness(cat_path)
    print(f"Loaded {len(tools)} tools from catalog ({cat_path})")

    # Evidence roots are READ locations only. Tool OUTPUT goes to a dedicated
    # scratch directory (below), which is always allowlisted regardless of these
    # roots — so the read surface stays tight and no ad-hoc /tmp entry is needed.
    evidence_roots = (
        args.evidence_roots.split(",")
        if args.evidence_roots
        else [
            "/cases",
            "/evidence",
        ]
    )

    output_dir = args.output or f"./output/inv-{int(time.time())}"

    # Where tools may WRITE their output. Tools run on the execution host, so the
    # scratch dir lives there: a path inside the remote VM under --remote, or
    # co-located with the run's output for a local run. The path is made unique
    # per run (keyed by the run's output directory name) so concurrent
    # investigations against the same VM never write to a shared scratch and
    # clobber each other's timeline.plaso / extracted files. ensure_scratch()
    # creates it on that host before any sub-agent runs.
    run_id = Path(output_dir).name
    scratch_dir = (
        f"/tmp/agentic-sift-scratch/{run_id}"
        if args.remote
        else str(Path(output_dir) / "scratch")
    )

    # Persist each command's raw stdout/stderr under the run's output directory so
    # every finding's underlying command output is saved and reproducible.
    executor = build_executor(
        tools,
        evidence_roots,
        args.remote,
        output_dir=str(Path(output_dir) / "outputs"),
        remote_user=args.remote_user,
        scratch_dir=scratch_dir,
    )
    executor.ensure_scratch()

    # Development-only: when --remote-mount is set, the read-only disk-image
    # mount is performed on the remote tool host over SSH (so the tools there can
    # read it), rather than on this machine. Absent the flag, the runner stays
    # None and the local mount path is used unchanged.
    mount_runner = None
    if getattr(args, "remote_mount", None):
        mount_runner = build_remote_mount_runner(args.remote_mount, args.remote_user)
    elif local_sudo_password is not None:
        # Local mount using the supplied sudo password (sudo -S). With no
        # password supplied, mount_runner stays None and the default passwordless
        # (sudo -n) local runner is used unchanged.
        from evidence.session import SubprocessPrivilegedRunner

        mount_runner = SubprocessPrivilegedRunner(sudo_password=local_sudo_password)

    focus = args.focus.split(",") if args.focus else None

    if args.brief and args.brief_file:
        print(
            "Error: --brief and --brief-file are mutually exclusive",
            file=sys.stderr,
        )
        sys.exit(1)
    brief = args.brief
    if args.brief_file:
        brief_path = Path(args.brief_file)
        if not brief_path.exists():
            print(f"Error: Brief file not found: {brief_path}", file=sys.stderr)
            sys.exit(1)
        brief = brief_path.read_text().strip()

    specs = build_evidence_specs(args.evidence, args.type)

    investigator = Investigator(
        executor=executor,
        registry_tools=tools,
        output_dir=output_dir,
        max_rounds=args.max_rounds,
        baseline_path=args.baseline,
        runner=mount_runner,
    )

    print("Starting investigation:")
    for spec in specs:
        print(f"  {spec.path} (type={spec.evidence_type})")
    print(f"Output: {output_dir}")
    if focus:
        print(f"Focus: {', '.join(focus)}")
    if brief:
        print(f"Brief: {brief[:100]}{'...' if len(brief) > 100 else ''}")
    print(f"Max rounds: {args.max_rounds}")
    print()

    try:
        report = investigator.investigate_evidence(
            specs,
            focus=focus,
            brief=brief,
        )
    finally:
        # Always reclaim the scratch dir (tool output can be many GB); leaving it
        # behind fills the execution host's disk across runs, after which every
        # mkdir fails and runs yield zero findings. Cleanup runs in finally, so a
        # cleanup error must be logged rather than propagated — otherwise it would
        # mask the investigation's own outcome (success or its real exception).
        try:
            executor.cleanup_scratch()
        except Exception:
            logger.warning("scratch cleanup failed", exc_info=True)

    _print_investigation_summary(report, output_dir)
    if report.get("status") == "errored" or report.get("report_write_failed"):
        sys.exit(1)


def _load_audit_events(audit_path: Path) -> list[dict]:
    """Read a JSONL audit log; returns an empty list if it doesn't exist."""
    if not audit_path.exists():
        return []
    events: list[dict] = []
    with open(audit_path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def cmd_score(args: argparse.Namespace) -> None:
    """Score a report against a baseline and write the scored report."""
    report_path = Path(args.report)
    if not report_path.exists():
        print(f"Error: report not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    audit_path = Path(args.audit) if args.audit else report_path.parent / "audit.jsonl"
    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        print(f"Error: baseline not found: {baseline_path}", file=sys.stderr)
        sys.exit(1)

    with open(report_path) as f:
        report = json.load(f)
    audit_events = _load_audit_events(audit_path)
    baseline = load_baseline(baseline_path)

    score = score_report(report, audit_events, baseline)
    report["accuracy_score"] = score.to_dict()

    output_path = Path(args.output) if args.output else report_path
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    md_path = output_path.with_suffix(".md")
    ReportGenerator(report, audit_events).write_markdown(md_path)

    print(
        f"Scored against `{baseline.case_id}`: "
        f"precision={score.precision:.3f} recall={score.recall:.3f} "
        f"F1={score.f1:.3f} hallucination_rate={score.hallucination_rate:.3f}"
    )
    print(
        f"Missed: {len(score.missed_baseline_findings)} | "
        f"Extra: {len(score.extra_findings)} | "
        f"Flagged hallucinations: {len(score.hallucinations_flagged)} | "
        f"Caught by verifier: {len(score.hallucinations_caught_by_verifier)}"
    )
    print(f"Scored report: {output_path}")
    print(f"Markdown report: {md_path}")


def cmd_compare_agents(args: argparse.Namespace) -> None:
    """Compare two scored reports head-to-head (e.g. subject vs Protocol SIFT)."""
    subject_path = Path(args.report)
    reference_path = Path(args.reference_report)
    for p, label in [
        (subject_path, "--report"),
        (reference_path, "--reference-report"),
    ]:
        if not p.exists():
            print(f"Error: {label} not found: {p}", file=sys.stderr)
            sys.exit(1)

    with open(subject_path) as f:
        subject_report = json.load(f)
    with open(reference_path) as f:
        reference_report = json.load(f)

    if (
        "accuracy_score" not in subject_report
        or "accuracy_score" not in reference_report
    ):
        print(
            "Error: both reports must contain an `accuracy_score` block. "
            "Run `score` on each first.",
            file=sys.stderr,
        )
        sys.exit(1)

    subject = _score_from_dict(subject_report["accuracy_score"])
    reference = _score_from_dict(reference_report["accuracy_score"])
    comparison = compare_against_baseline(subject, reference)

    if args.output:
        subject_report["baseline_comparison"] = comparison.to_dict()
        with open(args.output, "w") as f:
            json.dump(subject_report, f, indent=2)
        print(f"Wrote comparison to {args.output}")

    verdict = "PASS" if comparison.passes else "FAIL"
    print(f"\nHead-to-head: {verdict} (lower hallucination rate wins)")
    print(
        f"  hallucination_rate: subject={comparison.subject_hallucination_rate:.3f} "
        f"reference={comparison.reference_hallucination_rate:.3f} "
        f"(delta={-comparison.hallucination_delta:+.3f})"
    )
    print(
        f"  precision: subject={comparison.subject_precision:.3f} "
        f"reference={comparison.reference_precision:.3f} "
        f"(delta={comparison.precision_delta:+.3f})"
    )
    print(
        f"  recall:    subject={comparison.subject_recall:.3f} "
        f"reference={comparison.reference_recall:.3f} "
        f"(delta={comparison.recall_delta:+.3f})"
    )
    print(
        f"  F1:        subject={comparison.subject_f1:.3f} "
        f"reference={comparison.reference_f1:.3f} "
        f"(delta={comparison.f1_delta:+.3f})"
    )


def _score_from_dict(d: dict) -> AccuracyScore:
    """Rebuild an AccuracyScore from a serialized dict (for compare-agents)."""
    return AccuracyScore(
        baseline_id=d.get("baseline_id", ""),
        total_agent_findings=d.get("total_agent_findings", 0),
        total_baseline_findings=d.get("total_baseline_findings", 0),
        required_baseline_findings=d.get("required_baseline_findings", 0),
        precision=d.get("precision", 0.0),
        recall=d.get("recall", 0.0),
        f1=d.get("f1", 0.0),
        hallucination_rate=d.get("hallucination_rate", 0.0),
        missed_baseline_findings=list(d.get("missed_baseline_findings", [])),
        extra_findings=list(d.get("extra_findings", [])),
        confirmed_vs_inferred=dict(d.get("confirmed_vs_inferred", {})),
        hallucinations_flagged=list(d.get("hallucinations_flagged", [])),
        hallucinations_caught_by_verifier=list(
            d.get("hallucinations_caught_by_verifier", [])
        ),
    )


def cmd_refresh(args: argparse.Namespace) -> None:
    """(Re)build the LOCAL tool catalog for THIS machine.

    Pipeline: enumerate installed tools -> diff against the existing catalog ->
    LLM-enrich only the new/changed tools (the LLM also marks non-forensic noise
    irrelevant) -> mark removed tools not-installed (kept for history) -> merge
    sticky human overrides on top -> write ``./tool_catalog.json`` (CWD-relative
    by default, or ``--catalog PATH``) and bump ``refreshed_at``. Unchanged
    entries are carried over verbatim so the catalog is byte-stable across runs.

    ``--seed-only`` enriches from existing descriptions only (skips live
    ``--help``/``man`` probing) for a faster, lower-fidelity build off-box.
    ``--dry-run`` reports the diff and writes nothing.
    """
    from tool_registry import enrich as enrich_mod
    from tool_registry import scanner as scanner_mod

    cat_path = catalog_mod.catalog_path(args.catalog)
    ov_path = catalog_mod.overrides_path(args.overrides)

    # Existing catalog (may be absent on a first build).
    try:
        existing = catalog_mod.load_tool_inventory(cat_path)
    except catalog_mod.CatalogMissing:
        existing = []

    enumerated = scanner_mod.enumerate_tools()
    new, changed, removed = scanner_mod.diff_catalog(enumerated, existing)

    if args.dry_run:
        print(
            f"Dry run — catalog {cat_path}: "
            f"{len(new)} new, {len(changed)} changed, {len(removed)} removed "
            f"(of {len(enumerated)} enumerated, {len(existing)} cataloged). "
            "Nothing written."
        )
        return

    # Start from the existing entries (byte-stable) keyed by name, then enrich
    # only the new/changed ones — never re-enrich unchanged tools.
    by_name: dict[str, dict] = {
        t["name"]: t for t in existing if t.get("name")
    }
    stamp = _now_iso()
    diff_tools = new + changed
    total = len(diff_tools)

    def _enrich_one(tool: dict) -> tuple[dict, dict | None]:
        """Worker: build signals + enrich ONE tool. Returns (tool, entry|None).

        Each worker only builds and returns its own local state (no shared
        mutation), so the pool is thread-safe; the merge below is single-writer.
        A per-tool failure degrades to ``(tool, None)`` and is logged — one bad
        tool never aborts the whole refresh. ``entry is None`` also covers the
        LLM relevance-filter (non-forensic noise).
        """
        try:
            if args.seed_only:
                bundle = {
                    "name": tool.get("name", ""),
                    "path": tool.get("path", ""),
                    "existing_description": tool.get("description", "") or "",
                    "help_text": "",
                    "man_text": "",
                    "pkg_desc": "",
                }
            else:
                bundle = enrich_mod.build_signal_bundle(tool)
            # Tools found in a forensic dir are forensic by location — trust them
            # past the relevance filter. Package-sourced candidates (bash/grep/…)
            # are relevance-checked by the man-page-grounded enricher.
            entry = enrich_mod.enrich_tool(
                tool, bundle, now=stamp,
                trust_relevant=(tool.get("source") == "dir"),
            )
        except Exception:
            logger.warning(
                "enrichment failed for %s — skipping", tool.get("name", "?"),
                exc_info=True,
            )
            return tool, None
        return tool, entry

    # Enrich the diff set concurrently; merge results single-threaded in
    # submission order so the catalog stays order-stable.
    enriched_count = 0
    dropped_count = 0
    if diff_tools:
        max_workers = min(_MAX_ENRICH_WORKERS, total)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            results = list(pool.map(_enrich_one, diff_tools))
        for tool, entry in results:
            name = tool.get("name", "")
            if entry is None:
                # Non-forensic noise or a failed enrichment — drop from catalog.
                by_name.pop(name, None)
                dropped_count += 1
                continue
            # Carry the scanner-known fields (probe provenance) onto the entry.
            entry.setdefault("package", tool.get("package", ""))
            entry.setdefault("version", tool.get("version", ""))
            entry["installed"] = True
            by_name[name] = entry
            enriched_count += 1
        print(f"enriched {enriched_count}/{total} (dropped {dropped_count})")

    # Removed tools: keep history but mark not-installed (the gate filters them).
    for r in removed:
        name = r.get("name")
        if name in by_name:
            by_name[name]["installed"] = False

    merged_list = list(by_name.values())

    # Sticky human overrides win per-field.
    overrides: dict = {}
    if ov_path.exists():
        try:
            overrides = json.loads(ov_path.read_text())
        except (OSError, ValueError) as exc:
            print(f"Warning: ignoring unreadable overrides {ov_path}: {exc}",
                  file=sys.stderr)
    final_tools = catalog_mod.merge_overrides(merged_list, overrides)

    catalog_obj = {
        "metadata": {
            "refreshed_at": stamp,
            "installed_hash": catalog_mod.installed_hash(enumerated),
            "tool_count": len(final_tools),
        },
        "tools": final_tools,
    }
    cat_path.parent.mkdir(parents=True, exist_ok=True)
    cat_path.write_text(json.dumps(catalog_obj, indent=2))

    print(
        f"Refresh complete: {enriched_count} enriched (new+changed), "
        f"{dropped_count} dropped as non-forensic, {len(removed)} marked removed; "
        f"{len(final_tools)} tools total."
    )
    print(f"Catalog: {cat_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agentic-sift",
        description="Agentic forensic analysis powered by Claude + SIFT",
    )
    sub = parser.add_subparsers(dest="command")

    # investigate
    inv = sub.add_parser("investigate", help="Run a forensic investigation")
    inv.add_argument(
        "--evidence",
        required=True,
        action="append",
        help="Path to an evidence file. Repeat to analyze several items of one "
        "host together (e.g. --evidence disk.E01 --evidence mem.raw).",
    )
    inv.add_argument(
        "--type",
        action="append",
        choices=["disk", "memory", "pcap", "logs"],
        help="Evidence type, paired by position with --evidence (default disk). "
        "Repeat once per --evidence (e.g. --type disk --type memory).",
    )
    inv.add_argument(
        "--remote",
        default=None,
        help="DEVELOPMENT ONLY: SSH remote as HOST:PORT (port required, no "
        "default). Omit for the normal local, single-machine run. Requires "
        "--remote-user.",
    )
    inv.add_argument(
        "--remote-mount",
        default=None,
        help="DEVELOPMENT ONLY (HOST:PORT): perform the read-only disk-image "
        "mount on a remote tool host over SSH, for the split setup where the "
        "reasoning code and the forensic tools run on different machines. Omit "
        "for the normal single-machine setup, which mounts locally.",
    )
    inv.add_argument(
        "--remote-user",
        default=None,
        help="SSH login for --remote / --remote-mount (development only). "
        "Required when either is used; no default.",
    )
    inv.add_argument(
        "--focus",
        default=None,
        help="Comma-separated focus areas (e.g., persistence,lateral-movement)",
    )
    inv.add_argument(
        "--brief",
        default=None,
        help="Case briefing — free-form context for the investigation "
        "(e.g., 'Insider threat: employee suspected of exfiltrating source code "
        "via USB before resignation on 2026-03-15')",
    )
    inv.add_argument(
        "--brief-file",
        default=None,
        help="Path to a text file containing the case briefing",
    )
    inv.add_argument(
        "--max-rounds", type=int, default=5, help="Maximum investigation rounds"
    )
    inv.add_argument(
        "--fast",
        action="store_true",
        help="Speed mode: fewer hypotheses/rounds, single verifier round, verify "
        "only high-value findings, shorter LLM timeout, higher parallelism. "
        "(Per-domain tool scoping in the catalog is the bigger lever — build it "
        "with `refresh`.)",
    )
    inv.add_argument("--output", default=None, help="Output directory")
    inv.add_argument(
        "--catalog",
        default=None,
        help="Path to the tool catalog JSON (default: ./tool_catalog.json in the "
        "current directory). Build it with `agentic-sift refresh`.",
    )
    inv.add_argument(
        "--evidence-roots",
        default=None,
        help="Comma-separated allowed evidence root paths",
    )
    inv.add_argument(
        "--baseline",
        default=None,
        help="Path to a ground-truth baseline JSON (enables accuracy scoring)",
    )

    # score
    sc = sub.add_parser(
        "score", help="Score an existing report against a ground-truth baseline"
    )
    sc.add_argument("--report", required=True, help="Path to report.json")
    sc.add_argument(
        "--baseline", required=True, help="Path to ground-truth baseline JSON"
    )
    sc.add_argument(
        "--audit",
        default=None,
        help="Path to audit.jsonl (default: alongside --report)",
    )
    sc.add_argument(
        "--output",
        default=None,
        help="Output path for the scored report (default: overwrite --report)",
    )

    # compare-agents
    cb = sub.add_parser(
        "compare-agents",
        help="Compare two scored reports head-to-head (e.g. vs Protocol SIFT)",
    )
    cb.add_argument(
        "--report", required=True, help="Path to the subject scored report.json"
    )
    cb.add_argument(
        "--reference-report",
        required=True,
        help="Path to reference agent's scored report.json (e.g. Protocol SIFT)",
    )
    cb.add_argument(
        "--output",
        default=None,
        help="Optional path to write the subject report augmented with "
        "`baseline_comparison`",
    )

    # refresh
    ref = sub.add_parser(
        "refresh", help="Build/update the local tool catalog for this machine"
    )
    ref.add_argument(
        "--catalog",
        default=None,
        help="Catalog path to read/write (default: ./tool_catalog.json in the "
        "current directory)",
    )
    ref.add_argument(
        "--overrides",
        default=None,
        help="Sticky human overrides JSON (default: ./overrides.json next to the "
        "catalog)",
    )
    ref.add_argument(
        "--seed-only",
        action="store_true",
        help="Enrich from existing descriptions only — skip live --help/man "
        "probing (faster, lower fidelity; use off a forensic box)",
    )
    ref.add_argument(
        "--dry-run",
        action="store_true",
        help="Report the new/changed/removed diff and write nothing",
    )

    args = parser.parse_args()

    if args.command == "investigate":
        cmd_investigate(args)
    elif args.command == "score":
        cmd_score(args)
    elif args.command == "compare-agents":
        cmd_compare_agents(args)
    elif args.command == "refresh":
        cmd_refresh(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
