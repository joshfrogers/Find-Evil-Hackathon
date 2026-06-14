# Architecture

This document describes the architecture of **Agentic SIFT** — an autonomous
forensic-analysis CLI that drives Claude (via the Anthropic Messages API)
through hypothesis-driven investigations using the forensic tooling on a
[SANS SIFT](https://github.com/teamdfir/sift) workstation. It satisfies the
SANS *Find Evil!* submission requirement for an architecture diagram with
components, trust boundaries, and an explicit accounting of which guardrails
are **architectural** (enforced in code) versus **prompt-based** (instructed via
the system prompt).

## System Overview

Agentic SIFT is a Python orchestrator that treats forensic analysis the way a
senior analyst does: it forms hypotheses, tests them with targeted tooling,
challenges its own findings, and pivots when the evidence does not support a
theory. The large language model (LLM) does the *reasoning* — forming
hypotheses and interpreting tool output. The Python code does the *governing* —
deciding what tools exist, what may be executed, and where output goes.

The central design principle is a hard separation of duties:

- **The LLM decides** *what* to investigate and *how to interpret* results.
- **The Python code controls** *what can be executed* and *what tools are
  available*.

The LLM never touches `subprocess`, SSH, the filesystem, or the evidence
directly. Every command it proposes is routed through a code executor that
validates it against an allowlist, sandboxes its paths, and runs it as an argv
array with no shell interpolation. This is the architectural guardrail at the
heart of the system, and it is what makes the agent's autonomy safe to grant.

**Shipped deployment model — local-first, single machine.** The default and
recommended way to run Agentic SIFT is entirely on one SIFT workstation: the
Claude transport, the forensic tools, the evidence image, and the read-only
mount all live on the same host. A remote (SSH) execution mode exists as a
development convenience only; it has no baked-in connection defaults and is not
the shipped path (see [Execution Modes](#execution-modes)).

**Tech stack:**

- **Orchestration** — Python 3.10+ (standard library only; no third-party
  agent frameworks).
- **LLM transport** — Claude via the Anthropic Messages API over HTTPS, driven
  by the `ANTHROPIC_API_KEY` environment variable.
- **Execution** — allowlist-validated command execution (`LocalExecutor` /
  `SSHExecutor`), path sandboxing, argv arrays (never `shell=True`).
- **Evidence** — read-only disk-image mounting with SHA-256 integrity
  bracketing (hashed before and after the investigation).
- **Storage** — JSON for reports and progress, JSON-lines (JSONL) for the audit
  log, and a per-machine tool catalog scanned at runtime.

## Architecture Diagram

The diagram shows the five required elements — the agent/orchestrator, the SIFT
forensic tools, the executor, the evidence sources, and the output pipeline —
and the trust boundary that separates LLM reasoning from tool execution.

```
                          AGENTIC SIFT  —  single SIFT workstation (local-first)

  ┌───────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                       │
  │   User ──► CLI (cli/main.py)                                                           │
  │              │                                                                         │
  │              ▼                                                                          │
  │   ┌──────────────────────────────────────────────┐                                    │
  │   │  ORCHESTRATOR  (orchestrator/investigator.py)  │   ◄── REASONING SIDE              │
  │   │  • Hypothesis-driven loop (triage → form →     │       (LLM decides WHAT / HOW     │
  │   │    dispatch → verify → deepen/pivot)           │        to interpret)              │
  │   │  • Reads/writes Progress Tracker               │                                   │
  │   │  • Max 5 investigation rounds [ARCHITECTURAL]  │                                   │
  │   └──────────────────────────────────────────────┘                                    │
  │              │                                                                          │
  │      ┌───────┼─────────────┐                                                            │
  │      ▼       ▼             ▼                                                            │
  │  Domain    Domain        Domain         Verifier Agents                                 │
  │  Sub-Agent Sub-Agent  …  Sub-Agent      (challenge / refute findings)                   │
  │  (Disk)    (Memory)      (Timeline)                                                     │
  │      │       │             │                  │                                         │
  │      ▼       ▼             ▼                  ▼                                          │
  │   ┌────────────────────────────────────────────────┐                                   │
  │   │  TOOL CATALOG  (tool_registry/ + catalog/)       │   per-machine scan + gating      │
  │   │  • scanner.py: enumerate installed tools         │   (each sub-agent sees ONLY      │
  │   │  • gates.py:   gate_tools by domain / installed  │    its domain's tools)           │
  │   │    / target_os / input_type   [ARCHITECTURAL]    │                                  │
  │   └────────────────────────────────────────────────┘                                   │
  │      │       │             │                                                            │
  │      │ proposed command (text only — no execution capability)                           │
  │ ═════╪═══════╪═════════════╪══════════════ TRUST BOUNDARY ════════════════════════════ │
  │      ▼       ▼             ▼                                                            │
  │   ┌────────────────────────────────────────────────┐                                   │
  │   │  EXECUTOR  (executor/runner.py)   [ARCHITECTURAL]│   ◄── EXECUTION SIDE             │
  │   │  Validation pipeline (code, not prompt):         │       (Python decides WHAT       │
  │   │   1. Allowlist check (tool in catalog?)          │        CAN run)                  │
  │   │   2. Argument validation (known flags?)          │                                  │
  │   │   3. Path validation (under evidence root?       │   The LLM never touches          │
  │   │      symlink-escape check via resolve())         │   subprocess or SSH directly.    │
  │   │   4. Build argv array (no shell, ever)           │                                  │
  │   │   5. Execute with limits (timeout, output cap)   │                                  │
  │   │   6. Capture + log (ExecutionResult → audit)     │                                  │
  │   │  Mode: LocalExecutor (shipped) | SSHExecutor (dev)│                                 │
  │   └────────────────────────────────────────────────┘                                   │
  │              │                              │                                           │
  │              ▼                              ▼                                           │
  │   ┌────────────────────┐        ┌──────────────────────────────────────┐               │
  │   │  SIFT FORENSIC      │        │  EVIDENCE SOURCES                     │               │
  │   │  TOOLS              │ reads  │  (evidence/session.py, view.py)       │               │
  │   │  fls, mmls, fsstat, │◄──────►│  • Disk images (.E01/.raw), memory    │               │
  │   │  volatility3,       │ read-  │    dumps, pcap, log/artifact sets     │               │
  │   │  log2timeline,      │ only   │  • Read-only mount (losetup -r+mount) │               │
  │   │  RegRipper, yara …  │        │  • SHA-256 integrity bracket          │               │
  │   │  (read-only set)    │        │    (hash before + after) [ARCH.]      │               │
  │   └────────────────────┘        └──────────────────────────────────────┘               │
  │              │                                                                          │
  │              ▼                                                                          │
  │   ┌────────────────────────────────────────────────┐                                   │
  │   │  OUTPUT PIPELINE                                  │                                  │
  │   │  • Audit Logger (audit/logger.py) → audit.jsonl  │   every execution + agent        │
  │   │  • Progress Tracker (progress/tracker.py)        │   message + decision, with       │
  │   │    → progress.json                               │   IDs linking findings to        │
  │   │  • Correlation (correlation/) + Accuracy         │   the exact tool execution       │
  │   │    scoring (accuracy/)                           │                                  │
  │   │  • Report Generator (report/generator.py)        │                                  │
  │   │    → report.json + report.md                     │                                  │
  │   └────────────────────────────────────────────────┘                                   │
  │                                                                                         │
  └───────────────────────────────────────────────────────────────────────────────────────┘

  GUARDRAIL LEGEND
  [ARCHITECTURAL] = enforced in code; the LLM cannot bypass it regardless of its prompt.
  [PROMPT-BASED]  = instructed via the system prompt; shapes behaviour but is not enforced.
```

## Why No MCP Server (MCP is N/A)

The SANS hackathon lists a custom **MCP (Model Context Protocol) server** as one
supported architectural approach — exposing typed functions (e.g.
`get_amcache()`, `extract_mft_timeline()`) to the model instead of generic
shell. Agentic SIFT deliberately does **not** use MCP. Instead it uses a
**code executor** as the gatekeeper, for these reasons:

- **The executor, not the model, owns execution.** With MCP the model invokes
  tool functions across a protocol boundary, but the trust enforcement still has
  to live somewhere. Putting a Python executor directly between the LLM and the
  operating system makes the allowlist, path sandbox, argv construction, and
  read-only constraints first-class, in-code guardrails that exist regardless of
  any protocol layer.
- **Dynamic per-machine tool surface.** SIFT installs vary. The tool catalog is
  *scanned* on the machine where the investigation runs and *gated* per domain,
  so sub-agents see exactly the tools that are present. An MCP server's typed
  function set would be a second, statically defined surface to keep in sync
  with what is actually installed.
- **Fewer moving parts and no extra dependency.** The shipped system is the
  Python standard library plus the Anthropic API. There is no separate server
  process to run, secure, or document.

MCP is therefore **N/A** for this submission: its role (governing what the model
can run) is filled — more strictly — by the in-process executor and trust
boundary described below.

## Trust Boundary

The single most important boundary in the system is the line between the
**reasoning side** (the LLM and the agents that prompt it) and the **execution
side** (the executor and everything it can touch: subprocess, SSH, the
filesystem, and the evidence).

- **The LLM proposes; it never executes.** A sub-agent asks Claude to plan tool
  invocations. Claude's response is plain text — a *proposed* command. It has no
  capability to call `subprocess`, open an SSH connection, or read a file. It
  can only hand text to the executor.
- **The executor is the sole crossing point.** Every command — without
  exception — passes through `executor/runner.py`'s validation pipeline before
  anything runs. There is no side channel by which the LLM's output reaches the
  operating system.
- **Rejections feed back into reasoning, not around it.** If a proposed command
  fails validation (unknown tool, bad flag, out-of-bounds path), it is rejected
  and logged, and the rejection reason is returned to the LLM so it can propose
  an alternative. The model can retry, but it cannot bypass the pipeline.
- **The evidence is downstream of the boundary.** The LLM never names a raw
  device or mount operation that runs unchecked; mounting is performed in code,
  read-only, and the evidence is hashed before and after the run.

Because of this boundary, the agent can be granted real autonomy over *strategy*
while the *blast radius* of its actions stays fixed by code.

## Component Details

### Orchestrator — hypothesis-driven loop

`orchestrator/investigator.py` is the lead investigator. Rather than blanket-run
every tool, it runs a hypothesis loop:

1. **Initial triage** — run lightweight tools (partition layout, filesystem
   stats, basic listing) to understand the evidence landscape.
2. **Hypothesis formation** — based on triage output, the LLM forms 1–3
   hypotheses (e.g. "ransomware delivery via phishing attachment", "lateral
   movement from compromised RDP", "insider data exfiltration").
3. **Targeted dispatch** — spawn domain sub-agents to test specific hypotheses,
   each with a focused question rather than "analyze everything".
4. **Evaluation** — collect findings and judge each hypothesis as supported,
   refuted, or inconclusive.
5. **Deepen / pivot** — if a hypothesis is refuted, form new ones from what was
   learned; if evidence points somewhere unexpected, follow it.
6. **Convergence** — when hypotheses stabilize, correlate cross-domain findings
   (temporally and semantically) and generate the report.

**Self-correction:** when sub-agent findings contradict each other the
orchestrator dispatches verifier agents to resolve the conflict; when a tool
fails it consults the Progress Tracker for prior failure patterns and adapts.

**Iteration cap [ARCHITECTURAL]:** a maximum of 5 investigation rounds. If
hypotheses have not converged, the orchestrator reports what it has and flags
incomplete areas rather than looping indefinitely.

### Domain sub-agents

`agents/domains.py` defines six specialized forensic domains, each backed by a
system prompt that gives it analyst expertise. A sub-agent (`agents/base.py`)
receives a focused, hypothesis-tied task; queries the gated tool catalog for
its domain's tools; plans which tools to run; documents what it expects to find
*before* running each tool; executes through the executor; parses output into
findings; compares actual results against its expectations; assigns a confidence
level; and returns structured findings with links back to the exact executions
that produced them.

| Domain | Categories | Key Tools |
|--------|-----------|-----------|
| Disk Forensics | disk_forensics, filesystem_tools, file_carving_recovery | mmls, fls, fsstat, img_stat, foremost |
| Timeline | timeline_analysis | log2timeline, plaso, mactime |
| Memory | memory_analysis | volatility3 |
| Windows Artifacts | windows_artifact_analysis, windows_event_log_analysis | RegRipper, PECmd, evtx_dump, chainsaw |
| Network | network_forensics | tcpdump, tshark, zeek |
| Malware | malware_analysis, hashing_integrity | yara, clamav, ssdeep, olevba |

Confidence levels are **Confirmed** (direct evidence), **Inferred** (correlated
evidence), and **Possible** (a single weak signal). The expected-vs-actual
pattern both makes the agent's reasoning auditable and serves as a training
artifact for junior analysts reading the logs.

### Tool catalog + gating

The tool catalog (`tool_registry/` and `catalog/`) is the single source of
truth for what forensic tools are available. It is **not** a running service and
**no tool list is ever hardcoded into a prompt**.

- **`tool_registry/scanner.py`** enumerates the tools actually installed on the
  machine (via `PATH`, package metadata, and a gate-based scan of forensic
  directories). `tool_registry/enrich.py` attaches grounded metadata (categories,
  capabilities, I/O types) with provenance, and `tool_registry/catalog.py`
  handles load/merge and staleness.
- **`catalog/gates.py` (`gate_tools`) [ARCHITECTURAL]** filters the catalog at
  sub-agent spawn time by domain, by whether the tool is installed, by target OS,
  and by input type. A disk sub-agent literally cannot see memory-analysis tools;
  this is architectural specialization, not a prompt instruction.
- The executor validates every proposed command against this **same** catalog,
  so the model can never invoke a tool the catalog does not contain.

Because the catalog is scanned per machine, installing or updating a SIFT tool
makes it available to the relevant sub-agent on the next run with no code
changes — and a `refresh` CLI command re-scans on demand.

### Executor — validation pipeline

`executor/runner.py` is the architectural gatekeeper described in the trust
boundary. It exposes two modes that share one validation pipeline:
`LocalExecutor` (the shipped, single-machine path) and `SSHExecutor` (the
dev-only remote path). Only the final execution step differs (`subprocess.run`
versus an SSH-wrapped command); the validation is identical.

For each command the LLM proposes:

1. **Allowlist check** — is the binary present in the tool catalog? If not,
   reject and log the attempt.
2. **Argument validation** — are the flags known/permitted for that tool?
   Reject unknown or dangerous flags.
3. **Path validation** — does each path resolve under an allowed evidence root?
   Symlink-escape is detected via path resolution.
4. **Argv array construction** — the command is assembled as a list of strings;
   there is no shell interpolation, ever (never `shell=True`).
5. **Execution with limits** — per-tool timeout and output-size cap, with
   process-group cleanup on timeout.
6. **Capture + log** — the result (tool, argv, exit code, duration, captured
   output, truncation flags, timestamp, and a unique `execution_id`) is recorded
   to the audit trail.

Any failure rejects the command and returns the reason to the LLM, which may
propose an alternative but cannot circumvent the pipeline.

### Verifier agents

`agents/base.py` (`VerifierAgent`) and `verification/` implement adversarial
self-correction: dedicated challenger agents that try to *disprove* findings
before they reach the report. After a sub-agent produces a high-value finding,
the orchestrator dispatches a verifier that runs:

1. **Evidence check** — does the raw tool output actually support the claim?
   (The verifier has no incentive to confirm — its job is to challenge. This is
   the primary anti-hallucination mechanism.)
2. **Counter-evidence search** — run additional tools looking for contradictions.
3. **Alternative explanation** — propose benign explanations and try to rule
   them out.
4. **Corroboration search** — look for independent supporting evidence in other
   forensic domains.
5. **Confidence ruling** — issue a verdict: **Confirmed**, **Downgraded**, or
   **Refuted**.

**Iteration cap [ARCHITECTURAL]:** a maximum of 3 challenge rounds per finding;
if the sub-agent and verifier still disagree, the orchestrator makes the final
call and documents the disagreement. Only findings that survive verification are
elevated in the report. The `verification/` package also handles confidence
recalibration and cross-domain corroboration.

### Progress tracker

`progress/tracker.py` is a persistent file that the orchestrator and every agent
read and write during an investigation — the system's memory across rounds. It
records the lifecycle of each hypothesis (status, evidence for/against,
timestamps), `failed_approaches` (tool, args, failure, lesson learned),
`strategy_pivots`, and the iteration counters. Sub-agents consult
`failed_approaches` before choosing tools so they do not repeat failures, and
the orchestrator reads the tracker at the start of each round to inform
hypothesis formation. It is written out as `progress.json`.

### Audit logger

`audit/logger.py` writes every action as structured JSON-lines to `audit.jsonl`.
Event types include `tool_execution`, `agent_message` (inter-agent
communication, with token counts), `agent_decision`, `finding`, `verification`,
`self_correction`, `hypothesis`, and `orchestrator_plan`. Each finding links
back to specific `tool_execution` IDs, giving a complete traceability chain:

```
finding → tool_execution ID → exact command + captured output → evidence file
```

For verified findings the chain extends through the verification verdict to the
counter-evidence executions. This is the audit capability the hackathon's
"audit trail quality" and "agent execution logs" requirements call for.

### Evidence session — read-only mount + SHA-256 integrity bracket

`evidence/session.py` (`EvidenceSession`) and `evidence/view.py`
(`EvidenceView`) own the forensic-soundness lifecycle:

- **Read-only mount [ARCHITECTURAL]** — disk images are mounted read-only
  (`losetup -r` + `mount`) with type-aware handling; the executor's tool set is
  read-only only, and write/modify tools are not in the catalog.
- **Evidence roots [ARCHITECTURAL]** — evidence paths are validated and
  constrained to configured roots; output goes to a separate working directory,
  never the evidence.
- **SHA-256 integrity bracket [ARCHITECTURAL]** — every evidence item is hashed
  *before* the investigation and again *after*; a mismatch is a spoliation
  failure. This bracket is asserted on session close, with crash-safe teardown
  (unmount and re-hash) so the integrity check runs even if the investigation
  aborts.
- **Single mount, shared view** — evidence is mounted once and all sub-agents
  read from the mounted filesystem, and multiple evidence items belonging to one
  host can be analyzed in a single investigation.

### Report generator

`report/generator.py` synthesizes the orchestrator's findings into a structured
report emitted as both `report.json` and `report.md`. The report covers an
executive summary; investigation scope (evidence, tools, time period); a
timeline of events; findings (each with description, confidence level, evidence
links, and IOC details); an indicators-of-compromise section; **accuracy
metadata** (what was verified versus inferred, known limitations, potential
false positives); and an execution-log appendix. The `accuracy/` package scores
findings against ground-truth baselines (precision / recall / F1) and detects
hallucinations, and `correlation/` builds temporal and semantic correlations
that feed the timeline and finding clusters.

## Execution Modes

| Mode | Executor | Status | Connection details |
|------|----------|--------|--------------------|
| **Local (shipped)** | `LocalExecutor` | Default and recommended. Claude transport, tools, image, and read-only mount all on one SIFT workstation. | None — runs directly via `subprocess`. |
| **Remote (dev only)** | `SSHExecutor` | Development convenience for driving tools on a separate SIFT VM. **Not the shipped path.** | Caller-supplied only — `--remote HOST:PORT` (port required) and `--remote-user LOGIN`. No baked-in host, port, or user defaults; omitting any required value is an error. |

Both modes run the identical validation pipeline; only the final execution step
differs.

## Guardrails: Architectural vs Prompt-Based

The hackathon explicitly asks which constraints are enforced in code versus
instructed via the prompt. **Architectural** guardrails hold regardless of what
the LLM is asked to do; **prompt-based** guidance shapes behaviour but is not
enforced.

| Guardrail | Type | Enforced by |
|-----------|------|-------------|
| Tool allowlist (only catalogued tools may run) | **ARCHITECTURAL** | `executor/runner.py` validation pipeline, checked against the scanned catalog |
| Per-domain tool gating (sub-agent sees only its domain's tools) | **ARCHITECTURAL** | `catalog/gates.py` (`gate_tools`) at sub-agent spawn |
| Argument validation (reject unknown/dangerous flags) | **ARCHITECTURAL** | `executor/runner.py` |
| Path sandboxing to evidence roots + symlink-escape detection | **ARCHITECTURAL** | `executor/runner.py` (path resolution) |
| Argv arrays, never `shell=True` (no shell interpolation) | **ARCHITECTURAL** | `executor/runner.py` |
| Per-tool timeouts and output-size caps | **ARCHITECTURAL** | `executor/runner.py` |
| Read-only evidence mount | **ARCHITECTURAL** | `evidence/session.py` (`losetup -r` + `mount`); read-only tool set only |
| SHA-256 integrity bracket (hash before/after) + spoliation assertion | **ARCHITECTURAL** | `evidence/session.py` (crash-safe teardown) |
| Orchestrator iteration cap (max 5 rounds) | **ARCHITECTURAL** | `orchestrator/investigator.py` |
| Verifier challenge cap (max 3 rounds per finding) | **ARCHITECTURAL** | `verification/` |
| Full audit logging of every execution and agent message | **ARCHITECTURAL** | `audit/logger.py` |
| Investigation methodology (how to triage and sequence tools) | **PROMPT-BASED** | sub-agent / orchestrator system prompts |
| Hypothesis formation and pivoting strategy | **PROMPT-BASED** | orchestrator system prompt |
| Expected-vs-actual documentation before/after each tool | **PROMPT-BASED** | sub-agent system prompt |
| Confidence-level assignment (Confirmed / Inferred / Possible) | **PROMPT-BASED** | sub-agent / verifier system prompts |
| Counter-evidence and alternative-explanation reasoning | **PROMPT-BASED** | verifier system prompt |
| Report structure and narrative | **PROMPT-BASED** | report system prompt |

The takeaway: anything that bounds the agent's *capability* (what it can run,
where it can read, how long, how many times, and the integrity of the evidence)
is enforced in code and cannot be prompted away. Anything that shapes the
agent's *reasoning quality* (methodology, hypotheses, confidence, narrative) is
prompt-based, because that is reasoning the LLM is meant to perform.

## Dependencies

- Python 3.10+ (standard library only — no third-party agent frameworks).
- Claude API access via `ANTHROPIC_API_KEY` (the orchestrator calls the
  Anthropic Messages API over HTTPS).
- SIFT Workstation forensic tools (pre-installed on the SIFT VM).
- No `pip install` of LLM libraries required.

## License

MIT
