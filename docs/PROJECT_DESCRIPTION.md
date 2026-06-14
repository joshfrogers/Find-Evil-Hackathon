# Agentic SIFT

Autonomous, hypothesis-driven forensic triage on the SANS SIFT workstation — a Python CLI orchestrator that drives Claude (via the Anthropic API) through a real digital-forensics investigation, while the code, not the model, controls what is allowed to execute.

## Inspiration

Digital forensics and incident response (DFIR) has a bottleneck that every responder knows intimately: triage is slow, manual, and gated on a small population of senior experts.

When an endpoint or server is suspected of compromise, the first hours matter most — yet the work of those hours is overwhelmingly human and serial. A senior analyst mounts the image, runs a partition map, builds a timeline, pivots through registry hives, prefetch, event logs, memory, and network captures, forms a theory, tests it, discards it, and forms another. The toolset is enormous — the SIFT workstation alone ships hundreds of forensic utilities across two dozen categories — and knowing *which* tool answers *which* question is itself the expertise. Junior responders can run tools; far fewer can reason like an investigator about what the output means and what to look at next.

This expert-scarcity bottleneck shows up across the field in predictable ways: evidence degrades while a queue waits for an available analyst; off-hours incidents stall until someone senior is paged; organizations without deep in-house benches end up paying outside firms for capability they cannot staff. The constraint is rarely tooling — the tools are free and excellent. The constraint is the scarce, slow, human reasoning that decides how to *use* them.

Large language models are unexpectedly good at exactly that reasoning layer — hypothesis formation, tool selection, interpretation, pivoting — but they are also famously willing to assert things that are not in the evidence. In forensics, a confident hallucination is worse than a slow human. So the question that inspired Agentic SIFT was not "can an LLM run forensic tools?" It was: **can we get the *reasoning* of a senior analyst at machine speed, while making it architecturally impossible for the model to fabricate evidence, modify the image, or run a tool it was never allowed to run?**

That is the gap Agentic SIFT targets: scale the scarce reasoning, contain the model in hard guardrails, and produce output that an investigator — or opposing counsel — could actually trust.

## What it does

Agentic SIFT takes a piece of evidence (a disk image, memory dump, packet capture, or log set) and runs an autonomous, hypothesis-driven forensic investigation on it, end to end, from a single command:

```bash
python -m cli.main investigate --evidence /cases/image.E01 --type disk
```

It behaves like a lead investigator rather than a checklist runner:

1. **Triage.** Runs lightweight tools (partition map, filesystem stats, image stats) to understand the evidence landscape — never assuming, for example, that a partition starts at offset 0.
2. **Hypothesis formation.** From the triage output, Claude proposes a small set of concrete, testable theories ("persistence via a Run key," "lateral movement over RDP," "data staged for exfiltration").
3. **Targeted dispatch.** For each hypothesis, the orchestrator spawns specialized domain sub-agents — disk, memory, timeline, Windows artifacts, network, malware — each of which can only see the forensic tools relevant to its specialty.
4. **Adversarial verification.** High-value findings are handed to verifier agents whose only job is to *disprove* them: re-read the raw output, search for counter-evidence, propose benign explanations, and look for independent corroboration in other domains.
5. **Iteration and pivoting.** The orchestrator evaluates which hypotheses are supported, refuted, or inconclusive, learns from what failed, pivots to new theories, and re-dispatches — with a hard cap on rounds so it can never spiral.
6. **Reporting.** It emits a structured forensic report plus a full, machine-readable audit trail. Every finding carries a confidence label (Confirmed / Inferred / Possible) and links back to the exact tool execution that produced it.

The output is three artifacts per investigation: a human- and machine-readable report (`report.json`), a complete execution log (`audit.jsonl`), and the investigation's working memory (`progress.json` — hypotheses, failed approaches, and strategy pivots). Any claim in the report can be traced to the precise command and output that produced it.

## How we built it

Agentic SIFT is a Python CLI orchestrator that calls Claude over the Anthropic Messages API. The architectural decision at the heart of the project is a clean split of authority:

> **The LLM decides *what* to investigate and *how to interpret* results. The Python code controls *what can be executed* and *what tools are available*.**

The model never touches `subprocess`, never opens an SSH connection, and never sees a tool it is not permitted to use. Everything it proposes flows through code we control.

**The orchestrator (`orchestrator/investigator.py`)** runs the hypothesis loop: triage → hypotheses → dispatch → verify → deepen/pivot → correlate → report. It owns iteration caps, progress tracking, and graceful degradation, so autonomy never depends on the model "choosing" to stop.

**Domain sub-agents (`agents/`)** are specialized analysts. Each receives a focused task tied to one hypothesis, documents what it *expects* to find before running a tool, executes through the guarded executor, and then records actual-versus-expected. That expected/actual delta makes the agent's reasoning legible in the logs.

**Verifier agents (`verification/`)** are the anti-hallucination mechanism. They are adversarial by design — they have no incentive to confirm a finding, only to challenge it — and they run a multi-round challenge with cross-domain corroboration and confidence recalibration. Only findings that survive verification reach the report.

**The executor (`executor/runner.py`)** is the architectural gatekeeper, and this is where the guardrails live in *code, not prompts*. Every proposed command passes through a validation pipeline:

1. **Allowlist check** — the binary must exist in the scanned tool catalog.
2. **Argument validation** — unknown or dangerous flags are rejected.
3. **Path validation** — evidence paths must resolve under allowed roots, with symlink-escape detection.
4. **Argv array construction** — commands are built as argument arrays; there is no shell interpolation, ever.
5. **Bounded execution** — per-tool timeouts and output-size caps, with process-group cleanup.

If validation fails, the command is rejected, the rejection is logged, and the model is told why — but it cannot bypass the pipeline. The same principle governs evidence: images are mounted **read-only** (`losetup -r` + mount), and the evidence is SHA-256 hashed before and after the run so any modification would be detected as a spoliation failure.

**The tool catalog (`tool_registry/`, `catalog/`)** is built by scanning the actual workstation — there is no hardcoded list of tools baked into the code or prompts. A sub-agent's tool menu is gated by domain at dispatch time, so the disk-forensics agent literally cannot see memory tools.

**The audit logger (`audit/`)** records everything in structured JSON — tool executions (with output hashes), inter-agent messages, agent decisions, findings, verification verdicts, self-corrections, and the full hypothesis lifecycle — so an entire case can be reconstructed from the logs alone.

**Accuracy and correlation (`accuracy/`, `correlation/`)** close the loop: temporal and semantic correlation tie findings together across domains, and a scoring framework measures precision, recall, F1, and hallucination rate against ground-truth baselines.

The whole thing is Python standard library plus our code — no heavyweight agent framework — and it runs locally on a single SIFT workstation with `ANTHROPIC_API_KEY` set: the tools, the image, and the read-only mount all live on the same machine.

## Challenges we ran into

**Discovering tools without a hardcoded list.** We did not want a curated tool list that silently goes stale. But naively enumerating every executable on the machine produced thousands of candidates and would have triggered thousands of LLM enrichment calls. We landed on two deterministic, self-maintaining signals — trusted forensic directories taken wholesale, plus the binaries of explicitly user-installed packages (excluding base-OS and auto-dependencies) — and then used a man-page relevance filter to prune the rest. This actually *found* flagship tools a hand-curated list had been missing (bulk_extractor, autopsy, dislocker, aeskeyfind, extundelete).

**Per-domain scoping versus runaway breadth.** When we first removed the old hard cap on tools-per-agent, every agent suddenly received the entire catalog of ~600+ tools. The result was thousands of tool executions per run and an enormous verification tail. We had to introduce real per-domain scoping — each tool tagged with the domains it serves, gated fail-open at dispatch — to give each agent a small, relevant menu again.

**A transport regression that would have broken every run.** While adding prompt caching we sent an `anthropic-beta` caching header unconditionally, and our API gateway rejected it with an HTTP 400 — which would have killed every single LLM call. Prompt caching is generally available now, so the fix was to drop the beta header entirely and rely on `cache_control` content blocks, which work without it.

**Speed, parallelism, and hangs.** Long runs occasionally stalled on a slow API call, and our timeout-and-retry logic could compound that into multi-minute hangs. We added environment-tunable speed knobs and a `--fast` profile (fewer rounds, fewer hypotheses, high-value-only verification, a wider parallel pool, bounded per-call timeouts), which caps the worst case and makes iteration far quicker. We also learned that our development gateway serializes concurrent requests per credential — our parallel dispatch code was correct, and it parallelizes properly against the public API.

**Knowing when it's actually working.** The post-processing tail of a run (semantic correlation, image re-hashing, scoring) is quiet in the logs, so a healthy run could look like a hang. We added explicit phase markers that both print and write to the audit log, so progress is observable end to end.

## Accomplishments that we're proud of

- **Hypothesis-driven autonomy.** The system forms theories, tests them, recognizes when results don't support them, and pivots mid-run — with the full investigative arc visible in the logs rather than just in a demo.
- **Architectural guardrails, not prompt-based ones.** The allowlist, path sandboxing, argv arrays, read-only mounts, and iteration caps are enforced in code. The model can ask to do something forbidden; the code simply won't let it. Evidence integrity is protected by design, not by instruction.
- **Adversarial verification.** Dedicated verifier agents try to break every high-value finding before it's allowed into the report — the opposite of a system optimized to confirm itself.
- **Brutally honest accuracy.** On our best validated run against a public NIST forensic image, the system achieved **0.0 hallucination rate** with recall of 0.727 (8 of 11 ground-truth findings) in a single fast round. We track and report our misses and our false positives openly — in forensics, honesty outranks a flawless-looking demo.
- **Full audit traceability.** Every finding traces to the exact tool execution, command, and output that produced it; an entire investigation can be reconstructed from the logs alone.
- **563 tests.** The whole system is built test-first, so prompt and tooling changes that would silently break detection get caught before they merge.

## What we learned

- **Authority separation is the whole game.** The single most important design choice was deciding what the model is *allowed* to do versus what it merely *decides*. Once the executor is the only path to execution, the model's creativity becomes a feature instead of a liability.
- **Self-maintaining beats curated.** A scanner grounded in deterministic signals plus a relevance filter stays correct as the workstation changes; a hand-written tool list is wrong the moment someone installs something new.
- **An adversarial second opinion is cheap insurance.** Making a separate agent argue *against* each finding caught weak and unsupported claims that a single confident pass would have shipped.
- **Honest error analysis is an asset, not an admission.** Documenting exactly what the system missed and why — and proving a zero hallucination rate on a real image — is more credible than a perfect-looking result with no error analysis behind it.
- **Observability matters as much as correctness.** Silent phases read as failures; explicit phase markers turned an opaque pipeline into one you can trust at a glance.

## What's next

- **Close the remaining detection gaps.** The known content miss (host network identity — IP/MAC emission) is independent of speed and is the next correctness target; a couple of other misses look recoverable simply by allowing more investigation rounds.
- **Head-to-head baseline.** Run the system natively on a downloaded SIFT workstation and compare it directly against a stock LLM-plus-tools baseline (Protocol SIFT) on the same dataset, for a concrete improvement metric.
- **Documented bypass and spoliation testing.** Actively attempt to make the agent modify evidence or escape its allowlist, and publish whether the architectural guardrails hold.
- **Single-box everywhere.** Finish the path where the entire pipeline — Claude API access, forensic tools, and the read-only mount — runs on one SIFT box, so a responder can point it at an image and walk away.
- **Broader evidence coverage and richer correlation.** Extend depth across more artifact types and deepen cross-source correlation (e.g., disk findings corroborated against memory) — the dimension that turns triage into a real reconstruction.
