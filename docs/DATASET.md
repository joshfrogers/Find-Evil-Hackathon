# Dataset Documentation

This document describes the evidence datasets used to develop, test, and
benchmark Agentic SIFT, the ground-truth baselines we scored against, and a
summary of findings from our runs. It satisfies the hackathon's dataset
documentation requirement: *what was tested, where it came from, and what we
found.*

Full quantitative metrics (precision, recall, F1, hallucination rate, finding
counts per run) live in the **[Accuracy Report](./ACCURACY.md)**. This document
is the narrative companion: it explains each dataset, where to obtain it, and
what the ground-truth answer key looks like.

---

## Overview

Agentic SIFT was exercised against two classes of dataset:

| Class | Datasets | Purpose |
|-------|----------|---------|
| **Public benchmark disk images** | NIST CFReDS "Hacking Case", NIST CFReDS 2015 "Data Leakage Case", a public Windows 10 "SysInternals" intrusion image | Reproducible, third-party evidence with community-validated answers. These are the real accuracy benchmarks. |
| **Synthetic reference baseline** | `sample-case` | A small, fully-synthetic baseline (placeholder IOCs, no real image) used as a schema and pipeline smoke-test fixture. Not a real-world benchmark — clearly labelled as synthetic. |

Every dataset is paired with a **ground-truth baseline** — a JSON answer key
checked into the repository at `tests/fixtures/baselines/<case_id>.json`. The
investigation output is scored against the matching baseline by
`python -m cli.main score`, which computes precision, recall, F1, and a
hallucination rate.

> **Important integrity note.** Evidence disk images (`.E01`, `.raw`, etc.) are
> large and forensic-sensitive and are **never** committed to this repository.
> Only the small JSON ground-truth baselines are version-controlled. Download
> the public images from their original sources (linked below) and place them on
> the workstation under an allowed evidence root (e.g. `/cases/`). See the
> README section "Adding Evidence & Ground Truth".

---

## Ground-Truth Baseline Schema

Each baseline is a JSON answer key describing what a correct investigation
*should* surface for a given image. The schema is enforced by
`accuracy/baseline.py`. The minimal required keys are `case_id`,
`evidence_image`, and, per finding, `id` + `description`; everything else is
optional but improves match quality.

| Field | Level | Meaning |
|-------|-------|---------|
| `case_id` | top | Stable identifier; also the baseline filename (`<case_id>.json`). |
| `evidence_image` | top | Filename of the primary evidence image the baseline corresponds to. |
| `evidence_type` | top | `disk`, `memory`, etc. |
| `source` | top | Provenance of the answer key (where the ground truth came from). |
| `attack_chains` | top | Named phases of the scenario (e.g. *Delivery & Initial Access*) that group findings. |
| `findings[]` | top | The list of ground-truth items the agent is expected to recover. |
| `findings[].id` | finding | Stable per-finding identifier (e.g. `B-001`). |
| `findings[].description` | finding | Human-readable statement of the artifact/fact to be found. |
| `findings[].ioc_type` / `ioc_value` | finding | Optional IOC (ip, domain, hash, file_path, registry_key). |
| `findings[].artifact_type` | finding | Forensic source (registry, mft, prefetch, browser_history, evtx, usnjrnl, amcache, …). |
| `findings[].expected_confidence` | finding | `confirmed` (direct evidence) vs `inferred` (correlated). |
| `findings[].must_find` | finding | If `true`, this is a core item. The **must-find count** is the headline recall target — a credible investigation should recover these. |

**Provenance caveat.** Several baselines carry `todo_validate_against_image:
true`, meaning the answer key was assembled from public answer keys and
independent community writeups but has not yet been line-by-line re-verified
against the image by us. This is disclosed honestly in each baseline's `source`
field rather than presented as a vetted official key.

---

## Public Benchmark Datasets

### 1. NIST CFReDS "Hacking Case" (`NIST-HACKING-001`)

- **Source (public):** NIST Computer Forensic Reference Data Sets (CFReDS) —
  the "Hacking Case". Originally published by NIST and available from the CFReDS
  archive: `https://cfreds-archive.nist.gov/Hacking_Case.html`. This is a widely
  used, freely downloadable training image. NIST does **not** publish an official
  answer key, so our baseline answers were cross-validated across multiple
  independent forensic writeups.
- **Evidence:** A forensic image of a seized laptop. The case files are a split
  EnCase image (a `.E01`/`.E02` pair plus a multi-segment `SCHARDT.00x` set).
- **OS / scenario:** Windows XP Professional. The investigation centres on a
  suspect ("Mr. Evil") whose machine was used for wireless network
  reconnaissance ("war driving") and network sniffing. The classic exam goal is
  to tie the real registered owner of the machine to the hacker persona via
  on-disk artifacts.
- **Key artifacts:** Registry hives (computer name, registered owner, user
  account + SID, timezone, network/MAC configuration), application config files
  that link the owner identity to the alias (the network-discovery tool's
  `irunin.ini`, the IRC client's `mirc.ini`), and installed reconnaissance /
  sniffing tooling (a wireless network scanner, a packet capture/sniffer, a
  network discovery tool), plus associated email/messenger identities.
- **Ground truth:** 18 findings total, **11 marked `must_find`** (the four
  attack chains: System & User Identification, Network Reconnaissance &
  War Driving, Communication & Identity, Credential Theft & Network Sniffing).
- **Findings summary:** This was our most-iterated benchmark. Across runs the
  agent recovered a substantial fraction of the must-find items (best scored run
  reached recall ≈ 0.55 against the full baseline, and a later focused
  configuration recovered the majority of the must-find set) **with a
  hallucination rate of 0.0** — no fabricated findings. Recurring misses were
  artifacts requiring deeper config-file parsing (network/MAC details, the
  network discovery tool, an email address embedded in an app config). See the
  [Accuracy Report](./ACCURACY.md) for per-run precision/recall/F1.

### 2. NIST CFReDS 2015 "Data Leakage Case" (`NIST-DATALEAK-001`)

- **Source (public):** NIST CFReDS — the 2015 "Data Leakage Case":
  `https://cfreds.nist.gov/data_leakage_case/data-leakage-case.html`. Unlike the
  Hacking Case, NIST publishes a detailed step-by-step answer key for this
  scenario, which makes it an unusually strong benchmark.
- **Evidence:** Multiple correlated items for a single insider scenario — a
  workstation disk image plus several removable-media images (the case ships as
  split/7z-packaged `.E01` and archive sets).
- **OS / scenario:** Windows. An insider-threat / data-exfiltration scenario: a
  user coordinates with a conspirator over email, searches for and stages
  sensitive corporate files, exfiltrates them via personal webmail and removable
  USB media (renaming files to evade detection), then runs anti-forensic cleanup
  tooling to cover tracks.
- **Key artifacts:** Email correspondence (work + personal + conspirator
  addresses), file-search history (WordWheelQuery / TypedPaths / Recent docs),
  USB device connection artifacts (USBSTOR, setupapi), file copy/rename evidence
  (USN Journal, LNK files, `$SI` vs `$FN`), browser history to webmail, and
  evidence of cleanup-tool execution (prefetch / Amcache / uninstall keys).
- **Ground truth:** 14 findings total, **8 marked `must_find`** (attack chains:
  Coordination & Planning, Data Discovery & Collection, Exfiltration,
  Anti-Forensics & Cover-Up).
- **Findings summary:** Our recorded scoring runs on this image completed but
  produced no scored findings (recall 0.0), and — consistent with every other
  run — **0 hallucinations**. This image is a known gap and an explicit
  follow-up target; the no-output runs trace to pipeline/mount issues during
  those sessions rather than to fabricated output. See the
  [Accuracy Report](./ACCURACY.md).

### 3. SysInternals Intrusion Image (`SYSINTERNALS-001`)

- **Source (public):** A publicly available Windows 10 intrusion training image
  documented in several independent community DFIR writeups. Our baseline was
  synthesized from two independent published analyses and cross-checked against a
  third public challenge's ground truth; conflicts between the writeups were
  reconciled manually. Because it is assembled from community sources rather than
  an official key, this baseline carries `todo_validate_against_image: true`.
- **Evidence:** A single Windows disk image (`.E01`).
- **OS / scenario:** Windows 10 Enterprise (build 17763). A trojanized-download
  intrusion: the `hosts` file is poisoned to redirect a legitimate-looking
  download domain to an attacker IP, a Windows Defender path exclusion is added
  via PowerShell as pre-staging, the user downloads and executes a malicious
  `SysInternals.exe`, which pulls a secondary payload from an attacker domain and
  installs it as a Windows service for persistence — followed by prefetch
  deletion as anti-forensics.
- **Key artifacts:** MFT / USN Journal (download pipeline, file
  creation+deletion), Amcache + Shimcache + UserAssist + BAM (execution
  evidence with timestamps), browser/webcache (download URL), the modified
  `hosts` file, Defender-exclusion + service-install event logs (Event ID 7045),
  SRUM network byte counts, shellbags, and PE metadata of the malicious binary.
- **Ground truth:** 20 findings total, **11 marked `must_find`** (attack chains:
  Pre-Staging / Defense Evasion, Delivery & Initial Access, Execution,
  Persistence & Post-Exploitation).
- **Findings summary:** The recorded scoring run completed with no scored
  findings (recall 0.0) and **0 hallucinations**. A reviewed exploratory run on
  this image also surfaced a key report-quality lesson — tool *failures* were
  occasionally narrated as findings — which drove an evidence-positive
  finding-creation guard. See the [Accuracy Report](./ACCURACY.md) for details.

---

## Synthetic Reference Baseline

### `sample-case` (synthetic — not a real image)

- **Source:** Internal synthetic reference. This baseline does **not**
  correspond to any downloadable image; it was transcoded from the project's own
  sample report as a `v0` ground-truth fixture. It uses obvious placeholder IOCs
  (e.g. `*.example.com` domains, documentation-range / RFC-style addresses) so it
  can never be mistaken for real evidence.
- **Purpose:** A small, deterministic fixture for two jobs: (1) validating the
  baseline **schema** and the scoring pipeline end-to-end, and (2) serving as a
  copy-from example when authoring a new baseline. It is the reference template
  for the answer-key format, not an accuracy benchmark.
- **Scenario (illustrative):** A synthetic two-phase intrusion — a malicious
  "update" executable downloaded via the browser, persisted via a Run key and a
  service, executed, and beaconing to a C2 host; followed by credential theft and
  lateral movement with anti-forensic timestomping.
- **Ground truth:** 10 findings, **all 10 marked `must_find`**, across two
  attack chains (full malware lifecycle; credential theft & lateral movement).
- **Findings summary:** Used as a smoke test only. No accuracy claims are made
  from this fixture, and results from it are not reported as benchmark numbers.

---

## Cross-Cutting Findings

- **Zero hallucinations across all recorded scoring runs.** Every run in the
  accuracy index reports a hallucination rate of 0.0 — the architectural
  guardrails (evidence-linked findings, allowlist-validated execution, adversarial
  verification) kept fabricated artifacts out of the reports even when recall was
  low. This is the headline accuracy property of the system.
- **Recall is the primary open area, not precision-of-invention.** The dominant
  failure mode in our runs was *not finding* a real artifact (recall gaps),
  rather than *inventing* a false one. The NIST Hacking Case shows the system can
  recover a majority of must-find items under a focused configuration; the
  Data Leakage and SysInternals images are the active follow-up targets.
- **Honest provenance.** Several baselines are flagged
  `todo_validate_against_image: true`. We treat building and re-verifying one
  fully-validated golden report per public benchmark image as ongoing work, and
  we disclose the validation status in each baseline rather than overstating it.

---

## Reproducing a Run

```bash
# 1. Download a public image from its NIST/CFReDS source (links above)
#    and place it under an allowed evidence root on the workstation.
#    Example: /cases/4Dell_Latitude_CPi.E01

# 2. Run the investigation against the matching baseline.
python -m cli.main investigate \
    --evidence /cases/<image>.E01 \
    --type disk \
    --baseline tests/fixtures/baselines/<case_id>.json

# 3. Score the output against ground truth (precision / recall / F1 / hallucination).
python -m cli.main score \
    --report output/inv-XXXX/report.json \
    --baseline tests/fixtures/baselines/<case_id>.json
```

See the README for full setup, allowed evidence roots, and how to add a new
dataset + baseline.
