# Sample Output — Multi-Round Verification

Illustrative excerpt of the **Verification & Self-Correction** section the
`ReportGenerator` produces for a sample Windows workstation image once
multi-round verification is wired in.
Shows multi-round verification, deterministic cross-domain corroboration, and an
auditable self-correction. (Hand-authored example; not a live run.)

---

## Verification & Self-Correction

| Finding | Verdict | Rounds | Cross-domain corroboration |
|---------|---------|--------|----------------------------|
| F-1a2b3c | confirmed | 1 | 2 (F-9f8e7d, F-4c5b6a) |
| F-9f8e7d | confirmed | 1 | 1 (F-1a2b3c) |
| F-4c5b6a | downgraded | 3 | 0 (—) |
| F-7d6e5f | refuted | 2 | 0 (—) |

- Findings challenged: 4 (2 required multiple rounds)
- Self-corrections recorded: 2
  - F-4c5b6a: confirmed -> inferred (verdict downgraded, 3 rounds)
  - F-7d6e5f: confirmed -> confirmed (verdict refuted, 2 rounds)

---

### How to read this

- **F-1a2b3c** — "Run key persistence pointing at `C:\Temp\evil.exe`" (artifacts
  agent). The disk and memory agents independently surfaced the same
  `file_path` IOC, so it is **corroborated by 2 cross-domain findings**. The
  single-round challenge found no contradicting counter-evidence, so the loop
  stopped early and the verdict is **confirmed**. Recalibration kept it at
  `confirmed` (already the ceiling).

- **F-4c5b6a** — "Service installed for lateral movement" (artifacts agent).
  No other domain corroborated it. The verifier ran the full **3 rounds**: round
  1 challenged it, round 2 ran targeted counter-checks (a benign service install
  was plausible), round 3 issued **downgraded**. Confidence dropped
  `confirmed -> inferred` and a **self_correction** event was logged — the
  auditable proof of real-time self-correction (SANS tiebreaker).

- **F-7d6e5f** — "Outbound C2 to 10.0.0.5" (network agent). The verifier's
  counter-evidence (round 2) showed the connection never completed; verdict
  **refuted**, so the finding is dropped from the accepted set. The
  self_correction event preserves the trail of what was removed and why.

Every verdict, round count, and corroboration link is traceable to the
underlying `verification` and `self_correction` events in `audit.jsonl`.
