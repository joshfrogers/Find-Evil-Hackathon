# Tool Fallback Matrix & Error Recovery

This documents how `ToolAdvisor` (`tools/advisor.py`) keeps a forensic run at
**zero hard tool failures**: it learns which tools work on the current image,
pre-validates tools before they run, recovers argument-level mistakes, and
routes to a working alternative when a tool fails.

All of this runs on a **Linux SIFT host**, where the .NET Zimmerman parsers
cannot execute. The advisor is created once per investigation (per image) and
shared across triage and every sub-agent, so the compatibility matrix
accumulates over the whole run.

## Three recovery mechanisms

1. **Pre-validation** (`blocking_reason`) — refuses to spend an execution slot on a
   tool that cannot work here:
   - a `.NET` / `windows` / `powershell` runtime on a Linux host, or
   - an artifact parser handed a raw disk image (`.e01/.dd/.raw/...`) instead of
     an extracted artifact file.
2. **Argument remediation** (`normalize_args`) — fixes failures caused by the
   *arguments*, which a like-for-like tool swap cannot recover (the alternative
   reuses the same args and fails identically). See the table below.
3. **Fallback routing** (`suggest_fallback`) — on failure, walks the tool's
   capability chain forward (never backward, so no A→B→A cycles), skipping tools
   that are absent or already known-bad on this image.

## Fallback chains

Best-first per capability. A tool earlier in a chain that can't run on Linux
(e.g. a .NET parser) is simply skipped by pre-validation, so the chain still
resolves to the first *runnable* tool.

| Capability | Chain (best-first) | Linux notes |
|-----------|--------------------|-------------|
| `mft` | `mftecmd` → `analyzemft` → `mft.pl` | `mftecmd` is .NET (Windows-only); `analyzemft`/`mft.pl` are the Linux parsers |
| `registry` | `recmd` → `rip.pl` → `regslack.pl` | `recmd` is .NET (Windows-only); `rip.pl` (RegRipper) is the Linux primary; `regslack.pl` recovers deleted/slack data. **`regipy` is not installed**, so it is intentionally not in the chain. |
| `evtx` | `evtxecmd` → `evtx_dump.py` → `evtxparse.pl` | `evtxecmd` is .NET (Windows-only) |
| `amcache` | `amcacheparser` → `amcache.py` | `amcacheparser` is .NET (Windows-only) |
| `prefetch` | `pref.pl` | single Linux parser |
| `usn` | `usn.py` → `usnjls` → `usnj.pl` | all Linux |
| `carving` | `foremost` → `scalpel` → `photorec` | `bulk_extractor` is deliberately excluded (feature extraction, not file carving) |
| `timeline` | `tsk_gettimes` → `mactime` → `log2timeline.py` | all Linux; `regtime.pl` extracts registry timestamps for this stage |

## Argument remediation (`normalize_args`)

These are the failures from the SysInternals smoke test that a tool swap could
not have fixed. They are corrected in place before execution.

| Tool | Problem | Fix |
|------|---------|-----|
| `tsk_loaddb` | `-f ntfs` is an invalid flag (tsk_loaddb has no filesystem-type option) → non-zero exit | Drop `-f` and its value |
| `bulk_extractor` | needs a writable `-o <dir>` it can create; a missing or unwritable parent → "couldn't create output dir" | Ensure the `-o` parent exists and is writable; inject a fresh `-o` under the scratch dir when absent. Output is written off the read-only evidence mount. |

Unknown tools, and tools with no known argument issue, pass through unchanged.

## Compatibility matrix

Every attempt is recorded (`record_result`). A tool that has failed and never
succeeded on this image is **known-bad** (`is_known_bad`) and is skipped on
later commands. A tool that succeeded at least once is never blacklisted by a
later bad-args failure. The full matrix is emitted into the run report as
`report['tool_compatibility']`.

## Verification

- Unit + config-drift tests: `tests/test_advisor.py`,
  `tests/test_inventory_advisor_integration.py` (the latter validates every
  chain token resolves against the real `sift_sentinel/tool_inventory.json` via
  the production `cli.main.load_registry`).
- DoD evidence (pending, requires the SIFT VM): a full run on
  `base-sample-case-cdrive.E01` whose `report.json` `tool_compatibility` shows zero
  hard tool failures.
