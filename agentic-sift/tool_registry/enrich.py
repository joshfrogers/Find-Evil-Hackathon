"""Grounded, provenance-stamped LLM enrichment for discovered tools.

The crawler produces raw tool dicts (name/path/description). This module
turns one raw tool into a *catalog entry* by:

  1. Gathering objective grounding signals about the tool from the host
     (``--help`` output, the man page, and the package manager
     description) via :func:`build_signal_bundle`.
  2. Asking the LLM to classify the tool *only from that grounding text*
     and normalizing the result into a catalog entry, stamping each
     LLM-filled field with provenance, via :func:`enrich_tool`.

Design rules (forensic safety first):
  * Never raise from signal gathering — a missing/failing source is "".
  * Fail open. If the LLM is unavailable or returns garbage we KEEP the
    tool with ``target_os: ["any"]`` and ``confidence: "unknown"`` rather
    than dropping it or guessing specifics — a wrong single-OS label
    could hide a tool the investigator needs.
  * Only the LLM may mark a tool ``relevant: false`` (non-forensic OS /
    coreutils noise); in that case the caller skips it.

Stdlib only. All subprocess calls route through the module-level
:func:`_run` so tests can monkeypatch a single seam.
"""

from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
from typing import Any, Optional

from agents.claude import call_claude_json

logger = logging.getLogger(__name__)

# Cap each grounding text so the prompt stays bounded.
_HELP_LIMIT = 4096
_MAN_LIMIT = 4096
_PKG_LIMIT = 4096

_DEFAULT_MODEL = "claude"
_DEFAULT_CONFIDENCE = "medium"

_SYSTEM_PROMPT = (
    "You are cataloging digital-forensics tools for an automated "
    "investigation system. Classify each tool using ONLY the provided "
    "text (help output, man page, package description). Do NOT use prior "
    "knowledge and do NOT invent capabilities, OSes, or examples. When a "
    "field is not clearly supported by the text, output \"unknown\" for "
    "target_os or an empty list [] for list fields. Set relevant:false "
    "ONLY for clear non-forensic operating-system noise (generic "
    "coreutils / shell builtins with no investigative value).\n"
    "IMPORTANT — target_os is the OS of the EVIDENCE/IMAGE the tool is useful "
    "for analyzing, NOT the OS the tool runs on. A tool that analyzes "
    "artifacts from multiple OSes (e.g. a memory, registry, network, or "
    "filesystem analyzer that works across platforms) is \"any\". Only set a "
    "specific OS when the tool ONLY makes sense for evidence from that OS "
    "(e.g. a Windows-registry-only parser is [\"windows\"]). When in doubt, "
    "use \"any\" — a wrong single OS hides a needed tool.\n"
    "domains is which investigative agents should see the tool, from this "
    "fixed set: disk, memory, timeline, artifacts, network, malware. Use "
    "[\"any\"] for general-purpose tools usable by all. Respond with a single "
    "JSON object."
)


# ---------------------------------------------------------------------------
# subprocess seam
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 5) -> str:
    """Run ``cmd`` (argv list) and return stripped stdout, or "" on any
    failure. Single monkeypatch seam for tests — never raises.

    The timeout is short (5s) so one hanging ``--help``/``man``/``pkg`` probe
    cannot stall the concurrent refresh batch; a timeout (like any failure)
    yields "" per the contract.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ):
        return ""
    return (result.stdout or "").strip()


def _safe_run(cmd: list[str]) -> str:
    """Call _run but swallow *anything* it (or a test stub) might raise.

    build_signal_bundle must never propagate an error from a single
    grounding source.
    """
    try:
        out = _run(cmd)
    except Exception:  # noqa: BLE001 - defensive: a source must never break enrichment
        return ""
    return out or ""


# ---------------------------------------------------------------------------
# signal gathering
# ---------------------------------------------------------------------------


def _help_text(tool: dict) -> str:
    invoke = tool.get("path") or tool.get("name") or ""
    if not invoke:
        return ""
    out = _safe_run([invoke, "--help"])
    return out[:_HELP_LIMIT]


def _man_text(tool: dict) -> str:
    name = tool.get("name") or ""
    if not name:
        return ""
    # Only attempt man if it exists; a missing man page -> "".
    if not shutil.which("man"):
        return ""
    out = _safe_run(["man", name])
    return out[:_MAN_LIMIT]


def _pkg_desc(tool: dict) -> str:
    """Best-effort package description via dpkg -s / apt show / pip show.

    Returns the first ``Description``/``Summary`` line found, or "".
    """
    name = tool.get("name") or ""
    if not name:
        return ""

    for cmd in (
        ["dpkg", "-s", name],
        ["apt", "show", name],
        ["pip", "show", name],
    ):
        out = _safe_run(cmd)
        desc = _extract_description(out)
        if desc:
            return desc[:_PKG_LIMIT]
    return ""


def _extract_description(text: str) -> str:
    """Pull the Description/Summary field out of dpkg/apt/pip output."""
    if not text:
        return ""
    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("description:"):
            return stripped.split(":", 1)[1].strip()
        if low.startswith("summary:"):  # pip show
            return stripped.split(":", 1)[1].strip()
    return ""


def build_signal_bundle(tool: dict) -> dict:
    """Gather grounding signals for one tool.

    Returns a dict with keys: name, path, existing_description, help_text,
    man_text, pkg_desc. Never raises — a missing/failing source yields "".
    """
    return {
        "name": tool.get("name", ""),
        "path": tool.get("path", ""),
        "existing_description": tool.get("description", "") or "",
        "help_text": _help_text(tool),
        "man_text": _man_text(tool),
        "pkg_desc": _pkg_desc(tool),
    }


# ---------------------------------------------------------------------------
# prompt
# ---------------------------------------------------------------------------


def _build_prompt(bundle: dict) -> str:
    """Construct the grounded enrichment prompt from the bundle text."""
    return (
        "Classify the following tool for a forensic tool catalog using ONLY "
        "the text below. Do not invent anything. Output \"unknown\" or [] "
        "when the text does not clearly support a value.\n\n"
        f"Tool name: {bundle.get('name', '')}\n"
        f"Path: {bundle.get('path', '')}\n"
        f"Existing description: {bundle.get('existing_description', '')}\n\n"
        "--- man page ---\n"
        f"{bundle.get('man_text', '')}\n\n"
        "--- package description ---\n"
        f"{bundle.get('pkg_desc', '')}\n\n"
        "--- help output ---\n"
        f"{bundle.get('help_text', '')}\n\n"
        "Respond with a single JSON object with these keys:\n"
        '  "relevant": boolean (false ONLY for clear non-forensic OS/'
        "coreutils noise),\n"
        '  "description": string,\n'
        '  "target_os": list of EVIDENCE OSes this tool analyzes '
        "(windows|linux|macos|android|ios), or [\"any\"] if cross-platform, "
        'or "unknown" if unclear,\n'
        '  "domains": list from [disk, memory, timeline, artifacts, network, '
        'malware], or ["any"] if general-purpose,\n'
        '  "input_types": list of strings (or []),\n'
        '  "output_types": list of strings (or []),\n'
        '  "capabilities": list of strings (or []),\n'
        '  "runtime": string (or ""),\n'
        '  "usage_examples": list of strings (or []),\n'
        '  "confidence": "high" | "medium" | "low".\n'
    )


# ---------------------------------------------------------------------------
# normalization helpers
# ---------------------------------------------------------------------------


def _as_list(value: Any) -> list:
    """Coerce to a clean list of strings; anything unusable -> []."""
    if isinstance(value, list):
        return [v for v in value if v not in (None, "")]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


# Canonicalize the many ways an OS gets named into the lowercase tokens the
# gate compares against, so the catalog never carries "Windows" vs "windows"
# vs "Microsoft Windows" for the same thing.
_OS_CANON = {
    "windows": "windows", "win": "windows", "microsoft windows": "windows",
    "win32": "windows", "win64": "windows",
    "linux": "linux", "gnu/linux": "linux", "unix": "linux",
    "macos": "macos", "mac os": "macos", "mac os x": "macos", "osx": "macos",
    "os x": "macos", "darwin": "macos", "apple": "macos", "mac": "macos",
    "android": "android",
    "ios": "ios", "iphone": "ios", "ipados": "ios",
    "any": "any", "all": "any", "cross-platform": "any",
    "cross platform": "any", "unknown": "any", "n/a": "any",
}

# The fixed set of investigative agent domains a tool may be scoped to.
_AGENT_DOMAINS = {"disk", "memory", "timeline", "artifacts", "network", "malware"}


def _canon_os(token: str) -> str:
    """Map one OS string to its canonical lowercase token (else lowercased)."""
    t = str(token).strip().lower()
    return _OS_CANON.get(t, t)


def _normalize_target_os(value: Any) -> list:
    """Fail-open OS normalization to canonical lowercase tokens.

    "unknown" / omitted / empty / unusable -> ["any"]. Known synonyms collapse
    (e.g. "Microsoft Windows" -> "windows", "OSX" -> "macos"); the presence of
    any universal token ("any"/"cross-platform"/"unknown") collapses to ["any"].
    """
    items: list[str] = []
    if isinstance(value, list):
        items = [str(v).strip() for v in value if str(v).strip()]
    elif isinstance(value, str) and value.strip():
        items = [value.strip()]

    if not items:
        return ["any"]
    canon = [_canon_os(i) for i in items]
    if "any" in canon:
        return ["any"]
    # De-dup, preserve order.
    seen: set[str] = set()
    out = [c for c in canon if not (c in seen or seen.add(c))]
    return out


def _normalize_domains(value: Any) -> list:
    """Fail-open domain normalization to the known agent-domain set.

    Keeps only recognized domains (disk/memory/timeline/artifacts/network/
    malware). A universal token, or no recognized domain, fails open to ["any"]
    so a mis-tagged tool is shown to ALL agents rather than wrongly hidden.
    """
    items = _as_list(value)
    out: list[str] = []
    for v in items:
        s = str(v).strip().lower()
        if s in ("any", "all"):
            return ["any"]
        if s in _AGENT_DOMAINS and s not in out:
            out.append(s)
    return out or ["any"]


def _provenance(confidence: str, model: str, enriched_at: str) -> dict:
    return {
        "source": "llm",
        "model": model,
        "enriched_at": enriched_at,
        "confidence": confidence,
    }


def _failopen_entry(tool: dict, model: str, enriched_at: str) -> dict:
    """Catalog entry used when the LLM is unavailable / unparseable.

    Keep the tool, mark relevant, OS fail-open to ["any"], no invented
    specifics, confidence "unknown".
    """
    return {
        "name": tool.get("name", ""),
        "path": tool.get("path", ""),
        "relevant": True,
        "description": tool.get("description", "") or "",
        "target_os": ["any"],
        "domains": ["any"],
        "input_types": [],
        "output_types": [],
        "capabilities": [],
        "runtime": "",
        "usage_examples": [],
        "provenance": _provenance("unknown", model, enriched_at),
    }


# ---------------------------------------------------------------------------
# enrichment
# ---------------------------------------------------------------------------


def enrich_tool(
    tool: dict,
    bundle: dict,
    model: str = _DEFAULT_MODEL,
    now: str = "",
    enriched_at: str = "",
    trust_relevant: bool = False,
) -> Optional[dict]:
    """Enrich one tool into a catalog entry, or None if the LLM deems it
    non-forensic noise (``relevant == false``).

    ``model``/``now`` (alias ``enriched_at``) are passed in so callers
    control determinism; this function never calls datetime.now().

    ``trust_relevant`` short-circuits the relevance drop: when True (used for
    tools that are forensic BY LOCATION, e.g. discovered in ``/usr/local/bin``),
    a ``relevant: false`` verdict is ignored and the tool is kept and enriched
    anyway. The relevance filter then only prunes the package-sourced candidates.
    """
    stamp = enriched_at or now or ""

    prompt = _build_prompt(bundle)
    result = call_claude_json(prompt, system_prompt=_SYSTEM_PROMPT)

    # Fail open: unavailable or unparseable result -> keep tool, unknown.
    if not isinstance(result, dict):
        return _failopen_entry(tool, model, stamp)

    # The LLM may filter out non-forensic noise — unless this tool is trusted by
    # location (a forensic-dir install), in which case we keep it regardless.
    if result.get("relevant") is False and not trust_relevant:
        return None

    confidence = result.get("confidence") or _DEFAULT_CONFIDENCE

    return {
        "name": tool.get("name", ""),
        "path": tool.get("path", ""),
        "relevant": True,
        "description": str(
            result.get("description")
            or tool.get("description", "")
            or ""
        ),
        "target_os": _normalize_target_os(result.get("target_os")),
        "domains": _normalize_domains(result.get("domains")),
        "input_types": _as_list(result.get("input_types")),
        "output_types": _as_list(result.get("output_types")),
        "capabilities": _as_list(result.get("capabilities")),
        "runtime": str(result.get("runtime") or ""),
        "usage_examples": _as_list(result.get("usage_examples")),
        "provenance": _provenance(str(confidence), model, stamp),
    }
