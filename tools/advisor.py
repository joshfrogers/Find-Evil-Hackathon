"""Adaptive tool selection & error recovery for forensic investigations.

The ToolAdvisor lets the agent adapt to the evidence it is actually
given on a Linux SIFT host — it learns which tools work on this image,
stops retrying known-bad ones, catches inapplicable tools before they run,
and routes to a working alternative when a tool fails. The goal is 0 hard
tool failures per run: every failure degrades gracefully.

Two dominant failure classes motivated this (from inventory analysis):
  1. .NET Windows .exe parsers (MFTECmd, RECmd, EvtxECmd, AmcacheParser,
     ...) cannot execute natively on the Linux SIFT box. Each has a
     Perl/Python equivalent already present in the inventory.
  2. Artifact parsers handed a raw .E01 disk image instead of an extracted
     artifact file.

One ToolAdvisor instance is created per investigation (per image) and
shared across triage and all sub-agents, so the compatibility matrix
accumulates over the whole run.
"""

from __future__ import annotations

import os
import platform
import tempfile
import threading
import uuid


class ToolAdvisor:
    """Per-image tool compatibility tracker, pre-validator, and fallback router."""

    # Capability -> ordered tool identifiers, best-first. Identifiers are
    # canonical lowercase tokens that match a tool's name, path basename, or
    # symlink basename in tool_inventory.json — inventory names can be messy
    # (e.g. "RegRipper (rip.pl)"), so matching on basenames makes resolution
    # robust regardless of which alias the registry exposes. Chains are derived
    # from the inventory; confirm against a real sample-case run.
    FALLBACK_CHAINS: dict[str, list[str]] = {
        "mft": ["mftecmd", "analyzemft", "mft.pl"],
        # recmd (RECmd) is .NET — best on a Windows host, but always rejected by
        # blocking_reason on the Linux SIFT box; rip.pl (RegRipper) is the Linux
        # primary parser; regslack.pl recovers deleted/slack registry data when
        # rip.pl comes up empty. (The doc's "regipy" is not in tool_inventory.json,
        # and regtime.pl is timestamp-only — it lives in the "timeline" chain.)
        "registry": ["recmd", "rip.pl", "regslack.pl"],
        "evtx": ["evtxecmd", "evtx_dump.py", "evtxparse.pl"],
        "amcache": ["amcacheparser", "amcache.py"],
        "prefetch": ["pref.pl"],
        "usn": ["usn.py", "usnjls", "usnj.pl"],
        # bulk_extractor serves a different purpose (feature extraction), so it
        # is intentionally excluded from the carving chain.
        "carving": ["foremost", "scalpel", "photorec"],
        "timeline": ["tsk_gettimes", "mactime", "log2timeline.py"],
    }

    # Runtimes that cannot execute natively on a Linux SIFT host.
    INCOMPATIBLE_RUNTIMES_ON_LINUX = {".net", "windows", "powershell"}

    # Raw disk-image extensions — artifact parsers need an extracted file, not
    # one of these.
    RAW_IMAGE_EXTS = (".e01", ".ex01", ".dd", ".raw", ".img", ".vmdk")

    # Categories whose tools parse a single extracted artifact (not a raw image).
    ARTIFACT_PARSER_CATEGORIES = {
        "windows_artifact_analysis",
        "windows_event_log_analysis",
    }

    # Capabilities that operate on extracted artifacts rather than raw images.
    ARTIFACT_CAPABILITIES = {"mft", "registry", "evtx", "amcache", "prefetch", "usn"}

    MAX_FALLBACKS = 3

    def __init__(self, host_os: str | None = None) -> None:
        # Resolve the host OS once; default to the live platform.
        self.host_os = (host_os or platform.system() or "").lower()
        # tool_path -> {"successes": int, "failures": int, "last_error": str}
        self._matrix: dict[str, dict] = {}
        # One advisor is shared across concurrently-running sub-agents, so the
        # compatibility matrix (read-modify-write + iteration) is guarded against
        # races (lost updates, "dict changed size during iteration").
        self._matrix_lock = threading.Lock()
        # token -> capability, built once from FALLBACK_CHAINS.
        self._capability_index: dict[str, str] = {}
        for capability, tokens in self.FALLBACK_CHAINS.items():
            for token in tokens:
                self._capability_index[token] = capability

    # --- compatibility matrix ------------------------------------------------

    def record_result(self, tool_path: str, success: bool, error: str = "") -> None:
        """Record one tool attempt on this image."""
        with self._matrix_lock:
            entry = self._matrix.setdefault(
                tool_path, {"successes": 0, "failures": 0, "last_error": ""}
            )
            if success:
                entry["successes"] += 1
            else:
                entry["failures"] += 1
                if error:
                    entry["last_error"] = error

    def is_known_bad(self, tool_path: str) -> bool:
        """True only if the tool has failed and never succeeded on this image.

        A tool that succeeded at least once is not blacklisted by a later
        bad-args failure.
        """
        with self._matrix_lock:
            entry = self._matrix.get(tool_path)
            if not entry:
                return False
            return entry["failures"] > 0 and entry["successes"] == 0

    def matrix(self) -> dict:
        """Return a copy of the per-image compatibility matrix (for the report)."""
        with self._matrix_lock:
            return {path: dict(stats) for path, stats in self._matrix.items()}

    # --- pre-validation ------------------------------------------------------

    def blocking_reason(
        self,
        tool_dict: dict | None,
        tool_path: str,
        args: list[str],
        evidence_type: str = "",
    ) -> str | None:
        """Return a reason string if the tool should NOT run, else None.

        Never raises on missing fields — unknown tools are allowed (None).
        """
        runtime = str((tool_dict or {}).get("runtime", "")).lower()
        if runtime in self.INCOMPATIBLE_RUNTIMES_ON_LINUX and self._is_linux():
            return (
                f"runtime '{(tool_dict or {}).get('runtime')}' "
                "not executable on Linux SIFT host"
            )

        if self._is_artifact_parser(tool_dict, tool_path) and self._args_have_raw_image(
            args
        ):
            name = (
                (tool_dict or {}).get("name")
                or os.path.basename(tool_path.rstrip("/"))
                or tool_path
            )
            return (
                f"{name} needs an extracted artifact, not a raw image; "
                "extract via EvidenceManager first"
            )

        return None

    # --- argument remediation ------------------------------------------------

    def normalize_args(
        self,
        tool_dict: dict | None,
        tool_path: str,
        args: list[str],
        scratch_dir: str | None = None,
    ) -> list[str]:
        """Return ``args`` with known tool-specific, argument-level problems fixed.

        Some tools fail because of their arguments, not the tool itself — an
        invalid flag, or a missing/unwritable output directory. A like-for-like
        fallback cannot recover these: every alternative shares the arg shape and
        fails identically. We correct them here, before execution, so the failure
        does not count as a hard failure. Currently handled (the two smoke-test
        offenders on base-sample-case):

          * ``tsk_loaddb`` — drop the invalid ``-f <fs>`` flag. tsk_loaddb has no
            filesystem-type option; passing ``-f ntfs`` makes it exit non-zero.
          * ``bulk_extractor`` — ensure a writable ``-o <dir>`` output directory.
            bulk_extractor must create its output dir, so the parent must exist
            and be writable; if ``-o`` is absent we inject one under
            ``scratch_dir`` (the "couldn't create output dir" failure).

        Unknown tools, and tools with no known arg issue, pass through unchanged.
        ``scratch_dir`` should be a writable location off the read-only evidence
        mount (e.g. the evidence extraction cache); it defaults to the system
        temp dir.
        """
        tokens = self._identifiers(tool_dict, tool_path)
        fixed = list(args or [])

        if "tsk_loaddb" in tokens:
            fixed = self._drop_flag_with_value(fixed, "-f")

        if "bulk_extractor" in tokens:
            fixed = self._ensure_output_dir(fixed, "-o", scratch_dir)

        return fixed

    @staticmethod
    def _drop_flag_with_value(args: list[str], flag: str) -> list[str]:
        """Remove ``flag`` and the single value token that follows it."""
        out: list[str] = []
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg == flag:
                skip_next = True  # also drop the flag's value
                continue
            out.append(arg)
        return out

    def _ensure_output_dir(
        self, args: list[str], flag: str, scratch_dir: str | None
    ) -> list[str]:
        """Guarantee ``flag``'s output directory is creatable, injecting one if absent.

        The tool creates the output dir itself, so we only ensure its parent
        exists and is writable. When ``flag`` is missing we append it pointing at
        a fresh, non-existent dir under a writable scratch root.
        """
        root = scratch_dir or tempfile.gettempdir()
        if not self._make_writable_dir(root):
            root = tempfile.gettempdir()
            self._make_writable_dir(root)

        out = list(args)
        if flag in out:
            idx = out.index(flag)
            if idx + 1 < len(out):
                requested = out[idx + 1]
                if scratch_dir and os.path.isabs(requested):
                    requested_real = os.path.realpath(requested)
                    root_real = os.path.realpath(root)
                    if not self._is_under_dir(requested_real, root_real):
                        name = (
                            os.path.basename(requested.rstrip("/"))
                            or self._outdir_name()
                        )
                        out[idx + 1] = os.path.join(root, name)
                        return out
                parent = os.path.dirname(requested.rstrip("/")) or root
                if not self._make_writable_dir(parent):
                    # Requested parent is unwritable — redirect under the scratch root.
                    name = (
                        os.path.basename(requested.rstrip("/")) or self._outdir_name()
                    )
                    out[idx + 1] = os.path.join(root, name)
                return out
            # Trailing ``-o`` with no value — give it one.
            out.append(os.path.join(root, self._outdir_name()))
            return out

        # No output flag at all — inject one so the tool writes somewhere writable.
        return out + [flag, os.path.join(root, self._outdir_name())]

    @staticmethod
    def _make_writable_dir(path: str) -> bool:
        """Create ``path`` (and parents) if needed; return True if it's writable."""
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            return False
        return os.access(path, os.W_OK)

    @staticmethod
    def _is_under_dir(path: str, root: str) -> bool:
        try:
            return os.path.commonpath([path, root]) == root
        except ValueError:
            return False

    @staticmethod
    def _outdir_name() -> str:
        """A fresh, collision-free output-dir name (the tool creates the dir)."""
        return f"bulk_extractor_out_{uuid.uuid4().hex[:8]}"

    # --- fallback routing ----------------------------------------------------

    def suggest_fallback(
        self,
        failed_tool_path: str,
        failed_tool_dict: dict | None,
        available_tools: list[dict],
    ) -> dict | None:
        """Return the next working alternative tool dict, or None.

        Resolves the failed tool to a capability, then walks its chain for the
        next tool that is present in available_tools and not known-bad. The
        returned dict carries the path the caller needs to retry.
        """
        capability = self._capability_for(failed_tool_path, failed_tool_dict)
        if not capability:
            return None

        chain = self.FALLBACK_CHAINS.get(capability, [])
        failed_token = self._matched_token(failed_tool_path, failed_tool_dict, chain)
        # Start after the failed tool's position in the chain (if found),
        # otherwise consider the whole chain. Walking forward only means an
        # A -> B -> A cycle can never happen.
        start = chain.index(failed_token) + 1 if failed_token in chain else 0

        for token in chain[start:]:
            alt = self._find_available(token, available_tools)
            if alt is None:
                continue
            if alt.get("path") == failed_tool_path:
                continue  # never suggest the tool we just failed
            if self.is_known_bad(alt["path"]):
                continue
            return alt
        return None

    # --- helpers -------------------------------------------------------------

    def _is_linux(self) -> bool:
        return self.host_os == "linux"

    @staticmethod
    def _identifiers(tool_dict: dict | None, tool_path: str = "") -> set[str]:
        """Canonical lowercase tokens identifying a tool: name, path basename,
        and symlink basename. Basenames are the reliable match because inventory
        names can be messy (e.g. "RegRipper (rip.pl)")."""
        tokens: set[str] = set()
        d = tool_dict or {}
        path = d.get("path") or tool_path
        if path:
            tokens.add(os.path.basename(path.rstrip("/")).lower())
        symlink = d.get("symlink")
        if symlink:
            tokens.add(os.path.basename(symlink.rstrip("/")).lower())
        name = d.get("name")
        if name:
            tokens.add(name.lower())
        tokens.discard("")
        return tokens

    def _capability_for(self, tool_path: str, tool_dict: dict | None) -> str | None:
        for token in self._identifiers(tool_dict, tool_path):
            capability = self._capability_index.get(token)
            if capability:
                return capability
        return None

    def _matched_token(
        self, tool_path: str, tool_dict: dict | None, chain: list[str]
    ) -> str | None:
        for token in self._identifiers(tool_dict, tool_path):
            if token in chain:
                return token
        return None

    def _find_available(self, token: str, available_tools: list[dict]) -> dict | None:
        for tool in available_tools or []:
            if token in self._identifiers(tool, tool.get("path", "")):
                return tool
        return None

    def _is_artifact_parser(self, tool_dict: dict | None, tool_path: str) -> bool:
        category = str((tool_dict or {}).get("category", ""))
        if category in self.ARTIFACT_PARSER_CATEGORIES:
            return True
        return self._capability_for(tool_path, tool_dict) in self.ARTIFACT_CAPABILITIES

    def _args_have_raw_image(self, args: list[str]) -> bool:
        return any(
            str(arg).lower().endswith(self.RAW_IMAGE_EXTS) for arg in (args or [])
        )
