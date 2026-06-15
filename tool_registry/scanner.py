"""Forensic-tool enumeration + catalog diffing for the self-updating catalog.

This is the *discovery* half of the self-updating catalog: pure tool
ENUMERATION and DIFF, with NO LLM and NO enrichment. It answers two questions:

  1. enumerate_tools() — what candidate forensic tools exist on this host?
  2. diff_catalog()    — how does that live inventory differ from the persisted
     catalog? (new / changed / removed.)

Why not "enumerate the whole box", and why NO hand-maintained tool list?
----------------------------------------------------------------------
A real SIFT workstation has ~6,600 binaries+packages (all of ``/usr/bin``,
every ``dpkg``/``pip`` package). Two deterministic, self-maintaining signals
narrow that to forensic candidates WITHOUT a curated list (which would silently
miss whatever it forgot — e.g. ``autopsy``/``bulk_extractor``/``dislocker``):

  * Forensic DIRECTORIES — ``/usr/local/bin`` etc. On a SIFT box these hold the
    manually-installed forensic tools (RegRipper, the Zimmerman parsers,
    volatility, …); everything in them is forensic by location, so they are kept
    WHOLESALE and TRUSTED (the enrichment step does NOT relevance-filter them).
  * MANUALLY-INSTALLED packages — ``apt-mark showmanual`` is the set the box's
    owner explicitly installed (it excludes the base system and auto-pulled
    dependencies: coreutils, libc, fonts, …). Their binaries (via ``dpkg -L``)
    are the candidate apt tools. This catches every apt-installed forensic tool
    in ``/usr/bin`` (sleuthkit, plaso, bulk-extractor, dislocker, …) with no
    list to maintain.

The manual set still includes general dev tooling (bash, grep, git, editors),
so those candidates are passed to the enrichment step, whose grounded,
man-page-based ``relevant:false`` filter prunes non-forensic noise. Net: forensic
dirs are trusted as-is; manual-package binaries are LLM-relevance-checked.

Hermetic-by-design
------------------
Every external interaction funnels through two tiny module-level indirections,
``_run(cmd)`` and ``_listdir(path)``, so tests monkeypatch them and never shell
out. Off a Debian/apt host ``apt-mark``/``dpkg`` yield "", so enumeration falls
back to the forensic dirs alone (fail-open, never crashes).
"""

from __future__ import annotations

import os
import subprocess

# Directories whose executables are forensic BY LOCATION on a SIFT-style box:
# manual installs (SANS puts the bulk of the toolkit in /usr/local/bin) and
# /opt sub-trees. Everything found here is kept wholesale AND trusted (no
# relevance filtering downstream). ``/opt/*/bin`` is expanded at scan time.
_FORENSIC_DIRS = (
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt/sift/bin",
)

# Bin-dir prefixes a packaged binary may live under. ``dpkg -L`` lists every
# file a package ships; we keep only the leaf executables directly under one of
# these (so docs/man/lib paths are ignored).
_BIN_DIR_PREFIXES = (
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
)


# ---------------------------------------------------------------------------
# External-call indirection (the ONLY things tests need to monkeypatch)
# ---------------------------------------------------------------------------


# Per-command wall-clock cap. dpkg -L / apt-mark can stall (locked dpkg db, slow
# disk); without a bound a single hung call deadlocks the whole catalog refresh,
# which iterates over every manually-installed package. 30s is generous for these
# metadata queries while still guaranteeing forward progress.
_RUN_TIMEOUT_S = 30


def _run(cmd: list[str]) -> str:
    """Run a command and return its stdout as text (empty string on failure).

    The single choke-point for subprocess use in this module so tests can stub
    it. Never raises — a missing binary, non-zero exit, or timeout yields "".
    """
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=_RUN_TIMEOUT_S,
        )
        return proc.stdout or ""
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return ""


def _listdir(path: str) -> list[str]:
    """List a directory's entries (empty list if it does not exist).

    The single choke-point for filesystem listing so tests can stub it.
    """
    try:
        return os.listdir(path)
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Source 1: forensic directories (kept wholesale, trusted)
# ---------------------------------------------------------------------------


def _forensic_dirs() -> list[str]:
    """Ordered, de-duplicated forensic bin directories to scan wholesale.

    The fixed forensic dirs plus every ``/opt/*/bin`` (globbed via ``_listdir``
    so it stays behind the test seam).
    """
    dirs: list[str] = []
    seen: set[str] = set()

    def _add(d: str) -> None:
        if d and d not in seen:
            seen.add(d)
            dirs.append(d)

    for d in _FORENSIC_DIRS:
        _add(d)
    for child in _listdir("/opt"):
        _add(os.path.join("/opt", child, "bin"))
    return dirs


def _is_noise(name: str) -> bool:
    """Skip obvious non-tool directory entries (dotfiles, backups, docs)."""
    if not name or name.startswith("."):
        return True
    return name.endswith((".bak", ".md", ".txt", ".json", ".cfg", ".conf"))


def _enumerate_forensic_dirs() -> list[dict]:
    """Every entry in the forensic dirs — forensic by location. source=='dir'."""
    found: list[dict] = []
    for d in _forensic_dirs():
        for name in _listdir(d):
            if _is_noise(name):
                continue
            found.append(
                {
                    "name": name,
                    "path": os.path.join(d, name),
                    "package": "",
                    "source": "dir",
                }
            )
    return found


# ---------------------------------------------------------------------------
# Source 2: manually-installed packages' binaries (relevance-checked later)
# ---------------------------------------------------------------------------


def _manual_packages() -> list[str]:
    """Explicitly-installed package names, via ``apt-mark showmanual``.

    This is the box owner's deliberate install set — it excludes the base system
    and auto-pulled dependencies, so it is the natural "exclude system binaries"
    signal. Empty off an apt host.
    """
    out = _run(["apt-mark", "showmanual"])
    return [line.strip() for line in out.splitlines() if line.strip()]


def _package_binaries(pkg: str) -> list[str]:
    """Leaf executables a package ships into a bin dir, via ``dpkg -L``.

    Returns full paths of files that sit DIRECTLY under a bin-dir prefix (so
    docs/man/lib/data paths the package also ships are ignored).
    """
    out = _run(["dpkg", "-L", pkg])
    bins: list[str] = []
    for line in out.splitlines():
        path = line.strip()
        for prefix in _BIN_DIR_PREFIXES:
            if path.startswith(prefix):
                remainder = path[len(prefix) :]
                if remainder and "/" not in remainder:
                    bins.append(path)
                break
    return bins


def _enumerate_manual_packages() -> list[dict]:
    """Binaries of every manually-installed package. source=='pkg'.

    Includes general dev tooling (bash/grep/git) — those are pruned downstream
    by the enrichment step's man-page-grounded relevance filter, not here.
    """
    found: list[dict] = []
    for pkg in _manual_packages():
        for path in _package_binaries(pkg):
            found.append(
                {
                    "name": os.path.basename(path),
                    "path": path,
                    "package": pkg,
                    "source": "pkg",
                }
            )
    return found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enumerate_tools() -> list[dict]:
    """Enumerate the box's candidate forensic tools.

    Two deterministic sources, no hand-maintained list:
      * forensic DIRS (``/usr/local/bin`` …) — kept wholesale, ``source='dir'``
        (trusted; not relevance-filtered downstream).
      * MANUALLY-installed packages' bin binaries — ``source='pkg'``
        (relevance-filtered downstream by the man-page-grounded enricher).

    Returns a list of dicts, one per unique tool name::

        {"name": <basename>, "path": <abspath or "">,
         "package": <pkg or "">, "source": "dir"|"pkg"}

    Dedup is by ``name``, *first source wins* (forensic DIRS first, then
    packages). When a later source carries a ``path`` or ``package`` the
    surviving entry lacked, that value is MERGED in — so a tool found both in a
    forensic dir and via a package keeps its dir path and gains its package,
    while keeping ``source == "dir"`` (and thus its trusted status).

    Pure enumeration: no version probing, no categorization, no enrichment, no
    LLM. Relevance refinement happens later, at enrichment time, grounded in
    each tool's man page.
    """
    ordered: list[dict] = []
    ordered.extend(_enumerate_forensic_dirs())
    ordered.extend(_enumerate_manual_packages())

    by_name: dict[str, dict] = {}
    result: list[dict] = []
    for tool in ordered:
        name = tool["name"]
        existing = by_name.get(name)
        if existing is None:
            entry = dict(tool)
            by_name[name] = entry
            result.append(entry)
        else:
            # Merge: fill in any field the surviving (first) entry is missing.
            if not existing.get("path") and tool.get("path"):
                existing["path"] = tool["path"]
            if not existing.get("package") and tool.get("package"):
                existing["package"] = tool["package"]
    return result


def diff_catalog(
    enumerated: list[dict], catalog: list[dict]
) -> tuple[list[dict], list[dict], list[dict]]:
    """Diff a freshly enumerated inventory against the persisted catalog.

    Returns ``(new, changed, removed)``:

    * ``new``     — enumerated entries whose name is absent from the catalog.
    * ``changed`` — names present in BOTH but whose ``path``, ``package``, or
      ``version`` differ (missing keys compare as ""). The enumerated entry is
      returned (it carries the fresh values).
    * ``removed`` — catalog entries whose name is absent from the enumerated
      set. These are returned VERBATIM — diff_catalog does NOT mutate them or
      set ``installed: false``; flagging removed tools is the caller's job.

    A tool that is byte-stable across both sides appears in NONE of the three.
    """
    enum_by_name = {t["name"]: t for t in enumerated}
    cat_by_name = {t["name"]: t for t in catalog}

    new: list[dict] = []
    changed: list[dict] = []
    removed: list[dict] = []

    for name, etool in enum_by_name.items():
        ctool = cat_by_name.get(name)
        if ctool is None:
            new.append(etool)
        elif _differs(etool, ctool):
            changed.append(etool)

    for name, ctool in cat_by_name.items():
        if name not in enum_by_name:
            removed.append(ctool)

    return new, changed, removed


def _differs(a: dict, b: dict) -> bool:
    """True if the two tool dicts disagree on path, package, or version."""
    for key in ("path", "package", "version"):
        if a.get(key, "") != b.get(key, ""):
            return True
    return False
