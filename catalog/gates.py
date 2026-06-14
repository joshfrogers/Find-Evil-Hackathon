"""Deterministic, fail-open runtime tool-selection gates.

These are the three cheap, deterministic filters applied before a tool is
ever proposed to the reasoning loop. They answer a narrow question: "could
this tool conceivably run against THIS evidence on THIS image?" They are NOT
a relevance ranker — relevance is decided downstream.

Design principle: FAIL OPEN. When a gate lacks the metadata needed to make a
confident "no", it returns True (keep the tool). A missing/ambiguous field
must never silently hide a tool that might actually be the right one; an
over-broad candidate list is cheap, a wrongly-excluded tool is a blind spot.

A "tool" is a plain dict from the catalog, canonical shape::

    {"name": "RegRipper", "path": "/usr/bin/rip.pl", "installed": True,
     "target_os": ["windows"], "input_types": ["registry_hive", "artifact"],
     "runtime": "perl", ...}

Stdlib only. Pure functions: no I/O, no global state.
"""

from typing import Dict, List, Optional

# OS tokens that mean "runs anywhere" — their presence makes the OS gate pass
# on any image, regardless of the detected evidence OS.
_UNIVERSAL_OS_TOKENS = {"any", "cross-platform"}

# Map of evidence kind -> the set of input_types a tool may declare and still
# be considered able to consume that kind of evidence. "any" is always honored
# separately (see input_ok), and is included here for completeness.
_KIND_ACCEPTS: Dict[str, set] = {
    "disk": {"disk_image", "filesystem", "artifact", "registry_hive", "any"},
    "memory": {"memory_image", "any"},
    "pcap": {"pcap", "any"},
    "logs": {"logs", "any"},
}


def is_installed(tool: dict) -> bool:
    """True unless the tool is explicitly marked not installed.

    Only an explicit ``installed == False`` gates the tool out. A missing
    field (or any other value) fails open to True — we'd rather attempt a
    tool and let the executor report a real "not found" than pre-hide it on
    incomplete catalog metadata.
    """
    return tool.get("installed") is not False


def os_ok(tool: dict, evidence_os: Optional[str]) -> bool:
    """True unless the tool's declared OS is provably incompatible with the
    detected evidence OS.

    Returns True (fail open) UNLESS ALL of the following hold:
      * ``target_os`` is a non-empty list,
      * it contains no universal token ("any" / "cross-platform"),
      * ``evidence_os`` is a known, non-empty string, AND
      * ``evidence_os`` is not among ``target_os``.

    Comparison is case-insensitive. Consequences:
      * target_os missing/empty/["any"]  -> True on any image
      * evidence_os None/"" (undetected) -> True (fail open)
      * ["windows"] on linux  -> False;  on windows -> True
      * ["windows","linux"] on macos -> False; on windows -> True
    """
    target_os = tool.get("target_os")

    # Not a non-empty list -> no OS constraint to enforce -> keep.
    if not isinstance(target_os, list) or not target_os:
        return True

    normalized = {str(o).lower() for o in target_os}

    # Declared as universal -> runs anywhere -> keep.
    if normalized & _UNIVERSAL_OS_TOKENS:
        return True

    # Evidence OS undetected -> we cannot prove incompatibility -> keep.
    if not evidence_os:
        return True

    # Concrete constraint AND concrete evidence: keep only on a match.
    return str(evidence_os).lower() in normalized


def input_ok(tool: dict, evidence_kind: str) -> bool:
    """True unless the tool's declared input_types share nothing with the set
    accepted for a KNOWN evidence kind.

    Returns True (fail open) when:
      * ``input_types`` is missing/empty, OR
      * ``input_types`` contains "any", OR
      * ``input_types`` intersects the accepted set for the kind, OR
      * ``evidence_kind`` is unknown (not in the kind map).

    Only gates OUT when ``input_types`` is a non-empty list that shares NOTHING
    with the accepted set of a recognized kind.
    """
    input_types = tool.get("input_types")

    # No declared inputs -> no constraint to enforce -> keep.
    if not isinstance(input_types, list) or not input_types:
        return True

    declared = {str(t).lower() for t in input_types}

    # Universal input declaration -> keep.
    if "any" in declared:
        return True

    accepted = _KIND_ACCEPTS.get(str(evidence_kind).lower())

    # Unknown evidence kind -> we have no basis to exclude -> keep.
    if accepted is None:
        return True

    # Keep only if the tool can consume at least one accepted input form.
    return bool(declared & accepted)


def domain_ok(tool: dict, domain_name: Optional[str]) -> bool:
    """True unless the tool's declared ``domains`` provably excludes this agent
    domain.

    Returns True (fail open) when:
      * ``domains`` is missing/empty (older catalogs carry no domain tag), OR
      * ``domains`` contains the universal token "any", OR
      * ``domain_name`` is empty/None (no domain context to filter on), OR
      * ``domain_name`` is among ``domains``.

    Only gates OUT when ``domains`` is a non-empty list, has no "any", and does
    not contain ``domain_name`` — so a memory-only tool is hidden from the disk
    agent, but an untagged or ["any"] tool is shown to every agent. Comparison
    is case-insensitive.
    """
    domains = tool.get("domains")
    if not isinstance(domains, list) or not domains:
        return True
    normalized = {str(d).lower() for d in domains}
    if "any" in normalized:
        return True
    if not domain_name:
        return True
    return str(domain_name).lower() in normalized


def gate_tools(
    tools: List[dict],
    evidence_os: Optional[str],
    evidence_kind: str,
    domain_name: Optional[str] = None,
) -> List[dict]:
    """Return the subset of ``tools`` passing ALL gates (AND).

    Always applies the three evidence gates (installed / target_os / input_type).
    When ``domain_name`` is given, ALSO applies the fail-open domain gate so an
    agent only sees tools scoped to its domain (untagged/``any`` tools still
    pass). ``domain_name=None`` (the default) skips domain filtering, preserving
    the prior behavior and backward compatibility with un-tagged catalogs.

    Order-stable: surviving tools keep their original relative order.
    """
    return [
        tool
        for tool in tools
        if is_installed(tool)
        and os_ok(tool, evidence_os)
        and input_ok(tool, evidence_kind)
        and domain_ok(tool, domain_name)
    ]
