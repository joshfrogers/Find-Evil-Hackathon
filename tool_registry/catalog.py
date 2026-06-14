"""Local tool-catalog resolution, load, sticky-override merge, and staleness.

The catalog is a JSON file shaped as::

    {
      "metadata": {
        "refreshed_at": <iso8601>,
        "installed_hash": <str>,
        "tool_count": <int>
      },
      "tools": [ <tool entry dicts> ]
    }

This module resolves catalog/overrides paths (CWD-relative by default so the
catalog travels with the working tree, not the package), loads the inventory,
deep-merges human overrides on top of enriched tool entries (override wins
per-field and is re-stamped with ``source: "human"`` provenance), computes a
stable hash of the installed tool set, and reports staleness.

Stdlib only. Callers are responsible for any instruct-then-exit behavior on
``CatalogMissing`` — this module never calls ``sys.exit``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
from datetime import date, datetime
from typing import Any


class CatalogMissing(Exception):
    """Raised when a requested catalog file does not exist.

    Callers may catch this to print install/refresh instructions and exit;
    this module deliberately does not terminate the process itself.
    """


def catalog_path(arg: str | None) -> pathlib.Path:
    """Resolve the catalog file path.

    If ``arg`` is provided, it is used verbatim. Otherwise the default is
    ``<cwd>/tool_catalog.json`` (the current working directory, NOT the
    package directory) so the catalog lives alongside the working tree.
    """
    if arg:
        return pathlib.Path(arg)
    return pathlib.Path(os.getcwd()) / "tool_catalog.json"


def overrides_path(arg: str | None) -> pathlib.Path:
    """Resolve the overrides file path.

    If ``arg`` is provided, it is used verbatim. Otherwise the default is
    ``overrides.json`` resolved next to the default catalog's directory
    (the current working directory).
    """
    if arg:
        return pathlib.Path(arg)
    return catalog_path(None).parent / "overrides.json"


def load_catalog(path: pathlib.Path) -> dict[str, Any]:
    """Read and return the whole catalog object (metadata + tools).

    Raises:
        CatalogMissing: if ``path`` does not exist.
        ValueError: if the file is not valid JSON.
    """
    path = pathlib.Path(path)
    if not path.exists():
        raise CatalogMissing(f"Catalog file not found: {path}")
    raw = path.read_text(encoding="utf-8")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed catalog JSON at {path}: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError(f"Catalog root must be an object: {path}")
    return obj


def load_tool_inventory(path: pathlib.Path) -> list[dict[str, Any]]:
    """Read the catalog and return the flat ``tools`` list.

    Raises:
        CatalogMissing: if ``path`` does not exist.
        ValueError: if the file is malformed or ``tools`` is not a list.
    """
    obj = load_catalog(path)
    tools = obj.get("tools", [])
    if not isinstance(tools, list):
        raise ValueError(f"Catalog 'tools' must be a list: {path}")
    return tools


def merge_overrides(
    enriched: list[dict[str, Any]],
    overrides: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deep-merge human overrides on top of enriched tool entries.

    ``overrides`` maps a tool ``name`` to a partial field dict. For each tool
    present in ``enriched``, any overridden field replaces the enriched value
    (override always wins, never clobbered by enrichment) and that field's
    provenance is re-stamped to ``"human"``. Fields and tools not mentioned in
    ``overrides`` pass through unchanged. Overrides naming a tool that is not
    present are ignored. Output order matches ``enriched``.
    """
    result: list[dict[str, Any]] = []
    for tool in enriched:
        name = tool.get("name")
        override = overrides.get(name) if name is not None else None
        if not override:
            result.append(tool)
            continue
        merged = copy.deepcopy(tool)
        provenance = merged.get("provenance")
        if not isinstance(provenance, dict):
            provenance = {}
        else:
            provenance = dict(provenance)
        for field, value in override.items():
            merged[field] = copy.deepcopy(value)
            provenance[field] = "human"
        merged["provenance"] = provenance
        result.append(merged)
    return result


def installed_hash(enumerated: list[dict[str, Any]]) -> str:
    """Return a stable hash of the installed tool set.

    The hash depends only on the *set* of tool names: the same set yields the
    same hash regardless of ordering, while adding or removing a tool changes
    it. Tools without a ``name`` are skipped.
    """
    names = sorted(
        {t["name"] for t in enumerated if t.get("name") is not None}
    )
    payload = "\n".join(names).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _parse_iso_date(value: str) -> date | None:
    """Best-effort parse of an ISO-8601 date or datetime into a date.

    Returns None if the value cannot be parsed. Tolerates a trailing 'Z'.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        pass
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def staleness(
    catalog_meta: dict[str, Any],
    enumerated: list[dict[str, Any]] | None = None,
    *,
    today_iso: str = "",
) -> dict[str, Any]:
    """Report catalog staleness.

    Returns a dict with:
        refreshed_at: the catalog's ``refreshed_at`` string (or "").
        days_since: integer days between ``refreshed_at`` and ``today_iso``
            when both parse, else None.
        changed: True iff ``enumerated`` is given AND its installed_hash differs
            from ``catalog_meta["installed_hash"]``.

    ``today_iso`` must be passed explicitly for deterministic behavior; this
    function never calls ``datetime.now()``.
    """
    refreshed_at = catalog_meta.get("refreshed_at", "") or ""

    days_since: int | None = None
    refreshed_date = _parse_iso_date(refreshed_at)
    today_date = _parse_iso_date(today_iso)
    if refreshed_date is not None and today_date is not None:
        days_since = (today_date - refreshed_date).days

    changed = False
    if enumerated is not None:
        changed = installed_hash(enumerated) != catalog_meta.get(
            "installed_hash"
        )

    return {
        "refreshed_at": refreshed_at,
        "days_since": days_since,
        "changed": changed,
    }
