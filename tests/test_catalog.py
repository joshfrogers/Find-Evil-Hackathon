"""Tests for tool_registry.catalog.

Covers local-catalog path resolution, load, sticky-override merge,
installed-hash stability, and staleness computation.
"""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest

from tool_registry import catalog

FIXTURE = (
    pathlib.Path(__file__).parent / "fixtures" / "catalog" / "tool_catalog.json"
)


class CatalogPathTest(unittest.TestCase):
    def test_catalog_path_default_is_cwd(self) -> None:
        expected = pathlib.Path(os.getcwd()) / "tool_catalog.json"
        self.assertEqual(catalog.catalog_path(None), expected)

    def test_catalog_path_honors_override(self) -> None:
        self.assertEqual(
            catalog.catalog_path("/x/y.json"), pathlib.Path("/x/y.json")
        )

    def test_overrides_path_default_is_cwd(self) -> None:
        expected = pathlib.Path(os.getcwd()) / "overrides.json"
        self.assertEqual(catalog.overrides_path(None), expected)

    def test_overrides_path_honors_override(self) -> None:
        self.assertEqual(
            catalog.overrides_path("/x/over.json"),
            pathlib.Path("/x/over.json"),
        )


class LoadTest(unittest.TestCase):
    def test_load_missing_raises_catalog_missing(self) -> None:
        with self.assertRaises(catalog.CatalogMissing):
            catalog.load_tool_inventory(
                pathlib.Path("/no/such/tool_catalog.json")
            )

    def test_load_fixture_returns_six_tools(self) -> None:
        tools = catalog.load_tool_inventory(FIXTURE)
        self.assertEqual(len(tools), 6)
        names = [t["name"] for t in tools]
        self.assertIn("RegRipper", names)

    def test_load_catalog_returns_metadata(self) -> None:
        obj = catalog.load_catalog(FIXTURE)
        self.assertEqual(obj["metadata"]["tool_count"], 6)
        self.assertEqual(len(obj["tools"]), 6)

    def test_load_malformed_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / "tool_catalog.json"
            bad.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(ValueError):
                catalog.load_tool_inventory(bad)


class MergeOverridesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tools = catalog.load_tool_inventory(FIXTURE)

    def test_override_replaces_field_and_stamps_human(self) -> None:
        overrides = {"RegRipper": {"target_os": ["windows", "linux"]}}
        merged = catalog.merge_overrides(self.tools, overrides)
        rr = next(t for t in merged if t["name"] == "RegRipper")
        self.assertEqual(rr["target_os"], ["windows", "linux"])
        self.assertEqual(rr["provenance"]["target_os"], "human")

    def test_override_leaves_other_fields_and_tools(self) -> None:
        overrides = {"RegRipper": {"target_os": ["windows", "linux"]}}
        merged = catalog.merge_overrides(self.tools, overrides)
        rr = next(t for t in merged if t["name"] == "RegRipper")
        # untouched field on same tool
        self.assertEqual(rr["runtime"], "perl")
        # untouched provenance for other fields
        self.assertNotEqual(rr["provenance"].get("runtime"), "human")
        # other tools pass through unchanged
        vol = next(t for t in merged if t["name"] == "vol")
        self.assertEqual(vol["target_os"], ["any"])

    def test_override_order_stable(self) -> None:
        overrides = {"vol": {"runtime": "python3"}}
        merged = catalog.merge_overrides(self.tools, overrides)
        self.assertEqual(
            [t["name"] for t in merged], [t["name"] for t in self.tools]
        )

    def test_override_for_absent_tool_ignored(self) -> None:
        overrides = {"NotARealTool": {"runtime": "x"}}
        merged = catalog.merge_overrides(self.tools, overrides)
        names = [t["name"] for t in merged]
        self.assertNotIn("NotARealTool", names)
        self.assertEqual(len(merged), len(self.tools))

    def test_empty_overrides_passes_through(self) -> None:
        merged = catalog.merge_overrides(self.tools, {})
        self.assertEqual(
            [t["name"] for t in merged], [t["name"] for t in self.tools]
        )


class InstalledHashTest(unittest.TestCase):
    def test_hash_stable_for_same_set(self) -> None:
        tools = catalog.load_tool_inventory(FIXTURE)
        h1 = catalog.installed_hash(tools)
        h2 = catalog.installed_hash(list(reversed(tools)))
        self.assertEqual(h1, h2)

    def test_hash_changes_on_add(self) -> None:
        tools = catalog.load_tool_inventory(FIXTURE)
        h1 = catalog.installed_hash(tools)
        h2 = catalog.installed_hash(tools + [{"name": "newtool"}])
        self.assertNotEqual(h1, h2)

    def test_hash_changes_on_remove(self) -> None:
        tools = catalog.load_tool_inventory(FIXTURE)
        h1 = catalog.installed_hash(tools)
        h2 = catalog.installed_hash(tools[:-1])
        self.assertNotEqual(h1, h2)


class StalenessTest(unittest.TestCase):
    def test_changed_true_when_hash_differs(self) -> None:
        tools = catalog.load_tool_inventory(FIXTURE)
        meta = {
            "refreshed_at": "2026-06-14T00:00:00Z",
            "installed_hash": "stale-different-hash",
        }
        result = catalog.staleness(meta, tools, today_iso="2026-06-14")
        self.assertTrue(result["changed"])

    def test_changed_false_when_hash_matches(self) -> None:
        tools = catalog.load_tool_inventory(FIXTURE)
        meta = {
            "refreshed_at": "2026-06-14T00:00:00Z",
            "installed_hash": catalog.installed_hash(tools),
        }
        result = catalog.staleness(meta, tools, today_iso="2026-06-14")
        self.assertFalse(result["changed"])

    def test_changed_false_when_no_enumerated(self) -> None:
        meta = {"refreshed_at": "2026-06-14T00:00:00Z", "installed_hash": "x"}
        result = catalog.staleness(meta, None, today_iso="2026-06-14")
        self.assertFalse(result["changed"])

    def test_days_since_computed(self) -> None:
        meta = {"refreshed_at": "2026-06-01T00:00:00Z", "installed_hash": "x"}
        result = catalog.staleness(meta, None, today_iso="2026-06-14")
        self.assertEqual(result["days_since"], 13)

    def test_days_since_none_when_unparseable(self) -> None:
        meta = {"refreshed_at": "not-a-date", "installed_hash": "x"}
        result = catalog.staleness(meta, None, today_iso="2026-06-14")
        self.assertIsNone(result["days_since"])

    def test_refreshed_at_passed_through(self) -> None:
        meta = {"refreshed_at": "2026-06-01T00:00:00Z", "installed_hash": "x"}
        result = catalog.staleness(meta, None, today_iso="")
        self.assertEqual(result["refreshed_at"], "2026-06-01T00:00:00Z")
        self.assertIsNone(result["days_since"])


if __name__ == "__main__":
    unittest.main()
