"""Tests for tool_registry/enrich.py — the grounded, provenance-stamped LLM
enrichment step.

call_claude_json is stubbed at its lookup location in the enrich module so
no real network calls are made.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tool_registry.enrich import (
    build_signal_bundle,
    enrich_tool,
)


def _tool(**overrides):
    """A minimal raw tool dict as produced by the crawler."""
    t = {
        "name": "volatility3",
        "path": "/usr/local/bin/vol.py",
        "description": "Memory forensics framework",
    }
    t.update(overrides)
    return t


def _bundle(**overrides):
    """A canonical grounding bundle."""
    b = {
        "name": "volatility3",
        "path": "/usr/local/bin/vol.py",
        "existing_description": "Memory forensics framework",
        "help_text": "usage: vol.py [-h] ...",
        "man_text": "",
        "pkg_desc": "Advanced memory forensics framework",
    }
    b.update(overrides)
    return b


_FULL_PAYLOAD = {
    "relevant": True,
    "description": "Extracts artifacts from memory images.",
    "target_os": ["windows", "linux"],
    "input_types": ["memory_image"],
    "output_types": ["text", "json"],
    "capabilities": ["process_listing", "network_connections"],
    "runtime": "python3",
    "usage_examples": ["vol.py -f mem.raw windows.pslist"],
    "confidence": "high",
}


# ---------------------------------------------------------------------------
# build_signal_bundle
# ---------------------------------------------------------------------------


class BuildSignalBundleTest(unittest.TestCase):
    def test_gathers_all_signals(self):
        """Every grounding source is routed through _run and merged."""

        def fake_run(cmd):
            joined = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            if "--help" in joined:
                return "usage: vol.py [-h] ..."
            if cmd and "man" in joined.split()[0:2]:
                return "VOL(1) memory forensics manual"
            if "dpkg" in joined or "apt" in joined or "pip" in joined:
                return "Description: Advanced memory forensics framework"
            return ""

        with patch(
            "tool_registry.enrich._run", side_effect=fake_run
        ):
            bundle = build_signal_bundle(_tool())

        self.assertEqual(bundle["name"], "volatility3")
        self.assertEqual(bundle["path"], "/usr/local/bin/vol.py")
        self.assertEqual(
            bundle["existing_description"], "Memory forensics framework"
        )
        self.assertIn("usage: vol.py", bundle["help_text"])
        self.assertIn("memory forensics", bundle["man_text"])
        self.assertIn("memory forensics framework", bundle["pkg_desc"])

    def test_failing_source_yields_empty_string_never_raises(self):
        """A source that raises must degrade to '' rather than propagate."""

        def boom(cmd):
            raise OSError("command not found")

        with patch("tool_registry.enrich._run", side_effect=boom):
            bundle = build_signal_bundle(_tool())

        self.assertEqual(bundle["help_text"], "")
        self.assertEqual(bundle["man_text"], "")
        self.assertEqual(bundle["pkg_desc"], "")
        # Identity fields still present.
        self.assertEqual(bundle["name"], "volatility3")

    def test_help_text_truncated_to_about_4kb(self):
        big = "x" * 10000

        with patch(
            "tool_registry.enrich._run", return_value=big
        ):
            bundle = build_signal_bundle(_tool())

        self.assertLessEqual(len(bundle["help_text"]), 4096)


# ---------------------------------------------------------------------------
# enrich_tool
# ---------------------------------------------------------------------------


class EnrichToolTest(unittest.TestCase):
    @patch("tool_registry.enrich.call_claude_json")
    def test_full_payload_populates_all_fields_and_provenance(self, mock_llm):
        mock_llm.return_value = dict(_FULL_PAYLOAD)

        entry = enrich_tool(
            _tool(), _bundle(), model="test-model", now="2026-06-14T00:00:00Z"
        )

        self.assertIsNotNone(entry)
        # Identity passthrough.
        self.assertEqual(entry["name"], "volatility3")
        self.assertEqual(entry["path"], "/usr/local/bin/vol.py")
        # LLM-derived fields.
        self.assertTrue(entry["relevant"])
        self.assertEqual(
            entry["description"], "Extracts artifacts from memory images."
        )
        self.assertCountEqual(entry["target_os"], ["windows", "linux"])
        self.assertEqual(entry["input_types"], ["memory_image"])
        self.assertCountEqual(entry["output_types"], ["text", "json"])
        self.assertIn("process_listing", entry["capabilities"])
        self.assertEqual(entry["runtime"], "python3")
        self.assertIn("vol.py -f mem.raw windows.pslist", entry["usage_examples"])
        # Provenance stamp.
        prov = entry["provenance"]
        self.assertIsInstance(prov, dict)
        self.assertEqual(prov["source"], "llm")
        self.assertEqual(prov["model"], "test-model")
        self.assertEqual(prov["enriched_at"], "2026-06-14T00:00:00Z")
        self.assertEqual(prov["confidence"], "high")

    @patch("tool_registry.enrich.call_claude_json")
    def test_relevant_false_returns_none(self, mock_llm):
        mock_llm.return_value = {"relevant": False}

        entry = enrich_tool(_tool(), _bundle())

        self.assertIsNone(entry)

    @patch("tool_registry.enrich.call_claude_json")
    def test_llm_none_keeps_tool_failopen_unknown(self, mock_llm):
        mock_llm.return_value = None

        entry = enrich_tool(_tool(), _bundle())

        self.assertIsNotNone(entry)
        # Kept (fail-open) and marked relevant so it is not silently dropped.
        self.assertTrue(entry["relevant"])
        self.assertEqual(entry["target_os"], ["any"])
        # No invented specifics.
        self.assertEqual(entry["input_types"], [])
        self.assertEqual(entry["output_types"], [])
        self.assertEqual(entry["capabilities"], [])
        self.assertEqual(entry["provenance"]["confidence"], "unknown")
        self.assertEqual(entry["name"], "volatility3")

    @patch("tool_registry.enrich.call_claude_json")
    def test_target_os_unknown_string_normalized_to_any(self, mock_llm):
        payload = dict(_FULL_PAYLOAD)
        payload["target_os"] = "unknown"
        mock_llm.return_value = payload

        entry = enrich_tool(_tool(), _bundle())

        self.assertIsNotNone(entry)
        self.assertEqual(entry["target_os"], ["any"])

    @patch("tool_registry.enrich.call_claude_json")
    def test_target_os_omitted_normalized_to_any(self, mock_llm):
        payload = dict(_FULL_PAYLOAD)
        payload.pop("target_os")
        mock_llm.return_value = payload

        entry = enrich_tool(_tool(), _bundle())

        self.assertIsNotNone(entry)
        self.assertEqual(entry["target_os"], ["any"])

    @patch("tool_registry.enrich.call_claude_json")
    def test_unparseable_payload_kept_failopen(self, mock_llm):
        # Not a dict -> treated like None (fail-open keep).
        mock_llm.return_value = ["not", "a", "dict"]

        entry = enrich_tool(_tool(), _bundle())

        self.assertIsNotNone(entry)
        self.assertTrue(entry["relevant"])
        self.assertEqual(entry["target_os"], ["any"])
        self.assertEqual(entry["provenance"]["confidence"], "unknown")

    @patch("tool_registry.enrich.call_claude_json")
    def test_default_confidence_is_medium_when_llm_omits(self, mock_llm):
        payload = dict(_FULL_PAYLOAD)
        payload.pop("confidence")
        mock_llm.return_value = payload

        entry = enrich_tool(_tool(), _bundle())

        self.assertEqual(entry["provenance"]["confidence"], "medium")

    @patch("tool_registry.enrich.call_claude_json")
    def test_prompt_is_grounded_in_bundle_text(self, mock_llm):
        mock_llm.return_value = dict(_FULL_PAYLOAD)

        enrich_tool(_tool(), _bundle())

        self.assertTrue(mock_llm.called)
        prompt = mock_llm.call_args.args[0] if mock_llm.call_args.args else ""
        # Grounding text from the bundle must be in the prompt.
        self.assertIn("Advanced memory forensics framework", prompt)
        self.assertIn("usage: vol.py", prompt)


class EnrichDomainsAndOsTest(unittest.TestCase):
    """Per-domain tagging + canonical OS normalization added so the catalog
    scopes each agent's menu and the OS gate compares clean tokens."""

    @patch("tool_registry.enrich.call_claude_json")
    def test_domains_kept_and_invalid_dropped(self, mock_llm):
        mock_llm.return_value = {
            "relevant": True,
            "domains": ["Memory", "bogus-domain"],
            "target_os": ["any"],
        }
        entry = enrich_tool(_tool(), _bundle())
        self.assertEqual(entry["domains"], ["memory"])

    @patch("tool_registry.enrich.call_claude_json")
    def test_domains_failopen_to_any_when_none_valid(self, mock_llm):
        mock_llm.return_value = {
            "relevant": True,
            "domains": ["nonsense"],
            "target_os": ["any"],
        }
        entry = enrich_tool(_tool(), _bundle())
        self.assertEqual(entry["domains"], ["any"])

    @patch("tool_registry.enrich.call_claude_json")
    def test_target_os_synonyms_canonicalized(self, mock_llm):
        mock_llm.return_value = {
            "relevant": True,
            "target_os": ["Microsoft Windows", "OSX"],
        }
        entry = enrich_tool(_tool(), _bundle())
        self.assertCountEqual(entry["target_os"], ["windows", "macos"])

    @patch("tool_registry.enrich.call_claude_json")
    def test_cross_platform_token_collapses_to_any(self, mock_llm):
        mock_llm.return_value = {
            "relevant": True,
            "target_os": ["windows", "cross-platform"],
        }
        entry = enrich_tool(_tool(), _bundle())
        self.assertEqual(entry["target_os"], ["any"])

    @patch("tool_registry.enrich.call_claude_json")
    def test_failopen_entry_has_domains_any(self, mock_llm):
        mock_llm.return_value = None  # LLM unavailable -> fail-open entry
        entry = enrich_tool(_tool(), _bundle())
        self.assertEqual(entry["domains"], ["any"])

    @patch("tool_registry.enrich.call_claude_json")
    def test_prompt_requests_domains_field(self, mock_llm):
        mock_llm.return_value = {"relevant": True, "target_os": ["any"]}
        enrich_tool(_tool(), _bundle())
        prompt = mock_llm.call_args.args[0] if mock_llm.call_args.args else ""
        self.assertIn("domains", prompt)


if __name__ == "__main__":
    unittest.main()
