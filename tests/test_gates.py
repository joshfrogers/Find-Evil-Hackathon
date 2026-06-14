"""Tests for catalog/gates.py — the 3 deterministic, fail-open runtime
tool-selection gates plus the combining gate_tools().

Pure unit tests: no Claude, no executor. They exercise every fail-open
branch directly, using the canonical catalog tool dict shape.
"""

import sys
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from catalog.gates import domain_ok, gate_tools, input_ok, is_installed, os_ok


def _tool(**overrides):
    """Canonical catalog tool dict, overridable per-field."""
    base = {
        "name": "RegRipper",
        "path": "/usr/bin/rip.pl",
        "installed": True,
        "target_os": ["windows"],
        "input_types": ["registry_hive", "artifact"],
        "runtime": "perl",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# is_installed
# --------------------------------------------------------------------------
class TestIsInstalled(unittest.TestCase):
    def test_installed_true(self):
        self.assertTrue(is_installed({"installed": True}))

    def test_installed_false(self):
        self.assertFalse(is_installed({"installed": False}))

    def test_missing_field_fail_open_true(self):
        # Missing field -> True (fail-open)
        self.assertTrue(is_installed({"name": "x"}))

    def test_empty_dict_fail_open_true(self):
        self.assertTrue(is_installed({}))

    def test_only_explicit_false_gates_out(self):
        # Non-False falsy/odd values are not "explicitly False" -> True
        self.assertTrue(is_installed({"installed": None}))
        self.assertTrue(is_installed({"installed": "no"}))
        self.assertTrue(is_installed({"installed": 0}))
        self.assertTrue(is_installed({"installed": 1}))


# --------------------------------------------------------------------------
# os_ok
# --------------------------------------------------------------------------
class TestOsOk(unittest.TestCase):
    def test_target_os_missing_true_on_any_image(self):
        self.assertTrue(os_ok({}, "linux"))
        self.assertTrue(os_ok({}, "windows"))
        self.assertTrue(os_ok({}, None))

    def test_target_os_empty_true(self):
        self.assertTrue(os_ok({"target_os": []}, "linux"))

    def test_universal_token_any_true(self):
        self.assertTrue(os_ok({"target_os": ["any"]}, "linux"))
        self.assertTrue(os_ok({"target_os": ["any"]}, "windows"))

    def test_universal_token_cross_platform_true(self):
        self.assertTrue(os_ok({"target_os": ["cross-platform"]}, "linux"))

    def test_evidence_os_none_fail_open_true(self):
        self.assertTrue(os_ok({"target_os": ["windows"]}, None))

    def test_evidence_os_empty_string_fail_open_true(self):
        self.assertTrue(os_ok({"target_os": ["windows"]}, ""))

    def test_windows_tool_on_linux_evidence_false(self):
        self.assertFalse(os_ok({"target_os": ["windows"]}, "linux"))

    def test_windows_tool_on_windows_evidence_true(self):
        self.assertTrue(os_ok({"target_os": ["windows"]}, "windows"))

    def test_multi_os_macos_evidence_false(self):
        self.assertFalse(os_ok({"target_os": ["windows", "linux"]}, "macos"))

    def test_multi_os_windows_evidence_true(self):
        self.assertTrue(os_ok({"target_os": ["windows", "linux"]}, "windows"))

    def test_case_insensitive_compare(self):
        self.assertTrue(os_ok({"target_os": ["Windows"]}, "windows"))
        self.assertTrue(os_ok({"target_os": ["windows"]}, "WINDOWS"))
        self.assertFalse(os_ok({"target_os": ["Windows"]}, "Linux"))
        self.assertTrue(os_ok({"target_os": ["ANY"]}, "linux"))

    def test_target_os_not_a_list_fail_open_true(self):
        # Non-list target_os is not a "non-empty list" -> fail open
        self.assertTrue(os_ok({"target_os": "windows"}, "linux"))


# --------------------------------------------------------------------------
# input_ok
# --------------------------------------------------------------------------
class TestInputOk(unittest.TestCase):
    def test_input_types_missing_true(self):
        self.assertTrue(input_ok({}, "disk"))

    def test_input_types_empty_true(self):
        self.assertTrue(input_ok({"input_types": []}, "disk"))

    def test_contains_any_true(self):
        self.assertTrue(input_ok({"input_types": ["memory_image", "any"]}, "disk"))

    def test_unknown_kind_fail_open_true(self):
        # evidence_kind unknown -> fail open even with a restrictive list
        self.assertTrue(input_ok({"input_types": ["memory_image"]}, "weird_kind"))

    def test_disk_accepts_registry_hive(self):
        self.assertTrue(input_ok({"input_types": ["registry_hive"]}, "disk"))

    def test_disk_accepts_filesystem(self):
        self.assertTrue(input_ok({"input_types": ["filesystem"]}, "disk"))

    def test_disk_accepts_disk_image(self):
        self.assertTrue(input_ok({"input_types": ["disk_image"]}, "disk"))

    def test_disk_accepts_artifact(self):
        self.assertTrue(input_ok({"input_types": ["artifact"]}, "disk"))

    def test_disk_rejects_memory_only(self):
        # memory_image shares nothing with the disk accepted set -> gated out
        self.assertFalse(input_ok({"input_types": ["memory_image"]}, "disk"))

    def test_memory_accepts_memory_image(self):
        self.assertTrue(input_ok({"input_types": ["memory_image"]}, "memory"))

    def test_memory_rejects_disk_image(self):
        self.assertFalse(input_ok({"input_types": ["disk_image"]}, "memory"))

    def test_pcap_accepts_pcap(self):
        self.assertTrue(input_ok({"input_types": ["pcap"]}, "pcap"))

    def test_pcap_rejects_logs(self):
        self.assertFalse(input_ok({"input_types": ["logs"]}, "pcap"))

    def test_logs_accepts_logs(self):
        self.assertTrue(input_ok({"input_types": ["logs"]}, "logs"))

    def test_logs_rejects_pcap(self):
        self.assertFalse(input_ok({"input_types": ["pcap"]}, "logs"))

    def test_intersection_passes(self):
        # Shares at least one accepted member -> pass
        self.assertTrue(
            input_ok({"input_types": ["pcap", "logs"]}, "logs")
        )

    def test_input_types_not_a_list_fail_open_true(self):
        self.assertTrue(input_ok({"input_types": "registry_hive"}, "disk"))


# --------------------------------------------------------------------------
# gate_tools — combining gate (AND of all three), order-stable
# --------------------------------------------------------------------------
class TestGateTools(unittest.TestCase):
    def test_all_pass_kept(self):
        t = _tool()  # windows registry tool
        self.assertEqual(gate_tools([t], "windows", "disk"), [t])

    def test_os_gate_filters(self):
        t = _tool()  # windows-only
        self.assertEqual(gate_tools([t], "linux", "disk"), [])

    def test_installed_gate_filters(self):
        t = _tool(installed=False)
        self.assertEqual(gate_tools([t], "windows", "disk"), [])

    def test_input_gate_filters(self):
        t = _tool(input_types=["memory_image"])
        self.assertEqual(gate_tools([t], "windows", "disk"), [])

    def test_order_stable(self):
        a = _tool(name="a")
        b = _tool(name="b")
        c = _tool(name="c", installed=False)  # gated out
        d = _tool(name="d")
        result = gate_tools([a, b, c, d], "windows", "disk")
        self.assertEqual([t["name"] for t in result], ["a", "b", "d"])

    def test_empty_list(self):
        self.assertEqual(gate_tools([], "windows", "disk"), [])

    def test_fail_open_undetected_os_keeps_os_specific_tool(self):
        # evidence_os None -> os gate fails open, tool kept if other gates pass
        t = _tool()  # windows-only, registry input
        self.assertEqual(gate_tools([t], None, "disk"), [t])

    def test_combined_and_requires_every_gate(self):
        # Passes installed + input but fails os -> dropped
        t = _tool(target_os=["linux"])
        self.assertEqual(gate_tools([t], "windows", "disk"), [])


class TestDomainOk(unittest.TestCase):
    def test_untagged_tool_kept_for_any_domain(self):
        # Older catalogs carry no `domains` -> fail open (shown to all agents).
        self.assertTrue(domain_ok(_tool(), "memory"))

    def test_any_token_kept_for_any_domain(self):
        self.assertTrue(domain_ok(_tool(domains=["any"]), "memory"))

    def test_no_domain_context_keeps(self):
        self.assertTrue(domain_ok(_tool(domains=["disk"]), None))

    def test_scoped_tool_dropped_for_other_domain(self):
        self.assertFalse(domain_ok(_tool(domains=["memory"]), "disk"))

    def test_scoped_tool_kept_for_its_domain(self):
        self.assertTrue(domain_ok(_tool(domains=["memory", "timeline"]), "timeline"))

    def test_domain_match_is_case_insensitive(self):
        self.assertTrue(domain_ok(_tool(domains=["Memory"]), "memory"))


class TestGateToolsDomain(unittest.TestCase):
    def _mem(self):
        return _tool(
            name="vol", target_os=["any"], input_types=["any"], domains=["memory"]
        )

    def _disk(self):
        return _tool(
            name="fls", target_os=["any"], input_types=["any"], domains=["disk"]
        )

    def test_domain_arg_scopes_the_menu(self):
        # disk agent on a disk image sees only the disk-domain tool.
        out = gate_tools([self._mem(), self._disk()], "windows", "disk", "disk")
        self.assertEqual([t["name"] for t in out], ["fls"])

    def test_no_domain_arg_keeps_all_gated(self):
        # Backward-compatible: omitting the domain arg applies no domain filter.
        out = gate_tools([self._mem(), self._disk()], "windows", "disk")
        self.assertEqual({t["name"] for t in out}, {"vol", "fls"})

    def test_untagged_tools_survive_domain_filter(self):
        untagged = _tool(name="strings", target_os=["any"], input_types=["any"])
        out = gate_tools([untagged, self._mem()], "windows", "disk", "disk")
        self.assertEqual([t["name"] for t in out], ["strings"])


if __name__ == "__main__":
    unittest.main()
