"""Unit tests for the self-updating tool-catalog scanner.

These tests NEVER shell out. Every external interaction (`_run`, `_listdir`)
is monkeypatched with canned forensic-dir / apt-mark / dpkg output so the suite
is hermetic and deterministic regardless of the host the tests run on.

The scanner sources candidates from two deterministic, list-free signals:
forensic DIRS (kept wholesale, source='dir') and the binaries of
MANUALLY-installed packages (`apt-mark showmanual` -> `dpkg -L`, source='pkg').
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tool_registry import scanner


# ---------------------------------------------------------------------------
# Canned external-command output
# ---------------------------------------------------------------------------

# `apt-mark showmanual`: one package name per line. Includes a forensic package
# (sleuthkit) and a general dev tool (bash) — the scanner keeps both; relevance
# pruning of bash happens later, in the enrichment step, not here.
APT_MARK_OUTPUT = "sleuthkit\nbulk-extractor\nbash\n"

# `dpkg -L <pkg>` output per package: a mix of bin paths (kept) and
# doc/man/lib paths (ignored).
DPKG_L = {
    "sleuthkit": "/usr/bin/fls\n/usr/bin/mmls\n/usr/share/doc/sleuthkit/README\n/usr/bin\n",
    "bulk-extractor": "/usr/bin/bulk_extractor\n/usr/share/man/man1/bulk_extractor.1.gz\n",
    "bash": "/usr/bin/bash\n/bin/bash\n/etc/bash.bashrc\n",
}


def _fake_run(cmd):
    """Return canned stdout for the apt-mark / dpkg commands the scanner runs."""
    if cmd[:2] == ["apt-mark", "showmanual"]:
        return APT_MARK_OUTPUT
    if len(cmd) >= 3 and cmd[0] == "dpkg" and cmd[1] == "-L":
        return DPKG_L.get(cmd[2], "")
    return ""


def _fake_listdir(path):
    """Return canned executable basenames for the forensic dirs we scan."""
    table = {
        "/usr/local/bin": ["rip.pl", "volatility3", "notes.txt"],
    }
    return table.get(path, [])


class EnumerateToolsTest(unittest.TestCase):
    def setUp(self):
        # Restrict the forensic dir set to one our fake listdir knows, so the
        # result is fully deterministic.
        self._dirs_patcher = patch.object(
            scanner, "_forensic_dirs", return_value=["/usr/local/bin"]
        )
        self._dirs_patcher.start()
        self._run_patcher = patch.object(scanner, "_run", side_effect=_fake_run)
        self._run_patcher.start()
        self._ls_patcher = patch.object(
            scanner, "_listdir", side_effect=_fake_listdir
        )
        self._ls_patcher.start()

    def tearDown(self):
        self._dirs_patcher.stop()
        self._run_patcher.stop()
        self._ls_patcher.stop()

    def test_returns_list_of_dicts_with_required_keys(self):
        tools = scanner.enumerate_tools()
        self.assertIsInstance(tools, list)
        self.assertTrue(tools)
        for t in tools:
            self.assertIn("name", t)
            self.assertIn("path", t)
            self.assertIn("package", t)
            self.assertIn("source", t)
            self.assertIn(t["source"], ("dir", "pkg"))

    def test_forensic_dir_tool_kept_with_dir_source(self):
        tools = {t["name"]: t for t in scanner.enumerate_tools()}
        self.assertIn("rip.pl", tools)
        self.assertEqual(tools["rip.pl"]["path"], "/usr/local/bin/rip.pl")
        self.assertEqual(tools["rip.pl"]["source"], "dir")

    def test_noise_filtered_from_forensic_dir(self):
        # notes.txt is a doc, not a tool — the noise filter drops it.
        tools = {t["name"]: t for t in scanner.enumerate_tools()}
        self.assertNotIn("notes.txt", tools)

    def test_manual_package_bins_present_under_bin_dir_only(self):
        tools = {t["name"]: t for t in scanner.enumerate_tools()}
        # sleuthkit's /usr/bin binaries are kept...
        self.assertIn("fls", tools)
        self.assertEqual(tools["fls"]["source"], "pkg")
        self.assertEqual(tools["fls"]["package"], "sleuthkit")
        self.assertEqual(tools["fls"]["path"], "/usr/bin/fls")
        self.assertIn("mmls", tools)
        self.assertIn("bulk_extractor", tools)
        # ... but the doc/man/dir entries dpkg -L also lists are NOT tools.
        self.assertNotIn("README", tools)
        self.assertNotIn("bulk_extractor.1.gz", tools)

    def test_general_manual_tool_kept_at_scan_time(self):
        # bash is manually installed -> the scanner keeps it; the enrichment
        # step (not the scanner) is responsible for relevance-pruning it.
        tools = {t["name"]: t for t in scanner.enumerate_tools()}
        self.assertIn("bash", tools)
        self.assertEqual(tools["bash"]["source"], "pkg")

    def test_dedup_dir_wins_over_package(self):
        # volatility3 is in /usr/local/bin (dir). If a package also shipped it,
        # the dir entry wins (kept trusted). Here only the dir has it.
        tools = {t["name"]: t for t in scanner.enumerate_tools()}
        self.assertIn("volatility3", tools)
        self.assertEqual(tools["volatility3"]["source"], "dir")
        self.assertEqual(tools["volatility3"]["path"], "/usr/local/bin/volatility3")

    def test_no_duplicate_names(self):
        tools = scanner.enumerate_tools()
        names = [t["name"] for t in tools]
        self.assertEqual(len(names), len(set(names)))

    def test_falls_back_to_dirs_when_no_apt(self):
        # Off an apt host, apt-mark/dpkg yield "" -> only forensic dirs remain.
        with patch.object(scanner, "_run", return_value=""):
            tools = {t["name"]: t for t in scanner.enumerate_tools()}
        self.assertIn("rip.pl", tools)
        self.assertNotIn("fls", tools)


class DiffCatalogTest(unittest.TestCase):
    def test_new_tool_detected(self):
        enumerated = [
            {"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit"},
            {"name": "newtool", "path": "/usr/bin/newtool", "package": ""},
        ]
        catalog = [
            {"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit"},
        ]
        new, changed, removed = scanner.diff_catalog(enumerated, catalog)
        new_names = [t["name"] for t in new]
        self.assertIn("newtool", new_names)
        self.assertEqual(changed, [])
        self.assertEqual(removed, [])

    def test_removed_tool_detected_not_mutated(self):
        enumerated = [
            {"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit"},
        ]
        catalog = [
            {"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit"},
            {"name": "oldtool", "path": "/usr/bin/oldtool", "package": "old"},
        ]
        new, changed, removed = scanner.diff_catalog(enumerated, catalog)
        removed_names = [t["name"] for t in removed]
        self.assertIn("oldtool", removed_names)
        self.assertEqual(new, [])
        self.assertEqual(changed, [])
        # diff_catalog must NOT mutate the catalog entry (no installed flip).
        removed_tool = next(t for t in removed if t["name"] == "oldtool")
        self.assertNotIn("installed", removed_tool)

    def test_changed_on_path_difference(self):
        enumerated = [
            {"name": "fls", "path": "/usr/local/bin/fls", "package": "sleuthkit"},
        ]
        catalog = [
            {"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit"},
        ]
        new, changed, removed = scanner.diff_catalog(enumerated, catalog)
        changed_names = [t["name"] for t in changed]
        self.assertIn("fls", changed_names)
        self.assertEqual(new, [])
        self.assertEqual(removed, [])

    def test_changed_on_package_difference(self):
        enumerated = [{"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit2"}]
        catalog = [{"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit"}]
        new, changed, removed = scanner.diff_catalog(enumerated, catalog)
        self.assertEqual([t["name"] for t in changed], ["fls"])

    def test_changed_on_version_difference(self):
        enumerated = [
            {"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit", "version": "4.12"}
        ]
        catalog = [
            {"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit", "version": "4.11"}
        ]
        new, changed, removed = scanner.diff_catalog(enumerated, catalog)
        self.assertEqual([t["name"] for t in changed], ["fls"])

    def test_unchanged_tool_in_none(self):
        tool = {"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit", "version": "4.11"}
        enumerated = [dict(tool)]
        catalog = [dict(tool)]
        new, changed, removed = scanner.diff_catalog(enumerated, catalog)
        self.assertEqual(new, [])
        self.assertEqual(changed, [])
        self.assertEqual(removed, [])

    def test_missing_version_treated_as_empty(self):
        # Catalog has no version key; enumerated also lacks it -> unchanged.
        enumerated = [{"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit"}]
        catalog = [{"name": "fls", "path": "/usr/bin/fls", "package": "sleuthkit"}]
        new, changed, removed = scanner.diff_catalog(enumerated, catalog)
        self.assertEqual(changed, [])

    def test_returns_three_lists(self):
        result = scanner.diff_catalog([], [])
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        for part in result:
            self.assertIsInstance(part, list)


if __name__ == "__main__":
    unittest.main()
