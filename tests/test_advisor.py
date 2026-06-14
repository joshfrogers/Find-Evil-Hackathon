"""Tests for the ToolAdvisor (adaptive tool selection & error recovery).

These are pure unit tests: no Claude mock, no executor — they exercise the
advisor's matrix, pre-validation, and fallback routing directly.
"""

import os
import shutil
import sys
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.advisor import ToolAdvisor


# Representative tool dicts mirroring tool_inventory.json shape.
MFTECMD = {
    "name": "MFTECmd",
    "path": "/opt/zimmermantools/MFTECmd.exe",
    "symlink": "/usr/local/bin/mftecmd",
    "runtime": ".NET",
    "category": "windows_artifact_analysis",
}
ANALYZEMFT = {
    "name": "analyzemft",
    "path": "/opt/analyzemft/bin/analyzemft",
    "symlink": "/usr/local/bin/analyzemft",
    "category": "windows_artifact_analysis",
}
MFT_PL = {
    "name": "mft.pl",
    "path": "/usr/local/bin/mft.pl",
    "category": "log_analysis_scripting",
}
REGRIPPER = {
    "name": "RegRipper (rip.pl)",
    "path": "/usr/local/bin/rip.pl",
    "category": "windows_artifact_analysis",
}
FLS = {
    "name": "fls",
    "path": "/usr/bin/fls",
    "category": "disk_forensics",
}


class PreValidateTest(unittest.TestCase):
    def setUp(self):
        self.advisor = ToolAdvisor(host_os="Linux")

    def test_dotnet_on_linux_rejected(self):
        reason = self.advisor.blocking_reason(
            MFTECMD, MFTECMD["path"], ["/cases/MFT"], "disk"
        )
        self.assertIsNotNone(reason)
        self.assertIn("Linux", reason)

    def test_dotnet_allowed_off_linux(self):
        advisor = ToolAdvisor(host_os="Windows")
        reason = advisor.blocking_reason(MFTECMD, MFTECMD["path"], ["/cases/MFT"], "disk")
        self.assertIsNone(reason)

    def test_raw_image_to_artifact_parser_rejected(self):
        reason = self.advisor.blocking_reason(
            REGRIPPER, REGRIPPER["path"], ["/cases/image.E01"], "disk"
        )
        self.assertIsNotNone(reason)
        self.assertIn("extracted artifact", reason)

    def test_allows_when_runtime_and_category_missing(self):
        unknown = {"name": "mystery", "path": "/usr/bin/mystery"}
        reason = self.advisor.blocking_reason(
            unknown, unknown["path"], ["/cases/image.E01"], "disk"
        )
        self.assertIsNone(reason)

    def test_none_tool_dict_does_not_raise(self):
        self.assertIsNone(
            self.advisor.blocking_reason(None, "/usr/bin/whatever", ["/cases/x"], "disk")
        )

    def test_disk_tool_on_raw_image_allowed(self):
        # fls is not an artifact parser — operating on a raw image is fine.
        reason = self.advisor.blocking_reason(
            FLS, FLS["path"], ["-o", "0", "/cases/image.E01"], "disk"
        )
        self.assertIsNone(reason)


class IsKnownBadTest(unittest.TestCase):
    def setUp(self):
        self.advisor = ToolAdvisor(host_os="Linux")

    def test_lifecycle(self):
        path = MFTECMD["path"]
        self.assertFalse(self.advisor.is_known_bad(path))  # never seen

        self.advisor.record_result(path, success=False, error="boom")
        self.assertTrue(self.advisor.is_known_bad(path))  # failed, never succeeded

        self.advisor.record_result(path, success=True)
        self.assertFalse(self.advisor.is_known_bad(path))  # succeeded at least once

    def test_success_then_failure_not_known_bad(self):
        path = ANALYZEMFT["path"]
        self.advisor.record_result(path, success=True)
        self.advisor.record_result(path, success=False, error="bad args")
        self.assertFalse(self.advisor.is_known_bad(path))


class SuggestFallbackTest(unittest.TestCase):
    def setUp(self):
        self.advisor = ToolAdvisor(host_os="Linux")
        self.available = [MFTECMD, ANALYZEMFT, MFT_PL, FLS]

    def test_resolves_next_available_alternative(self):
        alt = self.advisor.suggest_fallback(MFTECMD["path"], MFTECMD, self.available)
        self.assertIsNotNone(alt)
        self.assertEqual(alt["name"], "analyzemft")

    def test_skips_known_bad_in_chain(self):
        # analyzemft already failed on this image — skip to mft.pl.
        self.advisor.record_result(ANALYZEMFT["path"], success=False, error="x")
        alt = self.advisor.suggest_fallback(MFTECMD["path"], MFTECMD, self.available)
        self.assertIsNotNone(alt)
        self.assertEqual(alt["name"], "mft.pl")

    def test_chain_exhaustion_returns_none(self):
        # Failing the last tool in the chain leaves no alternative.
        alt = self.advisor.suggest_fallback(MFT_PL["path"], MFT_PL, self.available)
        self.assertIsNone(alt)

    def test_all_alternatives_known_bad_returns_none(self):
        self.advisor.record_result(ANALYZEMFT["path"], success=False, error="x")
        self.advisor.record_result(MFT_PL["path"], success=False, error="x")
        alt = self.advisor.suggest_fallback(MFTECMD["path"], MFTECMD, self.available)
        self.assertIsNone(alt)

    def test_tool_not_in_any_chain_returns_none(self):
        alt = self.advisor.suggest_fallback(FLS["path"], FLS, self.available)
        self.assertIsNone(alt)

    def test_alternative_absent_from_available_skipped(self):
        # Only MFTECmd is available — no working alternative present.
        alt = self.advisor.suggest_fallback(MFTECMD["path"], MFTECMD, [MFTECMD, FLS])
        self.assertIsNone(alt)


class MatrixTest(unittest.TestCase):
    def test_matrix_accumulates_counts(self):
        advisor = ToolAdvisor(host_os="Linux")
        advisor.record_result(MFTECMD["path"], success=False, error="exit 1")
        advisor.record_result(ANALYZEMFT["path"], success=True)
        advisor.record_result(ANALYZEMFT["path"], success=True)

        matrix = advisor.matrix()
        self.assertEqual(matrix[MFTECMD["path"]]["failures"], 1)
        self.assertEqual(matrix[MFTECMD["path"]]["last_error"], "exit 1")
        self.assertEqual(matrix[ANALYZEMFT["path"]]["successes"], 2)

    def test_matrix_is_a_copy(self):
        advisor = ToolAdvisor(host_os="Linux")
        advisor.record_result(MFTECMD["path"], success=True)
        snapshot = advisor.matrix()
        snapshot[MFTECMD["path"]]["successes"] = 999
        self.assertEqual(advisor.matrix()[MFTECMD["path"]]["successes"], 1)


class NormalizeArgsTest(unittest.TestCase):
    """Argument-level remediation for failures a tool swap cannot fix."""

    def setUp(self):
        self.advisor = ToolAdvisor(host_os="Linux")
        self.tsk_loaddb = {"name": "tsk_loaddb", "path": "/usr/bin/tsk_loaddb"}
        self.bulk = {"name": "bulk_extractor", "path": "/usr/bin/bulk_extractor"}

    def test_tsk_loaddb_drops_invalid_f_flag(self):
        # The smoke-test failure: tsk_loaddb has no -f flag.
        out = self.advisor.normalize_args(
            self.tsk_loaddb, self.tsk_loaddb["path"], ["-f", "ntfs", "/cases/img.E01"]
        )
        self.assertEqual(out, ["/cases/img.E01"])

    def test_tsk_loaddb_without_f_flag_unchanged(self):
        args = ["-d", "/tmp/out.db", "/cases/img.E01"]
        out = self.advisor.normalize_args(
            self.tsk_loaddb, self.tsk_loaddb["path"], args
        )
        self.assertEqual(out, args)

    def test_bulk_extractor_injects_output_dir_when_missing(self):
        out = self.advisor.normalize_args(
            self.bulk, self.bulk["path"], ["/cases/img.E01"], scratch_dir="/tmp"
        )
        self.assertIn("-o", out)
        outdir = out[out.index("-o") + 1]
        # Parent must exist and be writable; the tool creates the dir itself.
        self.assertTrue(os.path.isdir(os.path.dirname(outdir)))
        self.assertFalse(os.path.exists(outdir))
        self.assertIn("/cases/img.E01", out)

    def test_bulk_extractor_creates_requested_parent(self):
        target = "/tmp/be_test_parent_xyz/out"
        self.addCleanup(shutil.rmtree, "/tmp/be_test_parent_xyz", ignore_errors=True)
        out = self.advisor.normalize_args(
            self.bulk, self.bulk["path"], ["-o", target, "/cases/img.E01"]
        )
        self.assertEqual(out, ["-o", target, "/cases/img.E01"])
        self.assertTrue(os.path.isdir("/tmp/be_test_parent_xyz"))

    def test_unknown_tool_passes_through(self):
        fls = {"name": "fls", "path": "/usr/bin/fls"}
        args = ["-o", "0", "/cases/img.E01"]
        self.assertEqual(self.advisor.normalize_args(fls, fls["path"], args), args)


class RegistryChainTest(unittest.TestCase):
    """The registry chain must have a real Linux fallback behind rip.pl."""

    def test_rip_pl_has_a_successor_in_chain(self):
        chain = ToolAdvisor.FALLBACK_CHAINS["registry"]
        self.assertIn("rip.pl", chain)
        # A failure of rip.pl must have somewhere to go (not the last element).
        self.assertLess(chain.index("rip.pl"), len(chain) - 1)

    def test_chain_does_not_reference_uninstalled_regipy(self):
        # regipy is not in tool_inventory.json; naming it dead-ends the chain.
        self.assertNotIn("regipy", ToolAdvisor.FALLBACK_CHAINS["registry"])


if __name__ == "__main__":
    unittest.main()
