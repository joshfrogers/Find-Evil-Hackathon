"""Integration tests: ToolAdvisor against a real catalog load path.

The pure unit tests in test_advisor.py exercise the advisor's logic with
synthetic tool dicts. These lock the advisor against the *actual catalog load
path* (``catalog.load_tool_inventory``) and the new enriched tool shape, so a
regression that drops the ``runtime`` field, or breaks the artifact-parser /
.NET-on-Linux guards, is caught rather than silently failing open.

Per D8 there is NO shipped inventory anymore — the catalog is built per-box by
``agentic-sift refresh``. So this validates against the committed test fixture
(``tests/fixtures/catalog/tool_catalog.json``), which uses the enriched flat
shape (``target_os``/``input_types``/``runtime``), the same shape ``refresh``
writes and the runtime loads.
"""

import sys
import unittest
from pathlib import Path

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tool_registry.catalog import load_tool_inventory
from tools.advisor import ToolAdvisor

CATALOG_PATH = PROJECT_ROOT / "tests" / "fixtures" / "catalog" / "tool_catalog.json"


class InventoryAdvisorIntegrationTest(unittest.TestCase):
    """Cross-references advisor behavior against a real catalog load."""

    @classmethod
    def setUpClass(cls):
        # Use the same loader the investigation CLI uses, so we validate the
        # dicts the advisor actually receives at runtime.
        cls.tools = load_tool_inventory(CATALOG_PATH)
        cls.linux_advisor = ToolAdvisor(host_os="linux")

    def _find(self, name: str) -> dict:
        match = next((t for t in self.tools if t.get("name") == name), None)
        self.assertIsNotNone(match, f"{name} not found in catalog fixture")
        return match

    def test_catalog_loads_nontrivially(self):
        # Guards against a corrupt/empty catalog regressing the whole suite.
        self.assertGreater(len(self.tools), 0)

    def test_dotnet_tool_carries_runtime_and_is_rejected_on_linux(self):
        # The .NET Zimmerman parsers are the dominant failure class the advisor
        # exists to handle. The runtime must survive the load path AND blocking_reason must
        # reject the tool on a Linux host.
        mftecmd = self._find("MFTECmd")
        self.assertEqual(str(mftecmd.get("runtime", "")).lower(), ".net")
        reason = self.linux_advisor.blocking_reason(
            mftecmd, mftecmd.get("path", ""), []
        )
        self.assertIsNotNone(
            reason, "MFTECmd (.NET) was NOT rejected on Linux by blocking_reason"
        )

    def test_native_tool_allowed_on_linux(self):
        # A native tool with non-raw-image args must NOT be pre-rejected.
        fls = self._find("fls")
        reason = self.linux_advisor.blocking_reason(fls, fls.get("path", ""), [])
        self.assertIsNone(reason, f"native fls wrongly rejected: {reason}")

    def test_artifact_parser_rejects_raw_image(self):
        # An artifact parser (RegRipper -> 'registry' capability) handed a raw
        # disk image must be rejected — it needs an extracted artifact.
        rip = self._find("RegRipper")
        reason = self.linux_advisor.blocking_reason(
            rip, rip.get("path", ""), ["/cases/image.E01"]
        )
        self.assertIsNotNone(
            reason, "RegRipper handed a raw .E01 was NOT rejected"
        )


if __name__ == "__main__":
    unittest.main()
