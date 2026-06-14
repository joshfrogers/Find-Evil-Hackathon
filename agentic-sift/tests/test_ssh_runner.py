"""Tests for the SSH-backed privileged runner used in the dev remote mode.

These exercise the runner against a fake SSH transport so no real SSH
connection or remote mount is ever made.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evidence.session import RunResult
from evidence.ssh_runner import SshPrivilegedRunner


def _sent_command(transport: MagicMock) -> str:
    """The remote command string handed to the transport (exec/exec_bytes)."""
    call = transport.exec.call_args or transport.exec_bytes.call_args
    sent = call.args[0]
    return " ".join(sent) if isinstance(sent, list) else sent


class SshPrivilegedRunnerTest(unittest.TestCase):
    def test_run_wraps_argv_in_ssh_and_returns_runresult(self):
        transport = MagicMock()
        # Fake transport returns (returncode, stdout, stderr) for a remote argv.
        transport.exec.return_value = (0, "/dev/loop0p1", "")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        result = runner.run(["losetup", "-r", "-P", "/cases/img.E01"])
        self.assertIsInstance(result, RunResult)
        self.assertEqual(result.returncode, 0)
        self.assertIn("/dev/loop0p1", result.stdout)
        # The privileged command was sent to the tool host, sudo-wrapped.
        sent = _sent_command(transport)
        self.assertIn("losetup", sent)

    def test_run_sudo_wraps_with_sudo_dash_n(self):
        transport = MagicMock()
        transport.exec.return_value = (0, "", "")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        runner.run(["losetup", "-r", "-P", "/cases/img.E01"])
        sent = _sent_command(transport)
        # Default use_sudo=True must prefix `sudo -n` on the remote command.
        self.assertTrue(sent.startswith("sudo -n "), sent)
        self.assertIn("sudo -n losetup", sent)

    def test_run_no_sudo_omits_sudo_prefix(self):
        transport = MagicMock()
        transport.exec.return_value = (0, "ok", "")
        runner = SshPrivilegedRunner(
            host="vm.example",
            port=2222,
            user="analyst",
            use_sudo=False,
            transport=transport,
        )
        runner.run(["blkid", "/dev/loop0"])
        sent = _sent_command(transport)
        self.assertNotIn("sudo", sent)
        self.assertTrue(sent.startswith("blkid"), sent)

    def test_run_nonzero_returncode_does_not_raise(self):
        transport = MagicMock()
        transport.exec.return_value = (32, "", "mount: failed")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        # Docstring promises it never raises on a non-zero exit.
        result = runner.run(["mount", "/dev/loop0p1", "/mnt/x"])
        self.assertEqual(result.returncode, 32)
        self.assertIn("failed", result.stderr)

    def test_run_timeout_path_returns_124(self):
        # Transport surfaces a timeout as (124, "", msg); runner must pass it
        # through as a RunResult rather than raising.
        transport = MagicMock()
        transport.exec.return_value = (124, "", "Timeout after 5s")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        result = runner.run(["losetup", "-r", "-P", "/cases/img.E01"], timeout=5)
        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.stdout, "")
        self.assertIn("Timeout", result.stderr)

    def test_run_to_file_writes_binary_safe(self):
        # icat output is raw bytes (here: an embedded NUL + non-utf8 byte). The
        # runner must write them verbatim via exec_bytes -> "wb", never decode.
        raw = b"MZ\x90\x00\xff\xfe binary blob"
        transport = MagicMock()
        transport.exec_bytes.return_value = (0, raw, "")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        with tempfile.TemporaryDirectory() as d:
            dest = str(Path(d) / "extracted.bin")
            result = runner.run_to_file(["icat", "/dev/loop0p1", "12345"], dest)
            self.assertEqual(result.returncode, 0)
            # stdout is dropped from the RunResult (matches the local contract).
            self.assertEqual(result.stdout, "")
            with open(dest, "rb") as fh:
                self.assertEqual(fh.read(), raw)
        # exec_bytes (not exec) must be used so bytes are never decoded.
        transport.exec_bytes.assert_called_once()
        transport.exec.assert_not_called()
        sent = _sent_command(transport)
        self.assertIn("sudo -n icat", sent)

    def test_run_to_file_write_error_returns_failure(self):
        transport = MagicMock()
        transport.exec_bytes.return_value = (0, b"data", "")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        # A non-existent directory makes open("wb") raise OSError; the runner
        # converts it to a returncode=1 RunResult rather than propagating.
        dest = "/nonexistent-dir-xyz/extracted.bin"
        result = runner.run_to_file(["icat", "/dev/loop0p1", "12345"], dest)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Could not write", result.stderr)


class SshPrivilegedRunnerIOTest(unittest.TestCase):
    """Host-side IO (sha256/makedirs/isdir) executes on the remote tool VM, so
    EvidenceSession's integrity hash, work-dir creation, and OS detection act on
    the host where the image and mount actually are."""

    def test_sha256_parses_sha256sum_output(self):
        transport = MagicMock()
        digest = "a" * 64
        transport.exec.return_value = (0, f"{digest}  /cases/img.E01\n", "")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        self.assertEqual(runner.sha256("/cases/img.E01"), digest)
        sent = _sent_command(transport)
        self.assertIn("sudo -n sha256sum", sent)
        self.assertIn("/cases/img.E01", sent)

    def test_sha256_raises_on_failure(self):
        transport = MagicMock()
        transport.exec.return_value = (1, "", "sha256sum: cannot open")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        with self.assertRaises(RuntimeError):
            runner.sha256("/cases/missing.E01")

    def test_makedirs_runs_mkdir_p(self):
        transport = MagicMock()
        transport.exec.return_value = (0, "", "")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        runner.makedirs("/tmp/ev/ewf")
        sent = _sent_command(transport)
        self.assertIn("sudo -n mkdir -p", sent)
        self.assertIn("/tmp/ev/ewf", sent)

    def test_makedirs_raises_on_failure(self):
        transport = MagicMock()
        transport.exec.return_value = (1, "", "mkdir: permission denied")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        with self.assertRaises(RuntimeError):
            runner.makedirs("/root/forbidden")

    def test_isdir_true_on_rc0(self):
        transport = MagicMock()
        transport.exec.return_value = (0, "", "")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        self.assertTrue(runner.isdir("/mnt/vol0"))
        sent = _sent_command(transport)
        self.assertIn("sudo -n test -d", sent)
        self.assertIn("/mnt/vol0", sent)

    def test_isdir_false_on_nonzero(self):
        transport = MagicMock()
        transport.exec.return_value = (1, "", "")
        runner = SshPrivilegedRunner(
            host="vm.example", port=2222, user="analyst", transport=transport
        )
        self.assertFalse(runner.isdir("/mnt/missing"))


if __name__ == "__main__":
    unittest.main()
