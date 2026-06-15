"""Tests for the executor validation pipeline."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# sys.path setup required for standalone execution on SIFT workstations
# (standalone project — no build system on the analysis host).
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from executor.runner import ExecutionResult, LocalExecutor

# `echo` lives at different paths across platforms (/bin/echo on macOS,
# /usr/bin/echo on many Linux distros); resolve it so these tests execute a real
# binary on any host instead of hardcoding a path that may not exist.
ECHO = shutil.which("echo") or "/bin/echo"


def _make_executor(
    tools: dict[str, str] | None = None,
    roots: list[str] | None = None,
) -> LocalExecutor:
    if tools is None:
        tools = {"/usr/bin/fls": "fls", "/usr/bin/mmls": "mmls"}
    if roots is None:
        roots = ["/cases", "/evidence"]
    return LocalExecutor(allowed_tools=tools, evidence_roots=roots)


class TestAllowlist(unittest.TestCase):
    def test_allowed_tool_passes(self):
        ex = _make_executor()
        result = ex.run("/usr/bin/fls", ["-r", "/cases/image.E01"])
        # Will fail because binary doesn't exist locally, but should NOT be rejected
        self.assertFalse(result.rejected)

    def test_disallowed_tool_rejected(self):
        ex = _make_executor()
        result = ex.run("/usr/bin/rm", ["-rf", "/cases/image.E01"])
        self.assertTrue(result.rejected)
        self.assertIn("not in allowlist", result.rejection_reason)

    def test_shell_command_rejected(self):
        ex = _make_executor()
        result = ex.run("/bin/bash", ["-c", "cat /etc/passwd"])
        self.assertTrue(result.rejected)


class TestPathValidation(unittest.TestCase):
    def test_evidence_root_path_passes(self):
        ex = _make_executor()
        reason = ex.validate_paths(["/cases/image.E01"])
        self.assertIsNone(reason)

    def test_outside_root_rejected(self):
        ex = _make_executor()
        reason = ex.validate_paths(["/etc/passwd"])
        self.assertIsNotNone(reason)
        self.assertIn("not under allowed evidence roots", reason)

    def test_flag_args_ignored(self):
        ex = _make_executor()
        reason = ex.validate_paths(["-r", "-m", "/"])
        # "/" alone would fail but flags starting with - are skipped,
        # and "/" doesn't start with / followed by more chars, so it's fine
        # Actually "/" starts with "/" — let's verify behavior
        # Non-path short args like "/" (mount point notation) are common in fls
        self.assertIsNone(reason)

    def test_tool_binary_path_allowed(self):
        ex = _make_executor()
        reason = ex.validate_paths(["/usr/bin/fls"])
        self.assertIsNone(reason)

    def test_non_path_dotdot_args_not_rejected(self):
        # Arguments that merely contain ".." but are not paths (numeric or date
        # ranges, e.g. mactime's -y 2018-01-01..2018-12-31) must not be treated
        # as paths and rejected.
        ex = _make_executor()
        self.assertIsNone(ex.validate_paths(["-y", "2018-01-01..2018-12-31"]))
        self.assertIsNone(ex.validate_paths(["--range=1..10"]))
        self.assertIsNone(ex._extract_path_from_arg("1..10"))
        self.assertIsNone(ex._extract_path_from_arg("2018-01-01..2018-12-31"))

    def test_relative_traversal_still_rejected(self):
        # A real relative traversal has a path separator and must still be
        # caught and rejected.
        ex = _make_executor()
        self.assertEqual(
            ex._extract_path_from_arg("../../etc/passwd"), "../../etc/passwd"
        )
        self.assertEqual(ex._extract_path_from_arg(".."), "..")
        reason = ex.validate_paths(["../../etc/passwd"])
        self.assertIsNotNone(reason)

    def test_relative_path_resolved_against_cwd(self):
        # A relative path is interpreted by the tool relative to its working
        # directory, so it is validated against the execution cwd (not the
        # orchestrator's process CWD).
        ex = _make_executor()  # evidence roots = ["/cases"]
        # A plain relative path carrying a separator is now extracted and checked
        # (previously it slipped through unvalidated).
        self.assertEqual(
            ex._extract_path_from_arg("out/timeline.body"), "out/timeline.body"
        )
        # A relative path that stays inside cwd is allowed even when cwd is not a
        # configured evidence root (e.g. a scratch dir).
        self.assertIsNone(
            ex.validate_paths(["out/timeline.body"], cwd="/tmp/scratch-xyz")
        )
        # A relative path that escapes cwd and lands outside every root is rejected.
        self.assertIsNotNone(ex.validate_paths(["../../etc/passwd"], cwd="/cases"))

    def test_option_relative_path_resolved_against_cwd(self):
        # --key=value arguments must validate the VALUE, not the whole option
        # string. Otherwise --out=../leak appears to stay inside cwd as a fake
        # filename while the tool interprets ../leak and escapes.
        ex = _make_executor()

        self.assertEqual(
            ex._extract_path_from_arg("--out=out/timeline.body"), "out/timeline.body"
        )
        self.assertIsNone(
            ex.validate_paths(["--out=out/timeline.body"], cwd="/tmp/scratch-xyz")
        )

        self.assertEqual(ex._extract_path_from_arg("--out=../leak"), "../leak")
        self.assertIsNotNone(
            ex.validate_paths(["--out=../leak"], cwd="/tmp/scratch-xyz")
        )
        self.assertIsNotNone(
            ex.validate_paths(["--out=../../etc/passwd"], cwd="/tmp/scratch-xyz")
        )

    def test_option_absolute_paths_still_validated(self):
        ex = _make_executor()

        self.assertEqual(
            ex._extract_path_from_arg("--image=/cases/image.E01"), "/cases/image.E01"
        )
        self.assertIsNone(ex.validate_paths(["--image=/cases/image.E01"]))
        self.assertIsNotNone(ex.validate_paths(["--out=/etc/passwd"]))


class TestOutputPersistence(unittest.TestCase):
    """Raw stdout/stderr are persisted per execution so a finding can be traced
    back to the exact output that produced it, and the verifier can re-read what
    it is challenging."""

    def test_stdout_persisted_to_file_keyed_by_execution_id(self):
        with tempfile.TemporaryDirectory() as out:
            ex = LocalExecutor(
                allowed_tools={ECHO: "echo"},
                evidence_roots=["/cases"],
                output_dir=out,
            )
            result = ex.run(ECHO, ["hello-trace"])
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout_path, "expected a stdout_path")
            self.assertIn(result.execution_id, result.stdout_path)
            self.assertTrue(os.path.exists(result.stdout_path))
            with open(result.stdout_path) as f:
                self.assertEqual(f.read().strip(), "hello-trace")

    def test_persisted_stdout_is_full_even_when_result_is_truncated(self):
        with tempfile.TemporaryDirectory() as out:
            ex = LocalExecutor(
                allowed_tools={sys.executable: "python"},
                evidence_roots=["/cases"],
                output_dir=out,
                max_output_bytes=5,
            )
            result = ex.run(
                sys.executable,
                ["-c", "import sys; sys.stdout.write('abcdefghi')"],
            )
            self.assertEqual(result.stdout, "abcde")
            self.assertTrue(result.stdout_truncated)
            with open(result.stdout_path) as f:
                self.assertEqual(f.read(), "abcdefghi")

    def test_stderr_persisted_to_file(self):
        with tempfile.TemporaryDirectory() as out:
            ex = LocalExecutor(
                allowed_tools={"/bin/sh": "sh"},
                evidence_roots=["/cases"],
                output_dir=out,
            )
            result = ex.run("/bin/sh", ["-c", "echo oops 1>&2"])
            self.assertTrue(result.stderr_path)
            self.assertTrue(os.path.exists(result.stderr_path))
            with open(result.stderr_path) as f:
                self.assertEqual(f.read().strip(), "oops")

    def test_no_output_dir_means_no_paths(self):
        # Backward compatible: without an output_dir, nothing is persisted.
        ex = LocalExecutor(
            allowed_tools={ECHO: "echo"},
            evidence_roots=["/cases"],
        )
        result = ex.run(ECHO, ["hi"])
        self.assertIsNone(result.stdout_path)
        self.assertIsNone(result.stderr_path)

    def test_outputs_persisted_as_utf8(self):
        # Tool output can contain non-ASCII bytes; persisting it must pin UTF-8
        # rather than the process locale, or a non-UTF-8 locale (e.g. LANG=C)
        # raises UnicodeEncodeError and the audit output is lost.
        with tempfile.TemporaryDirectory() as out:
            ex = LocalExecutor(
                allowed_tools={},
                evidence_roots=["/cases"],
                output_dir=out,
            )
            result = ExecutionResult(
                execution_id="e-utf8",
                tool=ECHO,
                argv=[ECHO],
                cwd="/tmp",
                exit_code=0,
                duration_ms=1,
                stdout="café ✓ Москва",
                stderr="naïve",
                stdout_truncated=False,
                stderr_truncated=False,
                timestamp="2026-06-09T00:00:00Z",
            )
            with patch("pathlib.Path.write_text") as wt:
                ex._persist_outputs(result)
            self.assertEqual(wt.call_count, 2)
            for call in wt.call_args_list:
                self.assertEqual(call.kwargs.get("encoding"), "utf-8")


class TestEvidenceRootRegistration(unittest.TestCase):
    """W5: EvidenceSession registers runtime mount points so the executor's
    path validation accepts /mnt/inv-* paths it couldn't see at construction."""

    def test_add_evidence_root_allows_previously_rejected_path(self):
        ex = _make_executor(roots=["/cases"])
        # A runtime mount point is rejected before registration.
        self.assertIsNotNone(ex.validate_paths(["/mnt/inv-1/Windows/file"]))
        ex.add_evidence_root("/mnt/inv-1")
        # ...and accepted after.
        self.assertIsNone(ex.validate_paths(["/mnt/inv-1/Windows/file"]))


class TestSSHExecutorContract(unittest.TestCase):
    def test_ssh_executor_requires_explicit_connection(self):
        """SSHExecutor must not assume any host/port/user — they are caller-supplied."""
        import inspect

        from executor.runner import SSHExecutor

        sig = inspect.signature(SSHExecutor.__init__)
        for name in ("host", "port", "user"):
            self.assertIs(
                sig.parameters[name].default,
                inspect.Parameter.empty,
                f"{name} must have no default (no environment-specific value baked in)",
            )


class TestExecution(unittest.TestCase):
    def test_binary_not_found(self):
        ex = _make_executor()
        result = ex.run("/usr/bin/fls", ["-r", "/cases/image.E01"])
        self.assertEqual(result.exit_code, -1)
        self.assertIn("Cannot execute", result.stderr)

    def test_exec_format_error_is_caught(self):
        """OSError [Errno 8] (exec format error) from scripts without a valid
        shebang must be caught and returned as a failed result, not raised."""
        with tempfile.NamedTemporaryFile(suffix=".pl", delete=False, mode="w") as f:
            f.write("# no shebang — kernel cannot exec this\nprint 'hi';\n")
            script = f.name
        os.chmod(script, 0o755)
        try:
            ex = LocalExecutor(
                allowed_tools={script: "bad-script"},
                evidence_roots=["/cases"],
            )
            result = ex.run(script, [])
            self.assertEqual(result.exit_code, -1)
            self.assertIn("Cannot execute", result.stderr)
            self.assertFalse(result.rejected)
        finally:
            os.unlink(script)

    def test_real_command(self):
        ex = _make_executor(
            tools={ECHO: "echo"},
            roots=["/cases"],
        )
        result = ex.run(ECHO, ["hello"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "hello")
        self.assertFalse(result.rejected)
        self.assertTrue(len(result.execution_id) > 0)


class TestScratchDir(unittest.TestCase):
    """Forensic tools must write output somewhere; the executor confines those
    writes to a dedicated scratch directory that is allowlisted alongside the
    evidence roots. Without it, a tool writing to /tmp is rejected (the bug that
    made every timeline/hive-export tool fail)."""

    def test_no_scratch_dir_rejects_writes_outside_evidence(self):
        ex = LocalExecutor(allowed_tools={}, evidence_roots=["/cases"])
        self.assertIsNone(ex.scratch_dir)
        # With no scratch dir configured, a /tmp output path is still rejected.
        self.assertIsNotNone(ex.validate_paths(["/tmp/timeline.plaso"]))

    def test_scratch_dir_is_allowlisted_but_other_paths_still_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            ex = LocalExecutor(
                allowed_tools={},
                evidence_roots=["/cases"],
                scratch_dir=scratch,
            )
            self.assertEqual(ex.scratch_dir, str(Path(scratch).resolve()))
            # A write under the scratch dir passes validation...
            self.assertIsNone(ex.validate_paths([f"{scratch}/timeline.plaso"]))
            # ...but an arbitrary out-of-tree path (e.g. /tmp) is still rejected.
            self.assertIsNotNone(ex.validate_paths(["/tmp/timeline.plaso"]))

    def test_ensure_scratch_creates_local_directory(self):
        with tempfile.TemporaryDirectory() as base:
            scratch = str(Path(base) / "scratch")
            ex = LocalExecutor(
                allowed_tools={}, evidence_roots=["/cases"], scratch_dir=scratch
            )
            self.assertFalse(Path(scratch).exists())
            ex.ensure_scratch()
            self.assertTrue(Path(scratch).is_dir())
            # Private to this user (no group/other bits) — scratch holds
            # potentially sensitive forensic output.
            self.assertEqual(os.stat(scratch).st_mode & 0o077, 0)

    def test_ensure_scratch_is_noop_without_scratch_dir(self):
        ex = LocalExecutor(allowed_tools={}, evidence_roots=["/cases"])
        # Must not raise when no scratch dir is configured.
        ex.ensure_scratch()


class TestCwdAutoCreate(unittest.TestCase):
    """A tool runs from the scratch dir as cwd; that dir must be created at exec
    time so a missing/never-provisioned scratch dir doesn't fail every tool with
    'cd: <scratch>: No such file or directory' (the 0-findings regression)."""

    def test_local_executor_creates_missing_cwd(self):
        with tempfile.TemporaryDirectory() as base:
            cwd = os.path.join(base, "scratch", "run1")  # does not exist yet
            ex = LocalExecutor(
                allowed_tools={ECHO: "echo"}, evidence_roots=["/cases"]
            )
            result = ex.run(ECHO, ["hi"], cwd=cwd)
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(os.path.isdir(cwd))

    def test_ssh_execute_mkdirs_cwd_remotely(self):
        from unittest.mock import MagicMock

        from executor.runner import SSHExecutor

        ex = SSHExecutor(
            allowed_tools={ECHO: "echo"},
            evidence_roots=["/cases"],
            host="h",
            port=22,
            user="u",
        )
        with patch("executor.runner.subprocess.run") as m:
            m.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            ex.run(ECHO, ["hi"], cwd="/scratch/run1")
        remote_cmd = m.call_args.args[0][-1]  # last arg of ssh argv
        self.assertIn("mkdir -p", remote_cmd)
        self.assertIn("/scratch/run1", remote_cmd)


class TestScratchCleanup(unittest.TestCase):
    """Scratch holds large tool output (Plaso timelines can be many GB). It must
    be removed at end of run so the execution host doesn't fill up across runs
    (a full disk made every mkdir fail → zero findings)."""

    def test_local_cleanup_removes_scratch_dir(self):
        with tempfile.TemporaryDirectory() as base:
            scratch = os.path.join(base, "scratch")
            ex = LocalExecutor(
                allowed_tools={}, evidence_roots=["/cases"], scratch_dir=scratch
            )
            ex.ensure_scratch()
            self.assertTrue(os.path.isdir(scratch))
            ex.cleanup_scratch()
            self.assertFalse(os.path.exists(scratch))

    def test_cleanup_noop_without_scratch_dir(self):
        ex = LocalExecutor(allowed_tools={}, evidence_roots=["/cases"])
        ex.cleanup_scratch()  # must not raise

    def test_cleanup_refuses_to_remove_unsafe_path(self):
        # A scratch dir that doesn't look like a scratch path must never be
        # rmtree'd (guards against wiping /tmp or a home dir by misconfig).
        ex = LocalExecutor(
            allowed_tools={}, evidence_roots=["/cases"], scratch_dir="/tmp"
        )
        ex.cleanup_scratch()
        self.assertTrue(os.path.isdir("/tmp"))

    def test_ssh_cleanup_rm_rf_remote(self):
        from unittest.mock import MagicMock

        from executor.runner import SSHExecutor

        ex = SSHExecutor(
            allowed_tools={},
            evidence_roots=["/cases"],
            host="h",
            port=22,
            user="u",
            scratch_dir="/tmp/agentic-sift-scratch/run1",
        )
        with patch("executor.runner.subprocess.run") as m:
            m.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            ex.cleanup_scratch()
        cmd = m.call_args.args[0][-1]
        self.assertIn("rm -rf", cmd)
        self.assertIn("/tmp/agentic-sift-scratch/run1", cmd)

    def test_ssh_scratch_logs_on_nonzero_remote_exit(self):
        # A silently-swallowed non-zero remote exit (e.g. disk full on mkdir) is
        # exactly what masked the disk-full failure; ensure it is logged.
        from unittest.mock import MagicMock

        from executor.runner import SSHExecutor

        ex = SSHExecutor(
            allowed_tools={},
            evidence_roots=["/cases"],
            host="h",
            port=22,
            user="u",
            scratch_dir="/tmp/agentic-sift-scratch/run1",
        )
        with patch("executor.runner.subprocess.run") as m:
            m.return_value = MagicMock(
                returncode=1, stdout=b"", stderr=b"No space left on device"
            )
            with self.assertLogs("executor.runner", level="WARNING") as cm:
                ex.ensure_scratch()
        self.assertTrue(any("No space left on device" in line for line in cm.output))

    def test_ssh_cleanup_does_not_raise_on_subprocess_error(self):
        # Cleanup runs in a finally block; a subprocess error must be logged, not
        # raised, so it cannot mask the investigation outcome.
        from executor.runner import SSHExecutor

        ex = SSHExecutor(
            allowed_tools={},
            evidence_roots=["/cases"],
            host="h",
            port=22,
            user="u",
            scratch_dir="/tmp/agentic-sift-scratch/run1",
        )
        with patch(
            "executor.runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=60),
        ):
            ex.cleanup_scratch()  # must not raise


class TestLongRunningTimeout(unittest.TestCase):
    """Heavy tools (super-timelining with Plaso, carving) take far longer than
    the default per-command timeout; without a larger budget they are killed
    mid-run (log2timeline.py exited -1 'SSH timeout after 120s')."""

    def test_slow_tool_gets_long_running_timeout(self):
        ex = LocalExecutor(
            allowed_tools={},
            evidence_roots=["/cases"],
            long_running_timeout=1800,
        )
        self.assertEqual(ex._effective_timeout("/usr/bin/log2timeline.py", None), 1800)

    def test_normal_tool_keeps_default_timeout(self):
        ex = LocalExecutor(
            allowed_tools={}, evidence_roots=["/cases"], default_timeout=120
        )
        self.assertEqual(ex._effective_timeout("/usr/bin/fls", None), 120)

    def test_explicit_timeout_overrides_both(self):
        ex = LocalExecutor(allowed_tools={}, evidence_roots=["/cases"])
        self.assertEqual(ex._effective_timeout("/usr/bin/log2timeline.py", 30), 30)


if __name__ == "__main__":
    unittest.main()
