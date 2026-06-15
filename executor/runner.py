"""Local and SSH executors with allowlist validation.

Every command passes through the validation pipeline before execution:
  1. Tool allowlist check (is this binary in the registry?)
  2. Path validation (are evidence paths under allowed roots?)
  3. Build argv array (no shell interpolation)
  4. Execute with timeout and output limits
  5. Log result to audit trail
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Tools that legitimately run for many minutes (building a Plaso super-timeline,
# carving unallocated space) and would otherwise be killed by the default
# per-command timeout. Matched by basename so /usr/bin and /usr/local/bin both
# resolve. These get long_running_timeout instead of default_timeout.
LONG_RUNNING_TOOLS = frozenset(
    {
        "log2timeline.py",
        "psort.py",
        "psteal.py",
        "bulk_extractor",
        "foremost",
        "scalpel",
        "photorec",
    }
)


def _is_safe_scratch(path: Optional[str]) -> bool:
    """Whether ``path`` is safe to recursively delete as a scratch directory.

    Guards cleanup against wiping a critical directory if scratch_dir is ever
    misconfigured: the path must be set, must contain ``scratch`` in its name,
    and must not be a shallow system root.
    """
    if not path:
        return False
    denylist = {"/", "/tmp", "/var/tmp", "/root", "/home", "/data"}
    normalized = path.rstrip("/") or "/"
    if normalized in denylist:
        return False
    return "scratch" in path.lower()


@dataclass(frozen=True)
class ExecutionResult:
    """Result of a validated tool execution."""

    execution_id: str
    tool: str
    argv: list[str]
    cwd: str
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    timestamp: str
    rejected: bool = False
    rejection_reason: Optional[str] = None
    # Filesystem paths where the raw stdout/stderr were persisted, if the
    # executor was configured with an output directory; None otherwise.
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    # Full decoded output before the audit/report truncation cap is applied.
    # These are only used for persistence; stdout/stderr remain capped so audit
    # events and report JSON stay bounded.
    raw_stdout: Optional[str] = None
    raw_stderr: Optional[str] = None


@dataclass(frozen=True)
class RejectedExecution:
    """Returned when the validation pipeline rejects a command."""

    execution_id: str
    tool: str
    argv: list[str]
    rejection_reason: str
    timestamp: str

    def to_execution_result(self) -> ExecutionResult:
        return ExecutionResult(
            execution_id=self.execution_id,
            tool=self.tool,
            argv=self.argv,
            cwd="",
            exit_code=-1,
            duration_ms=0,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timestamp=self.timestamp,
            rejected=True,
            rejection_reason=self.rejection_reason,
        )


class Executor(ABC):
    """Base executor with shared validation pipeline."""

    def __init__(
        self,
        allowed_tools: dict[str, str],
        evidence_roots: list[str],
        default_timeout: int = 120,
        max_output_bytes: int = 2_000_000,
        output_dir: Optional[str] = None,
        scratch_dir: Optional[str] = None,
        long_running_timeout: int = 1800,
    ) -> None:
        # allowed_tools: binary_path -> tool_name
        self._allowed_tools = allowed_tools
        self._evidence_roots = [Path(r).resolve() for r in evidence_roots]
        self._default_timeout = default_timeout
        # Budget for known long-running tools (see LONG_RUNNING_TOOLS): a Plaso
        # super-timeline or a full carve can take many minutes, so they get this
        # instead of default_timeout unless the caller passes an explicit one.
        self._long_running_timeout = long_running_timeout
        self._max_output_bytes = max_output_bytes
        # When set, each execution's raw stdout/stderr is written here as
        # <execution_id>.out / .err, so a finding can be traced back to the exact
        # output that produced it. Disabled (paths left as None) when unset.
        self._output_dir = Path(output_dir) if output_dir else None
        if self._output_dir is not None:
            self._output_dir.mkdir(parents=True, exist_ok=True)
        # Forensic tools must write their output somewhere (super-timelines,
        # carved files, extracted hives, redirected stdout). That destination is
        # this single scratch directory, which is added to the allowed roots so
        # writes to it pass path validation — while every other out-of-evidence
        # path (e.g. /tmp) stays rejected. It lives on the EXECUTION host (the
        # SIFT workstation locally, or the VM under SSH), so its path is treated
        # lexically here and created by ensure_scratch() on that host. None
        # disables it (writes are then confined to the evidence roots alone).
        self.scratch_dir = str(Path(scratch_dir).resolve()) if scratch_dir else None
        if self.scratch_dir is not None:
            self._evidence_roots.append(Path(self.scratch_dir))

    def add_evidence_root(self, path: str) -> None:
        """Register an additional allowed evidence root at runtime.

        Evidence is sometimes mounted after the executor has been constructed —
        for example, a disk image mounted under a temporary directory for the
        duration of one investigation. This adds that mount point (and any
        extraction cache beneath it) to the set of paths the executor will accept,
        without having to rebuild it.
        """
        self._evidence_roots.append(Path(path).resolve())

    def ensure_scratch(self) -> None:
        """Create the scratch directory on the execution host, if configured.

        The base implementation creates it on the LOCAL filesystem, which is
        correct for executors that run tools on this machine (LocalExecutor).
        Executors that run tools on another host (SSHExecutor) override this to
        create the directory there. A no-op when no scratch dir is configured.
        """
        if self.scratch_dir is not None:
            # 0700: forensic tool output (extracted hives, carved files,
            # timelines) can be sensitive; keep the scratch dir private to this
            # user rather than world-readable under the default umask.
            Path(self.scratch_dir).mkdir(parents=True, exist_ok=True, mode=0o700)

    def cleanup_scratch(self) -> None:
        """Remove this run's scratch directory from the execution host.

        Tool output (Plaso storage files, carved/extracted data) can be many GB;
        left behind it accumulates across runs and fills the host disk, after
        which every mkdir fails and runs yield zero findings. The base
        implementation removes a LOCAL scratch dir; SSHExecutor overrides it to
        remove the remote one. A no-op when no scratch dir is configured or the
        path does not look like a scratch dir (a guard against wiping /tmp etc.).
        """
        if _is_safe_scratch(self.scratch_dir):
            shutil.rmtree(self.scratch_dir, ignore_errors=True)

    def validate_tool(self, tool_path: str) -> Optional[str]:
        """Returns rejection reason if tool is not allowed, else None."""
        if tool_path not in self._allowed_tools:
            return f"Tool not in allowlist: {tool_path}"
        return None

    def _extract_path_from_arg(self, arg: str) -> Optional[str]:
        """Extract a path component from an argument, handling --opt=/path."""
        if arg == "/":
            return None
        if arg.startswith("/"):
            return arg
        if "=" in arg and arg.startswith("-"):
            _, _, val = arg.partition("=")
            if val.startswith("/"):
                return val
        if ".." in arg:
            # Only treat a "..": containing argument as a path when it actually
            # looks like one — a real traversal carries a path separator
            # (../../etc/passwd), or is the bare parent-directory token "..".
            # Otherwise legitimate non-path values that merely contain ".."
            # (numeric or date ranges such as 1..10 or 2018-01-01..2018-12-31)
            # would be resolved as paths and wrongly rejected.
            if arg == ".." or "/" in arg:
                return arg
        return None

    def validate_paths(self, args: list[str]) -> Optional[str]:
        """Check that any path-like arguments resolve under evidence roots."""
        for arg in args:
            path_str = self._extract_path_from_arg(arg)
            if path_str is None:
                continue
            try:
                resolved = Path(path_str).resolve()
            except (OSError, ValueError):
                return f"Path could not be resolved (fail closed): {path_str}"
            if not any(
                self._is_under_root(resolved, root) for root in self._evidence_roots
            ):
                if path_str in self._allowed_tools:
                    continue
                return f"Path not under allowed evidence roots: {path_str}"
        return None

    def _is_under_root(self, path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _effective_timeout(self, tool_path: str, timeout: Optional[int]) -> int:
        """Resolve the timeout for a command.

        An explicit caller-supplied timeout always wins. Otherwise a known
        long-running tool (LONG_RUNNING_TOOLS) gets the larger long-running
        budget, and everything else gets the default per-command timeout.
        """
        if timeout is not None:
            return timeout
        if Path(tool_path).name in LONG_RUNNING_TOOLS:
            return self._long_running_timeout
        return self._default_timeout

    def run(
        self,
        tool_path: str,
        args: list[str],
        cwd: str = "/tmp",
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """Validate and execute a command. Returns result or rejection."""
        exec_id = str(uuid.uuid4())[:8]
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        rejection = self.validate_tool(tool_path)
        if rejection:
            return RejectedExecution(
                execution_id=exec_id,
                tool=tool_path,
                argv=[tool_path, *args],
                rejection_reason=rejection,
                timestamp=ts,
            ).to_execution_result()

        rejection = self.validate_paths(args)
        if rejection:
            return RejectedExecution(
                execution_id=exec_id,
                tool=tool_path,
                argv=[tool_path, *args],
                rejection_reason=rejection,
                timestamp=ts,
            ).to_execution_result()

        argv = [tool_path, *args]
        effective_timeout = self._effective_timeout(tool_path, timeout)

        result = self._execute(
            exec_id=exec_id,
            argv=argv,
            cwd=cwd,
            timeout=effective_timeout,
            timestamp=ts,
        )
        return self._persist_outputs(result)

    def _persist_outputs(self, result: ExecutionResult) -> ExecutionResult:
        """Write the execution's raw stdout/stderr to the output directory and
        record their paths on the result. No-op when no output directory is
        configured."""
        if self._output_dir is None:
            return result
        out_path = self._output_dir / f"{result.execution_id}.out"
        err_path = self._output_dir / f"{result.execution_id}.err"
        # Pin UTF-8 so non-ASCII tool output is never lost to a non-UTF-8
        # process locale (e.g. LANG=C), which would otherwise raise
        # UnicodeEncodeError and drop the audit output.
        out_path.write_text(
            result.raw_stdout if result.raw_stdout is not None else result.stdout,
            encoding="utf-8",
        )
        err_path.write_text(
            result.raw_stderr if result.raw_stderr is not None else result.stderr,
            encoding="utf-8",
        )
        return replace(result, stdout_path=str(out_path), stderr_path=str(err_path))

    @abstractmethod
    def _execute(
        self,
        exec_id: str,
        argv: list[str],
        cwd: str,
        timeout: int,
        timestamp: str,
    ) -> ExecutionResult: ...

    def _truncate(self, output: str) -> tuple[str, bool]:
        encoded = output.encode("utf-8", errors="replace")
        if len(encoded) > self._max_output_bytes:
            truncated = encoded[: self._max_output_bytes].decode(
                "utf-8", errors="ignore"
            )
            return truncated, True
        return output, False


class LocalExecutor(Executor):
    """Runs tools directly via subprocess. Used on the SIFT workstation.

    Uses raw subprocess.run with argv lists (never shell=True). The allowlist +
    path-sandbox validation pipeline above is the architectural enforcement
    layer — the LLM proposes commands but never reaches subprocess directly.
    """

    def _execute(
        self,
        exec_id: str,
        argv: list[str],
        cwd: str,
        timeout: int,
        timestamp: str,
    ) -> ExecutionResult:
        # Ensure the working directory exists on this host. Tools run from the
        # scratch dir as cwd; if it was never provisioned (e.g. a startup
        # ensure_scratch that silently failed), subprocess would raise instead of
        # running. Creating it here per-exec is idempotent and self-healing.
        try:
            Path(cwd).mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            pass
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                cwd=cwd,
                capture_output=True,
                timeout=timeout,
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            raw_stdout = proc.stdout.decode("utf-8", errors="replace")
            raw_stderr = proc.stderr.decode("utf-8", errors="replace")
            stdout, stdout_trunc = self._truncate(raw_stdout)
            stderr, stderr_trunc = self._truncate(raw_stderr)
            return ExecutionResult(
                execution_id=exec_id,
                tool=argv[0],
                argv=argv,
                cwd=cwd,
                exit_code=proc.returncode,
                duration_ms=duration_ms,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_trunc,
                stderr_truncated=stderr_trunc,
                timestamp=timestamp,
                raw_stdout=raw_stdout,
                raw_stderr=raw_stderr,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - start) * 1000)
            return ExecutionResult(
                execution_id=exec_id,
                tool=argv[0],
                argv=argv,
                cwd=cwd,
                exit_code=-1,
                duration_ms=duration_ms,
                stdout="",
                stderr=f"Timeout after {timeout}s",
                stdout_truncated=False,
                stderr_truncated=False,
                timestamp=timestamp,
            )
        except OSError as exc:
            return ExecutionResult(
                execution_id=exec_id,
                tool=argv[0],
                argv=argv,
                cwd=cwd,
                exit_code=-1,
                duration_ms=0,
                stdout="",
                stderr=f"Cannot execute {argv[0]}: {exc}",
                stdout_truncated=False,
                stderr_truncated=False,
                timestamp=timestamp,
            )


class SSHExecutor(Executor):
    """Runs tools via SSH on a remote SIFT VM. Used during development.

    SSH requires a command string, so args are wrapped with POSIX single-quoting
    via _shell_quote. All args are pre-validated by the allowlist pipeline first.
    """

    def __init__(
        self,
        allowed_tools: dict[str, str],
        evidence_roots: list[str],
        host: str,
        port: int,
        user: str,
        default_timeout: int = 120,
        max_output_bytes: int = 2_000_000,
        output_dir: Optional[str] = None,
        scratch_dir: Optional[str] = None,
    ) -> None:
        super().__init__(
            allowed_tools,
            evidence_roots,
            default_timeout,
            max_output_bytes,
            output_dir,
            scratch_dir,
        )
        self._host = host
        self._port = port
        self._user = user

    def _ssh_argv(self, remote_command: str) -> list[str]:
        """SSH invocation that runs ``remote_command`` on the remote VM."""
        return [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-p",
            str(self._port),
            f"{self._user}@{self._host}",
            remote_command,
        ]

    def _run_scratch_ssh(self, remote_command: str, action: str, timeout: int) -> None:
        """Run a scratch provision/cleanup command on the VM over SSH.

        Logs (never raises) on a non-zero remote exit or a local subprocess
        error, so a silent remote failure (permission denied, disk full) is
        visible instead of swallowed — and so a cleanup-time error can never mask
        the investigation's own outcome.
        """
        try:
            result = subprocess.run(
                self._ssh_argv(remote_command), capture_output=True, timeout=timeout
            )
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("remote scratch %s failed: %s", action, exc)
            return
        if result.returncode != 0:
            stderr = (result.stderr or b"").decode("utf-8", errors="replace").strip()
            logger.warning(
                "remote scratch %s exited %s: %s",
                action,
                result.returncode,
                stderr[:200],
            )

    def ensure_scratch(self) -> None:
        """Create the scratch directory inside the remote VM over SSH.

        The scratch dir is a path on the VM (where tools actually run), so it
        cannot be created with a local mkdir — it is provisioned on the remote
        host before any sub-agent runs. A no-op when no scratch dir is set.
        """
        if self.scratch_dir is None:
            return
        self._run_scratch_ssh(
            f"mkdir -p -m 0700 {self._shell_quote(self.scratch_dir)}", "provision", 30
        )

    def cleanup_scratch(self) -> None:
        """Remove this run's scratch directory inside the remote VM over SSH."""
        if not _is_safe_scratch(self.scratch_dir):
            return
        self._run_scratch_ssh(
            f"rm -rf {self._shell_quote(self.scratch_dir)}", "cleanup", 60
        )

    def _execute(
        self,
        exec_id: str,
        argv: list[str],
        cwd: str,
        timeout: int,
        timestamp: str,
    ) -> ExecutionResult:
        # Build SSH command — the remote command is passed as argv, not shell string.
        # mkdir -p the cwd first: tools run from the scratch dir, and creating it
        # per-exec is idempotent and self-healing if the startup ensure_scratch
        # never took effect (otherwise every tool fails 'cd: <scratch>: No such
        # file or directory' and the run yields zero findings).
        remote_cmd = " ".join(self._shell_quote(a) for a in argv)
        qcwd = self._shell_quote(cwd)
        ssh_argv = self._ssh_argv(
            f"mkdir -p -m 0700 {qcwd} && cd {qcwd} && {remote_cmd}"
        )

        start = time.monotonic()
        try:
            proc = subprocess.run(
                ssh_argv,
                capture_output=True,
                timeout=timeout + 10,  # extra buffer for SSH overhead
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            raw_stdout = proc.stdout.decode("utf-8", errors="replace")
            raw_stderr = proc.stderr.decode("utf-8", errors="replace")
            stdout, stdout_trunc = self._truncate(raw_stdout)
            stderr, stderr_trunc = self._truncate(raw_stderr)
            return ExecutionResult(
                execution_id=exec_id,
                tool=argv[0],
                argv=argv,
                cwd=cwd,
                exit_code=proc.returncode,
                duration_ms=duration_ms,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_trunc,
                stderr_truncated=stderr_trunc,
                timestamp=timestamp,
                raw_stdout=raw_stdout,
                raw_stderr=raw_stderr,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - start) * 1000)
            return ExecutionResult(
                execution_id=exec_id,
                tool=argv[0],
                argv=argv,
                cwd=cwd,
                exit_code=-1,
                duration_ms=duration_ms,
                stdout="",
                stderr=f"SSH timeout after {timeout}s",
                stdout_truncated=False,
                stderr_truncated=False,
                timestamp=timestamp,
            )

    @staticmethod
    def _shell_quote(s: str) -> str:
        """Quote a string for safe inclusion in a remote shell command."""
        return "'" + s.replace("'", "'\"'\"'") + "'"
