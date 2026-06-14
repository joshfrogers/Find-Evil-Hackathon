"""Privileged runner that performs the read-only mount on a separate tool host.

In a split development setup the reasoning code runs on one machine while the
forensic tools and the disk image live on another (a VM). Mounting the image on
the reasoning machine is useless there: the tools that need to read the mounted
files run on the other host and cannot see that mount. This runner sends the same
trusted mount-pipeline commands (losetup, mount, ...) over SSH to the host where
the tools and the image actually are, so the filesystem is mounted in the right
place.

It implements the same ``PrivilegedRunner`` contract as the local
``SubprocessPrivilegedRunner`` (``run`` and ``run_to_file`` returning
``RunResult``) and is a drop-in substitute selected by a development-only flag;
the shipped single-machine path uses the local runner unchanged.

The commands issued here originate only from the mounting session's own code and
are never derived from untrusted input. They are sudo-wrapped on the remote host
exactly as the local runner wraps them, then quoted into a single remote command
string because SSH executes a command line, not an argv array.
"""

from __future__ import annotations

import shlex
import subprocess
from typing import Optional, Protocol

from evidence.session import RunResult


class SshTransport(Protocol):
    """Sends one already-assembled remote command to the tool host over SSH.

    ``exec`` runs the given remote command and returns
    ``(returncode, stdout, stderr)`` with stdout decoded as text. ``exec_bytes``
    returns ``(returncode, stdout_bytes, stderr)`` with stdout left as raw bytes,
    for binary extraction (e.g. ``icat``) where decoding would corrupt content.
    The default implementation shells out to ``ssh``; tests inject a fake so no
    real connection is opened.
    """

    def exec(
        self, remote_cmd: list[str], timeout: int = 120
    ) -> tuple[int, str, str]: ...

    def exec_bytes(
        self, remote_cmd: list[str], timeout: int = 120
    ) -> tuple[int, bytes, str]: ...


class _SubprocessSshTransport:
    """Default transport: runs the remote command via the ``ssh`` binary."""

    def __init__(self, host: str, port: int, user: str) -> None:
        self._host = host
        self._port = port
        self._user = user

    def _exec_raw(self, remote_cmd: list[str], timeout: int) -> tuple[int, bytes, str]:
        """Run the remote command, returning raw stdout bytes and decoded stderr."""
        ssh_argv = [
            "ssh",
            "-o",
            # Dev-only localhost VM: pin the host key on first connect, then
            # verify it on every later connect (rejects a changed key). Avoids
            # the MITM-equivalent StrictHostKeyChecking=no + /dev/null combo.
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            "-p",
            str(self._port),
            f"{self._user}@{self._host}",
            *remote_cmd,
        ]
        try:
            proc = subprocess.run(
                ssh_argv,
                capture_output=True,
                timeout=timeout + 10,  # extra buffer for SSH overhead
            )
            return (
                proc.returncode,
                proc.stdout,
                proc.stderr.decode("utf-8", errors="replace"),
            )
        except subprocess.TimeoutExpired:
            return (124, b"", f"Timeout after {timeout}s")
        except FileNotFoundError as e:
            return (127, b"", f"ssh not found: {e}")

    def exec(self, remote_cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        returncode, stdout, stderr = self._exec_raw(remote_cmd, timeout)
        return (returncode, stdout.decode("utf-8", errors="replace"), stderr)

    def exec_bytes(
        self, remote_cmd: list[str], timeout: int = 120
    ) -> tuple[int, bytes, str]:
        return self._exec_raw(remote_cmd, timeout)


class SshPrivilegedRunner:
    """Issues trusted mount-pipeline commands on a remote tool host over SSH.

    ``host``/``port``/``user`` address the remote tool host. ``use_sudo`` prefixes
    ``sudo -n`` on the remote command for the privileged loop/mount operations
    (turn it off only for unprivileged use and tests). An injectable ``transport``
    makes the class unit-testable without a real SSH connection; when omitted, a
    subprocess-based ``ssh`` wrapper is used. Never raises on a non-zero exit — the
    caller inspects ``RunResult``.
    """

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        use_sudo: bool = True,
        transport: Optional[SshTransport] = None,
    ) -> None:
        self._host = host
        self._port = port
        self._user = user
        self._use_sudo = use_sudo
        self._transport: SshTransport = transport or _SubprocessSshTransport(
            host, port, user
        )

    def _remote_command(self, argv: list[str]) -> list[str]:
        """Sudo-wrap the argv, then quote it into one remote command string.

        SSH runs a command line rather than an argv array, so the privileged
        command is joined with POSIX quoting to preserve argument boundaries.
        """
        wrapped = (["sudo", "-n", *argv]) if self._use_sudo else list(argv)
        return [" ".join(shlex.quote(a) for a in wrapped)]

    def run(self, argv: list[str], timeout: int = 120) -> RunResult:
        remote_cmd = self._remote_command(argv)
        returncode, stdout, stderr = self._transport.exec(remote_cmd, timeout)
        return RunResult(
            argv=remote_cmd,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def run_to_file(self, argv: list[str], dest: str, timeout: int = 120) -> RunResult:
        """Run a command on the tool host, capturing its raw stdout into a local file.

        The hashing/extraction reads happen on the reasoning host, so the remote
        stdout is captured and written locally; the mount itself lives on the tool
        host. The full stdout is buffered in memory and then written as raw bytes
        ("wb"), matching the local runner's binary-safe contract — binary
        extraction (e.g. icat) must not be decoded. Unlike the local runner this
        does not stream incrementally, so a very large extraction is held in RAM;
        acceptable for the development seam.
        """
        remote_cmd = self._remote_command(argv)
        returncode, stdout, stderr = self._transport.exec_bytes(remote_cmd, timeout)
        try:
            with open(dest, "wb") as out:
                out.write(stdout)
        except OSError as e:
            return RunResult(remote_cmd, 1, "", f"Could not write {dest}: {e}")
        return RunResult(remote_cmd, returncode, "", stderr)

    # Host-side IO executed on the remote tool VM (same host as the image/mount),
    # so EvidenceSession's integrity hash, work-dir creation, and OS detection act
    # where the evidence is rather than on the local reasoning machine.
    def sha256(self, path: str) -> str:
        result = self.run(["sha256sum", path])
        if result.returncode != 0:
            raise RuntimeError(
                f"remote sha256sum failed ({result.returncode}) for {path}: "
                f"{result.stderr.strip()}"
            )
        # `sha256sum` prints "<hexdigest>  <path>"; take the first token.
        digest = result.stdout.split()[0] if result.stdout.split() else ""
        if not digest:
            raise RuntimeError(f"remote sha256sum produced no digest for {path}")
        return digest

    def makedirs(self, path: str) -> None:
        result = self.run(["mkdir", "-p", path])
        if result.returncode != 0:
            raise RuntimeError(
                f"remote mkdir -p failed ({result.returncode}) for {path}: "
                f"{result.stderr.strip()}"
            )

    def isdir(self, path: str) -> bool:
        return self.run(["test", "-d", path]).returncode == 0
