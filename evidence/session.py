"""Read-only access to a forensic disk image, with a tamper-evidence guarantee.

EvidenceSession opens a disk image (a raw `dd` image or an Expert Witness Format
`.E01`), mounts every filesystem it contains read-only, and proves the image was
not modified while it was open by hashing it before and after. It provides byte
access plus that integrity guarantee only; it does not parse artifacts or decide
what to look for.

Device model:

    losetup -r -P <source>             read-only loop device + a kernel partition
                                       scan, exposing /dev/loopN and a
                                       /dev/loopNpK device per partition
    lsblk -Pno NAME,TYPE,FSTYPE,START  list the child partitions, each one's
                                       filesystem type, and its start offset,
                                       in a single call
    mount -r <partition_device>        mount each partition's device read-only

Letting the kernel parse the partition table (instead of parsing the text output
of a tool like `mmls`) and letting libblkid identify filesystems (instead of
`fsstat`, which can hang on some filesystem types) keeps this code free of
per-image assumptions: supporting a new operating system or filesystem is a
change to the lookup tables below, not to the logic. An earlier design mounted
each partition at a byte offset within a single loop device; that was abandoned
because the kernel refuses overlapping loop devices once more than one partition
is mounted that way.

The privileged commands here (losetup, mount, ewfmount, ...) run via a trusted
runner with sudo. They are issued only by this module's own code and are never
derived from untrusted input.

Write protection has two independent layers: the read-only loop device
(`losetup -r`) is the primary guarantee, and the filesystem-level read-only mount
options are a backstop.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Optional, Protocol


class SpoliationError(Exception):
    """Raised when the evidence image hash changed between open and close."""


@dataclass
class RunResult:
    """Result of a privileged command issued by EvidenceSession."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


class PrivilegedRunner(Protocol):
    """Issues a trusted, code-originated privileged command (with sudo).

    The IO methods (sha256/makedirs/isdir) run on the SAME host as ``run`` — the
    local machine for ``SubprocessPrivilegedRunner`` (which is also where the
    image and mount live in the shipped single-machine setup), or the remote tool
    VM for ``SshPrivilegedRunner``. EvidenceSession routes its integrity hash,
    work-dir creation, and OS detection through these so they always act on the
    host where the evidence actually is, rather than on the reasoning machine.
    """

    def run(self, argv: list[str], timeout: int = 120) -> RunResult: ...

    def run_to_file(self, argv: list[str], dest: str, timeout: int = 120) -> RunResult:
        """Run a command, streaming raw stdout bytes to `dest` (binary-safe)."""
        ...

    def sha256(self, path: str) -> str:
        """SHA-256 of a file on the command host (binary-safe, streamed)."""
        ...

    def makedirs(self, path: str) -> None:
        """Create a directory and parents on the command host; idempotent."""
        ...

    def isdir(self, path: str) -> bool:
        """Whether ``path`` is a directory on the command host."""
        ...


class SubprocessPrivilegedRunner:
    """Runs trusted mount-pipeline commands via subprocess.

    These commands originate only from EvidenceSession's own code, so they run
    directly rather than through any command-validation/allowlist layer that
    untrusted commands would be subject to. `use_sudo` prefixes the privileged
    mount/loop operations with sudo: `sudo -n` (passwordless / cached creds) by
    default, or `sudo -S` reading a supplied password from stdin when
    `sudo_password` is set (for hosts where sudo needs a password — e.g. the SANS
    SIFT default user). Turn `use_sudo` off for unprivileged use and in tests.
    Never raises on a non-zero exit — the caller inspects RunResult.
    """

    def __init__(
        self, use_sudo: bool = True, sudo_password: str | None = None
    ) -> None:
        self._use_sudo = use_sudo
        self._sudo_password = sudo_password

    def _build_argv(self, argv: list[str]) -> list[str]:
        if not self._use_sudo:
            return list(argv)
        if self._sudo_password is not None:
            # -S reads the password from stdin; -p "" suppresses the prompt text
            # so it never contaminates captured stderr.
            return ["sudo", "-S", "-p", "", *argv]
        return ["sudo", "-n", *argv]

    def _sudo_stdin(self) -> bytes | None:
        """Password bytes to feed `sudo -S` on stdin, or None for passwordless."""
        if self._use_sudo and self._sudo_password is not None:
            return (self._sudo_password + "\n").encode()
        return None

    def run(self, argv: list[str], timeout: int = 120) -> RunResult:
        full = self._build_argv(argv)
        try:
            proc = subprocess.run(
                full, capture_output=True, timeout=timeout, input=self._sudo_stdin()
            )
            return RunResult(
                argv=full,
                returncode=proc.returncode,
                stdout=proc.stdout.decode("utf-8", errors="replace"),
                stderr=proc.stderr.decode("utf-8", errors="replace"),
            )
        except subprocess.TimeoutExpired:
            return RunResult(full, 124, "", f"Timeout after {timeout}s")
        except FileNotFoundError as e:
            return RunResult(full, 127, "", f"Binary not found: {e}")

    def run_to_file(self, argv: list[str], dest: str, timeout: int = 120) -> RunResult:
        # Stream raw stdout to a file — used for binary extraction (icat), where
        # decoding to str would corrupt the bytes.
        full = self._build_argv(argv)
        try:
            with open(dest, "wb") as out:
                proc = subprocess.run(
                    full,
                    stdout=out,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    input=self._sudo_stdin(),
                )
            return RunResult(
                full, proc.returncode, "", proc.stderr.decode("utf-8", "replace")
            )
        except subprocess.TimeoutExpired:
            return RunResult(full, 124, "", f"Timeout after {timeout}s")
        except FileNotFoundError as e:
            return RunResult(full, 127, "", f"Binary not found: {e}")

    # Host-side IO — runs locally (this host is where the image/mount live in the
    # shipped single-machine setup). These are unprivileged reads/creates, so no
    # sudo wrapping; the SSH runner overrides them to act on the remote VM.
    def sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def makedirs(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)

    def isdir(self, path: str) -> bool:
        return os.path.isdir(path)


@dataclass
class Locator:
    """Points materialize() at evidence: a live file, or a file by inode.

    kind="live": a path within a mounted filesystem — read in place by default,
        or copied out (copy=True) for tools that need a real local file.
    kind="inode": a Sleuth Kit metadata address identifying a file by its inode
        rather than its path (e.g. a deleted file, or NTFS's $MFT). The bytes are
        extracted with `icat` directly from the partition's device, so content
        that is not reachable through the mounted filesystem can still be read.
    """

    kind: str
    volume_index: int = 0
    path: str = ""
    inode: str = ""
    reason: str = ""


@dataclass
class Volume:
    """A mountable filesystem found on the image."""

    index: int
    device: str  # block device to mount/probe (/dev/loopN or /dev/loopNpK)
    fs_type: str  # canonical (normalized) filesystem name
    start_sector: int = 0  # partition start in 512-byte sectors (metadata)
    offset_bytes: int = 0  # start_sector * 512


@dataclass
class IntegrityRecord:
    """SHA-256 of the evidence image, captured before and after the run."""

    image_path: str
    before_sha256: str
    after_sha256: Optional[str] = None

    @property
    def verified(self) -> bool:
        return self.after_sha256 is not None and self.after_sha256 == self.before_sha256


# Normalize the many fs spellings emitted by libblkid/lsblk and blkid into one
# canonical key. New evidence types are a data change here, not an engine change.
_FS_ALIASES = {
    "ntfs": "ntfs",
    "fat": "vfat",
    "fat12": "vfat",
    "fat16": "vfat",
    "fat32": "vfat",
    "vfat": "vfat",
    "msdos": "vfat",
    "exfat": "exfat",
    "ext2": "ext4",
    "ext3": "ext4",
    "ext4": "ext4",
    "xfs": "xfs",
    "btrfs": "btrfs",
    "hfs": "hfsplus",
    "hfs+": "hfsplus",
    "hfsplus": "hfsplus",
    "apfs": "apfs",
    "iso9660": "iso9660",
    "udf": "udf",
}

# Canonical filesystem -> (mount driver, read-only options). The ro loop is the
# real write-block; these options additionally suppress journal replay (itself a
# forensic-soundness violation). Unknown types fall back to ("auto", "ro").
_FS_MOUNT = {
    "ntfs": ("ntfs-3g", "ro,show_sys_files"),
    "vfat": ("vfat", "ro"),
    "exfat": ("exfat", "ro"),
    "ext4": ("ext4", "ro,noload"),
    "xfs": ("xfs", "ro,norecovery"),
    "btrfs": ("btrfs", "ro,nologreplay"),
    "hfsplus": ("hfsplus", "ro"),
    # APFS has no in-kernel Linux driver; mounting it needs apfs-fuse (a FUSE
    # binary driven differently from `mount -t`), which may not be installed. We
    # still detect apfs so it is recorded; the mount itself may fail.
    "apfs": ("apfs-fuse", "ro"),
    "iso9660": ("iso9660", "ro"),
    "udf": ("udf", "ro"),
}

_E01_SUFFIXES = (".e01", ".ex01", ".s01")
_SECTOR = 512  # lsblk/sysfs START is always in 512-byte units (4Kn-safe)

# Windows is detected by a marker directory. ntfs-3g preserves on-disk case and
# isdir is case-sensitive on Linux, so probe the realistic casings: modern
# installs use Windows/System32, XP-era images use WINDOWS/system32.
_WINDOWS_MARKERS = (
    ("Windows", "System32"),
    ("WINDOWS", "system32"),
    ("WINDOWS", "System32"),
    ("Windows", "system32"),
)


class EvidenceSession:
    def __init__(
        self,
        image_path: str,
        *,
        runner: PrivilegedRunner,
        work_dir: str,
        executor=None,
        atexit_register=atexit.register,
        signal_register=signal.signal,
    ) -> None:
        self._image_path = image_path
        self._runner = runner
        self._work_dir = work_dir
        # Optional command executor whose set of allowed paths is extended at
        # mount time, so commands run through it may read the just-mounted
        # evidence and the extraction cache (paths that did not exist when it was
        # constructed).
        self._executor = executor
        # The atexit/signal registrars are injectable so tests can capture them;
        # they default to the real ones.
        self._atexit_register = atexit_register
        self._signal_register = signal_register
        self._closed = False
        # Signal handlers that were installed before this session registered its
        # own, kept so they can be restored on close().
        self._prev_signal_handlers: dict = {}

        self._ewf_dir = os.path.join(work_dir, "ewf")
        self._mnt_base = os.path.join(work_dir, "mnt")
        # The extraction cache is writable and lives outside the mounted evidence,
        # so a tool writing output here can never accidentally target the
        # read-only image.
        self._cache_dir = os.path.join(work_dir, "cache")
        self._custody_path = os.path.join(work_dir, "evidence_access.jsonl")

        self._raw_device: Optional[str] = None
        self._is_ewf = image_path.lower().endswith(_E01_SUFFIXES)
        self._volumes: list[Volume] = []
        self._roots: list[str] = []
        self._os: Optional[str] = None
        self._integrity: Optional[IntegrityRecord] = None

    # --- lifecycle ---------------------------------------------------------

    def open(self, keys=None) -> "EvidenceSession":
        """Open the image, mount its filesystems read-only, and start the run.

        `keys` is reserved for future unlock material for encrypted volumes
        (e.g. LUKS or BitLocker passphrases/recovery keys). It is accepted for
        forward compatibility but is not yet used.
        """
        # 1. Integrity "before" — bracket the whole run with a hash. Set before
        #    the try below so that, if any later step fails, close()'s "after"
        #    hash still has a baseline to compare against.
        self._integrity = IntegrityRecord(
            image_path=self._image_path,
            # Hash on the host where the image lives (local here, the remote VM
            # under an SSH runner) — never with a local open() that would fail
            # when the image is on another machine.
            before_sha256=self._runner.sha256(self._image_path),
        )

        # If any setup step after the baseline fails, tear down whatever was
        # already created (FUSE mount, loop device, partially-mounted
        # partitions) so nothing leaks, then re-raise. close() handles partial
        # state and is idempotent. (Python does not call __exit__ when __enter__
        # raises, so the context-manager path relies on this too.)
        try:
            # 2. Attach the image read-only with a kernel partition scan.
            if self._is_ewf:
                # Create the FUSE mount point on the host where ewfmount runs.
                self._runner.makedirs(self._ewf_dir)
                self._run("ewfmount", [self._image_path, self._ewf_dir])
                raw_source = os.path.join(self._ewf_dir, "ewf1")
            else:
                raw_source = self._image_path
            self._raw_device = self._attach_loop_ro(raw_source)

            # Install teardown handlers as soon as there is state to release, so
            # a failure in a later step (or a signal arriving mid-open) still
            # cleans up rather than leaking the loop/mounts/FUSE layer.
            self._register_crash_handlers()

            # 3. Enumerate volumes from the kernel's view (lsblk).
            self._volumes = self._enumerate_volumes()

            # 4. Mount each volume's device read-only. A volume that fails to
            #    mount (e.g. missing driver or corrupt filesystem) is skipped
            #    rather than aborting the whole run; it stays in self._volumes
            #    (it is known) but is absent from self._roots (it is not
            #    mounted), so a mounted volume is distinguishable from a failed
            #    one.
            self._roots = [
                m for m in (self._mount_volume(v) for v in self._volumes) if m
            ]

            # 5. Auto-detect OS from the mounted tree -> profile.
            self._os = self._detect_os(self._roots)

            # 6. Let the executor read the mounted evidence and cache.
            if self._executor is not None:
                for root in self._roots:
                    self._executor.add_evidence_root(root)
                self._executor.add_evidence_root(self._cache_dir)
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        # Idempotent: teardown + the integrity check run exactly once, even if
        # close() is reached via both the context manager and an atexit/signal.
        #
        # The idempotency guard is not atomic against signal delivery on its own:
        # a SIGTERM/SIGINT arriving between reading and setting the flag would
        # re-enter close() through the signal handler and tear down twice. Block
        # those signals around the guard (and the teardown) so the flag is set
        # without interruption; the prior mask is always restored. Platforms
        # without pthread_sigmask (or off the main thread) simply skip blocking.
        blocked = False
        try:
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
            )
            blocked = True
        except (AttributeError, ValueError, OSError):
            previous_mask = None

        try:
            if self._closed:
                return
            self._closed = True

            # Put the caller's original signal handlers back before doing
            # anything else, so the session never permanently overrides them.
            self._restore_signal_handlers()

            # Tear down in reverse: unmount filesystems, then detach the loop
            # (which removes its partition devices), then unmount the FUSE layer.
            for root in reversed(self._roots):
                self._run("umount", [root], check=False)
            # A scanned btrfs filesystem keeps its backing loop device busy, so
            # `losetup -d` fails and the loop leaks unless btrfs is told to
            # forget the device first.
            if any(v.fs_type == "btrfs" for v in self._volumes):
                self._run("btrfs", ["device", "scan", "--forget"], check=False)
            if self._raw_device:
                self._run("losetup", ["-d", self._raw_device], check=False)
            if self._is_ewf:
                self._run("umount", [self._ewf_dir], check=False)

            # Integrity "after" — re-hash, write the report, then assert
            # untouched.
            if self._integrity is not None:
                self._integrity.after_sha256 = self._runner.sha256(self._image_path)
                self._write_integrity_report()
                if not self._integrity.verified:
                    raise SpoliationError(
                        f"Evidence hash changed during investigation: "
                        f"{self._integrity.before_sha256} -> "
                        f"{self._integrity.after_sha256}"
                    )
        finally:
            if blocked:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def __enter__(self) -> "EvidenceSession":
        return self.open()

    def __exit__(self, *exc) -> bool:
        self.close()
        return False

    # --- accessors ---------------------------------------------------------

    def image_path(self) -> str:
        return self._image_path

    def raw_device(self) -> str:
        if self._raw_device is None:
            raise RuntimeError("Session not open; no raw device")
        return self._raw_device

    def roots(self) -> list[str]:
        return list(self._roots)

    def volumes(self) -> list[Volume]:
        return list(self._volumes)

    def integrity(self) -> IntegrityRecord:
        if self._integrity is None:
            raise RuntimeError("Session not open; no integrity record")
        return self._integrity

    @property
    def os(self) -> Optional[str]:
        return self._os

    @property
    def profile(self) -> Optional[str]:
        return self._os

    # --- materialization ---------------------------------------------------

    def materialize(self, locator: Locator, *, copy: bool = False) -> str:
        """Return a real local path for the evidence the locator points at.

        - live (default): the path of the file as mounted, read in place (no
          copy).
        - live + copy=True: a read-only copy in the cache, for tools that
          memory-map the file, write sidecar files next to it, or need a seekable
          real file (a read-only or FUSE mount can break those).
        - inode: bytes extracted with `icat` from the partition's device, for
          content not reachable through the mounted filesystem (deleted files,
          NTFS's $MFT, ...).

        Extraction is not size-capped, so large but legitimate evidence (page or
        hibernation files, memory-resident artifacts) is never silently skipped.
        Extracted content is deduplicated by SHA-256, and every extraction is
        appended to the custody log (evidence_access.jsonl).
        """
        if locator.kind == "live":
            in_place = self._resolve_live(locator)
            if not copy:
                return in_place
            dest = self._cache_file(in_place)
            self._record_custody("live-copy", locator, dest)
            return dest
        if locator.kind == "inode":
            dest = self._extract_inode(locator)
            self._record_custody("inode", locator, dest)
            return dest
        raise ValueError(f"Unknown locator kind: {locator.kind!r}")

    def _resolve_live(self, locator: Locator) -> str:
        root = self._roots[locator.volume_index]
        candidate = os.path.join(root, locator.path.lstrip("/"))
        # Symlink-escape guard: a symlink in the evidence must not let a read
        # leave the mount root. (This is a safety guard, not a size guard.)
        real_root = os.path.realpath(root)
        real = os.path.realpath(candidate)
        if real != real_root and not real.startswith(real_root + os.sep):
            raise ValueError(f"Locator path escapes evidence root: {locator.path!r}")
        return candidate

    def _extract_inode(self, locator: Locator) -> str:
        os.makedirs(self._cache_dir, exist_ok=True)
        device = self._volumes[locator.volume_index].device
        # A unique temp name per call, so concurrent extractions (or any other
        # writer in the cache dir) can't clobber each other's bytes before the
        # atomic content-addressed commit.
        fd, tmp = tempfile.mkstemp(dir=self._cache_dir)
        os.close(fd)  # run_to_file reopens this path to stream icat's output
        result = self._runner.run_to_file(["icat", device, locator.inode], tmp)
        if result.returncode != 0:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise RuntimeError(
                f"icat failed for inode {locator.inode} on {device}: {result.stderr}"
            )
        return self._commit_cache_temp(tmp)

    def _cache_file(self, src: str) -> str:
        # Stream the source into the cache in fixed-size chunks, hashing as we go,
        # so memory stays bounded regardless of file size (large evidence such as
        # pagefile/hiberfil is the whole point). One read pass produces both the
        # copy and its digest; then content-address the result, deduping if we
        # already hold those exact bytes.
        os.makedirs(self._cache_dir, exist_ok=True)
        digest = hashlib.sha256()
        fd, tmp = tempfile.mkstemp(dir=self._cache_dir)
        try:
            with os.fdopen(fd, "wb") as out, open(src, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
                    out.write(chunk)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        dest = os.path.join(self._cache_dir, digest.hexdigest())
        if os.path.exists(dest):
            os.remove(tmp)
        else:
            os.chmod(tmp, 0o444)
            os.replace(tmp, dest)
        return dest

    def _commit_cache_temp(self, tmp: str) -> str:
        # Content-address the extracted temp file; dedup if we already have it.
        digest = self._sha256(tmp)
        dest = os.path.join(self._cache_dir, digest)
        if os.path.exists(dest):
            os.remove(tmp)
        else:
            os.chmod(tmp, 0o444)
            os.replace(tmp, dest)
        return dest

    def _record_custody(self, kind: str, locator: Locator, dest: str) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kind": kind,
            "volume_index": locator.volume_index,
            "path": locator.path,
            "inode": locator.inode,
            "dest": dest,
            "sha256": os.path.basename(dest),
            "reason": locator.reason,
        }
        with open(self._custody_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    # --- crash safety ------------------------------------------------------

    def _register_crash_handlers(self) -> None:
        # atexit always runs; signals turn an abrupt SIGTERM/SIGINT into an
        # orderly teardown so mounts/loops/FUSE never leak.
        self._atexit_register(self._safe_close)
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                # Keep the prior handler so close() can put it back.
                self._prev_signal_handlers[sig] = self._signal_register(
                    sig, self._on_signal
                )
            except (ValueError, OSError):
                # signal.signal only works in the main thread; if we're not in
                # it, atexit still covers teardown.
                pass

    def _restore_signal_handlers(self) -> None:
        # Reinstall whatever handlers were present before open(), so a caller's
        # (or another library's) signal handling is not left overridden.
        for sig, previous in self._prev_signal_handlers.items():
            try:
                # A handler not installed from Python reads back as None, which
                # signal.signal() rejects; the default disposition stands in for
                # it so restoring never raises.
                self._signal_register(
                    sig, previous if previous is not None else signal.SIG_DFL
                )
            except (ValueError, OSError, TypeError):
                pass
        self._prev_signal_handlers = {}

    def _safe_close(self) -> None:
        # Never raise from an atexit/signal context (e.g. swallow a spoliation
        # error here — it is still recorded in integrity_report.json).
        try:
            self.close()
        except Exception:
            pass

    def _on_signal(self, signum, frame) -> None:
        self._safe_close()
        raise SystemExit(128 + signum)

    def _write_integrity_report(self) -> None:
        if self._integrity is None:
            return
        report = {
            "image_path": self._integrity.image_path,
            "before_sha256": self._integrity.before_sha256,
            "after_sha256": self._integrity.after_sha256,
            "verified": self._integrity.verified,
        }
        with open(os.path.join(self._work_dir, "integrity_report.json"), "w") as f:
            json.dump(report, f, indent=2)

    # --- internals ---------------------------------------------------------

    def _run(self, cmd: str, args: list[str], check: bool = True) -> RunResult:
        result = self._runner.run([cmd, *args])
        if check and result.returncode != 0:
            raise RuntimeError(
                f"Privileged command failed ({result.returncode}): "
                f"{cmd} {' '.join(args)}\n{result.stderr}"
            )
        return result

    def _attach_loop_ro(self, source: str) -> str:
        # `-r` read-only (block-layer write-block) + `-P` partition scan so the
        # kernel exposes /dev/loopNpK for each partition.
        result = self._run("losetup", ["-r", "-P", "-f", "--show", source])
        device = result.stdout.strip()
        if not device:
            raise RuntimeError(f"losetup returned no device for {source}")
        return device

    def _enumerate_volumes(self) -> list[Volume]:
        base = self.raw_device()
        rows = self._lsblk(base)
        base_name = os.path.basename(base)
        partitions = [r for r in rows if r["type"] == "part"]

        if not partitions:
            # Partitionless image: the whole device is one filesystem. The base
            # loop row carries the FSTYPE (blkid fallback if libblkid was blank).
            base_row = next((r for r in rows if r["name"] == base_name), None)
            fs = self._normalize_fs(base_row["fstype"]) if base_row else ""
            if not fs:
                fs = self._normalize_fs(self._blkid_device(base))
            return [Volume(0, base, fs or "unknown", 0, 0)]

        volumes: list[Volume] = []
        for r in partitions:
            device = "/dev/" + r["name"]
            fs = self._normalize_fs(r["fstype"]) or self._normalize_fs(
                self._blkid_device(device)
            )
            if not fs:
                # Not a mountable filesystem (swap / LVM2_member / crypto_LUKS /
                # unformatted). LVM/LUKS handling is a deferred enhancement.
                continue
            start = self._partition_start_sector(r["name"])
            volumes.append(
                Volume(
                    index=len(volumes),
                    device=device,
                    fs_type=fs,
                    start_sector=start,
                    offset_bytes=start * _SECTOR,
                )
            )
        return volumes

    def _lsblk(self, base: str) -> list[dict]:
        # `-P` pairs form is robust to empty fields (e.g. a partition libblkid
        # can't identify), unlike whitespace-split columns.
        #
        # Do NOT request the START column here: it only exists on util-linux
        # >= 2.39, and on older lsblk the whole call fails with "unknown column:
        # START" and exits non-zero. Since this runs check=False, that failure was
        # swallowed -> zero rows -> _enumerate_volumes' partitionless branch
        # misfired and the disk mounted nothing (empty mnt/volN, raw-only run).
        # The start sector is read from sysfs instead (see _partition_start_sector).
        result = self._run("lsblk", ["-Pno", "NAME,TYPE,FSTYPE", base], check=False)
        if result.returncode != 0:
            # Surface the failure rather than swallowing it — a silent lsblk
            # error is exactly what masked this bug across multiple runs.
            print(
                f"[evidence] lsblk failed ({result.returncode}) on {base}: "
                f"{result.stderr.strip()}",
                file=sys.stderr,
            )
        rows: list[dict] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            kv = dict(re.findall(r'(\w+)="([^"]*)"', line))
            rows.append(
                {
                    "name": kv.get("NAME", ""),
                    "type": kv.get("TYPE", ""),
                    "fstype": kv.get("FSTYPE", ""),
                }
            )
        return rows

    def _partition_start_sector(self, name: str) -> int:
        """Start sector of a partition, read from sysfs.

        Replaces lsblk's START column (util-linux >= 2.39 only). sysfs is present
        on every kernel and its ``start`` is always in 512-byte units, so 4Kn
        disks need no special handling. Read through the runner so it works on the
        remote VM under an SSH runner too.
        """
        res = self._run("cat", [f"/sys/class/block/{name}/start"], check=False)
        try:
            return int(res.stdout.strip() or 0)
        except ValueError:
            return 0

    def _blkid_device(self, device: str) -> str:
        result = self._run("blkid", ["-s", "TYPE", "-o", "value", device], check=False)
        return result.stdout.strip()

    @staticmethod
    def _normalize_fs(raw: str) -> str:
        return _FS_ALIASES.get(raw.strip().lower(), "")

    def _mount_volume(self, vol: Volume) -> Optional[str]:
        # Returns the mount directory on success, or None if the mount failed
        # (e.g. a missing filesystem driver or a corrupt filesystem). A failed
        # mount must not leave its directory in the set of usable roots, since an
        # empty mount point would otherwise look like a real, mounted filesystem.
        mnt = os.path.join(self._mnt_base, f"vol{vol.index}")
        # Create the mount point on the host where `mount` runs.
        self._runner.makedirs(mnt)
        driver, opts = _FS_MOUNT.get(vol.fs_type, ("auto", "ro"))
        # Mount the partition device directly (no offset) — read-only.
        result = self._run(
            "mount", ["-r", "-t", driver, "-o", opts, vol.device, mnt], check=False
        )
        if result.returncode != 0:
            return None
        return mnt

    def _detect_os(self, roots: list[str]) -> Optional[str]:
        # Stat the mounted tree on the host where it is mounted (local, or the
        # remote VM under an SSH runner), so OS detection works in both setups.
        for root in roots:
            if any(
                self._runner.isdir(os.path.join(root, w, s))
                for w, s in _WINDOWS_MARKERS
            ):
                return "windows"
            if self._runner.isdir(os.path.join(root, "System", "Library")):
                return "macos"
            if self._runner.isdir(os.path.join(root, "etc")) and self._runner.isdir(
                os.path.join(root, "var")
            ):
                return "linux"
        return None

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
