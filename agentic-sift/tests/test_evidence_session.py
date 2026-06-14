"""Tests for EvidenceSession (open / serve / verify / teardown).

A RecordingRunner stands in for the privileged command runner, so the mount
pipeline can be exercised without root, real block devices, or a disk image. The
scripted command outputs mirror the real output of the underlying tools:

    losetup -r -P <source>            -> /dev/loopN (+ a kernel partition scan
                                          creating /dev/loopNpK per partition)
    lsblk -Pno NAME,TYPE,FSTYPE,START -> child partitions, filesystem type, and
                                          start offset, one per line
    mount -r <partition_device>       -> each partition's device mounted directly
"""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Allow running these tests directly (python -m unittest) without a build
# system, by putting the package root on sys.path. Mirrors the other test
# modules in this project.
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import json  # noqa: E402

from evidence.session import (  # noqa: E402
    EvidenceSession,
    Locator,
    RunResult,
    SpoliationError,
    SubprocessPrivilegedRunner,
)


class RecordingRunner:
    """Fake privileged runner: records argv calls, returns scripted output.

    `script` maps a command basename (argv[0]) to a RunResult or a callable
    taking the argv and returning a RunResult. Unmapped commands succeed empty.
    """

    def __init__(self, script=None, file_script=None):
        self.calls: list[list[str]] = []
        self.script = script or {}
        # basename -> bytes written by run_to_file (binary capture, e.g. icat)
        self.file_script = file_script or {}

    def run(self, argv, timeout=120) -> RunResult:
        self.calls.append(list(argv))
        key = os.path.basename(argv[0])
        resp = self.script.get(key)
        if callable(resp):
            resp = resp(argv)
        if resp is None:
            return RunResult(argv=list(argv), returncode=0, stdout="", stderr="")
        return RunResult(
            argv=list(argv),
            returncode=resp.returncode,
            stdout=resp.stdout,
            stderr=resp.stderr,
        )

    def run_to_file(self, argv, dest, timeout=120) -> RunResult:
        self.calls.append(list(argv))
        key = os.path.basename(argv[0])
        data = self.file_script.get(key, b"")
        if callable(data):
            data = data(argv)
        with open(dest, "wb") as f:
            f.write(data)
        return RunResult(argv=list(argv), returncode=0, stdout="", stderr="")

    # Host-side IO the session routes through the runner. The fake performs the
    # real local operation, so it behaves exactly like the in-process os/hashlib
    # calls these replaced — keeping the existing mount/integrity/OS-detection
    # tests meaningful against real temp files and dirs.
    def sha256(self, path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def makedirs(self, path) -> None:
        os.makedirs(path, exist_ok=True)

    def isdir(self, path) -> bool:
        return os.path.isdir(path)

    def command_sequence(self) -> list[str]:
        return [os.path.basename(c[0]) for c in self.calls]


def _ok(stdout="", stderr="", rc=0) -> RunResult:
    return RunResult(argv=[], returncode=rc, stdout=stdout, stderr=stderr)


def _write_image(data: bytes = b"EVIDENCE-BYTES", suffix=".E01") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _lsblk_line(name, typ, fstype="", start="") -> str:
    # The real `lsblk -Pno` form: KEY="value" pairs, robust to empty fields.
    return f'NAME="{name}" TYPE="{typ}" FSTYPE="{fstype}" START="{start}"'


def _losetup_fn(loop):
    def fn(argv):
        if "-d" in argv:
            return _ok()
        return _ok(stdout=loop + "\n")

    return fn


def _partitionless_script(loop="/dev/loop9", fstype="ntfs", blkid=""):
    """Partitionless image: base loop carries the FSTYPE, no part children."""
    base = os.path.basename(loop)
    return {
        "ewfmount": _ok(),
        "losetup": _losetup_fn(loop),
        "lsblk": _ok(stdout=_lsblk_line(base, "loop", fstype) + "\n"),
        "blkid": _ok(stdout=(blkid + "\n") if blkid else "\n"),
        "mount": _ok(),
        "umount": _ok(),
    }


def _partitioned_script(loop="/dev/loop9", parts=None, blkid=""):
    """Partitioned image: base loop row + one TYPE=part row per partition.

    parts: list of (suffix, fstype, start). Empty fstype exercises the blkid
    fallback (libblkid couldn't ID it, e.g. APFS).
    """
    base = os.path.basename(loop)
    parts = parts or [("p1", "exfat", "2048"), ("p2", "btrfs", "122880")]
    lines = [_lsblk_line(base, "loop", "", "")]
    for suf, fs, start in parts:
        lines.append(_lsblk_line(base + suf, "part", fs, start))
    return {
        "ewfmount": _ok(),
        "losetup": _losetup_fn(loop),
        "lsblk": _ok(stdout="\n".join(lines) + "\n"),
        "blkid": _ok(stdout=(blkid + "\n") if blkid else "\n"),
        "mount": _ok(),
        "umount": _ok(),
    }


class TestMountPipeline(unittest.TestCase):
    def test_e01_pipeline_runs_in_order(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            EvidenceSession(img, runner=runner, work_dir=work).open()
            seq = runner.command_sequence()
            self.assertEqual(seq[0], "ewfmount")
            self.assertEqual(seq[1], "losetup")
            self.assertIn("lsblk", seq)
            self.assertEqual(seq[-1], "mount")
            os.unlink(img)

    def test_losetup_is_read_only_with_partition_scan(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            EvidenceSession(img, runner=runner, work_dir=work).open()
            attach = next(
                c for c in runner.calls if "losetup" in c[0] and "--show" in c
            )
            self.assertIn("-r", attach)  # read-only = primary write-block
            self.assertIn("-P", attach)  # kernel partition scan -> /dev/loopNpK
            os.unlink(img)

    def test_raw_device_is_base_loop(self):
        runner = RecordingRunner(_partitionless_script(loop="/dev/loop7"))
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            self.assertEqual(sess.raw_device(), "/dev/loop7")
            os.unlink(img)

    def test_teardown_reverses_setup(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work)
            sess.open()
            sess.close()
            seq = runner.command_sequence()
            self.assertIn("umount", seq)
            detach = [c for c in runner.calls if "losetup" in c[0] and "-d" in c]
            self.assertTrue(detach, "expected losetup -d teardown")
            self.assertLess(seq.index("umount"), len(seq) - 1)
            os.unlink(img)


class TestVolumeEnumeration(unittest.TestCase):
    def test_partitionless_single_volume_on_base_device(self):
        runner = RecordingRunner(_partitionless_script(loop="/dev/loop9"))
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            vols = sess.volumes()
            self.assertEqual(len(vols), 1)
            self.assertEqual(vols[0].device, "/dev/loop9")  # whole device
            self.assertEqual(vols[0].fs_type, "ntfs")
            self.assertEqual(vols[0].offset_bytes, 0)
            os.unlink(img)

    def test_partitioned_volumes_use_partition_devices(self):
        runner = RecordingRunner(_partitioned_script(loop="/dev/loop9"))
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            vols = sess.volumes()
            self.assertEqual([v.device for v in vols], ["/dev/loop9p1", "/dev/loop9p2"])
            self.assertEqual([v.fs_type for v in vols], ["exfat", "btrfs"])
            # offset = START sectors * 512 (sysfs/lsblk START is always 512-unit,
            # so 4Kn disks need no special handling).
            self.assertEqual(vols[0].offset_bytes, 2048 * 512)
            self.assertEqual(vols[1].offset_bytes, 122880 * 512)
            os.unlink(img)

    def test_partition_without_filesystem_is_dropped(self):
        # A partition libblkid can't ID and blkid also can't -> not mountable
        # (e.g. swap / BIOS boot / unformatted) -> dropped.
        parts = [("p1", "ext4", "2048"), ("p2", "", "500000")]
        runner = RecordingRunner(_partitioned_script(parts=parts, blkid=""))
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            self.assertEqual([v.device for v in sess.volumes()], ["/dev/loop9p1"])
            os.unlink(img)


class TestFsDetection(unittest.TestCase):
    def _single_part_fs(self, lsblk_fstype, blkid="", expected=None):
        runner = RecordingRunner(
            _partitioned_script(parts=[("p1", lsblk_fstype, "2048")], blkid=blkid)
        )
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            fs = sess.volumes()[0].fs_type
            os.unlink(img)
            return fs

    def test_exfat(self):
        self.assertEqual(self._single_part_fs("exfat"), "exfat")

    def test_vfat_from_fat32(self):
        self.assertEqual(self._single_part_fs("vfat"), "vfat")

    def test_ext_family_normalized(self):
        self.assertEqual(self._single_part_fs("ext3"), "ext4")

    def test_hfsplus(self):
        self.assertEqual(self._single_part_fs("hfsplus"), "hfsplus")

    def test_apfs_via_blkid_fallback(self):
        # libblkid in lsblk left FSTYPE empty; a direct blkid on the partition
        # device resolves it.
        self.assertEqual(self._single_part_fs("", blkid="apfs"), "apfs")


class TestMountDrivers(unittest.TestCase):
    def _driver_for(self, fstype):
        runner = RecordingRunner(_partitioned_script(parts=[("p1", fstype, "2048")]))
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            EvidenceSession(img, runner=runner, work_dir=work).open()
            mount = next(c for c in runner.calls if os.path.basename(c[0]) == "mount")
            os.unlink(img)
            return mount[mount.index("-t") + 1]

    def test_ntfs_driver(self):
        self.assertEqual(self._driver_for("ntfs"), "ntfs-3g")

    def test_vfat_driver(self):
        self.assertEqual(self._driver_for("vfat"), "vfat")

    def test_exfat_driver(self):
        self.assertEqual(self._driver_for("exfat"), "exfat")

    def test_btrfs_driver(self):
        self.assertEqual(self._driver_for("btrfs"), "btrfs")

    def test_mounts_partition_device_not_offset(self):
        runner = RecordingRunner(_partitioned_script(loop="/dev/loop9"))
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            EvidenceSession(img, runner=runner, work_dir=work).open()
            mounts = [c for c in runner.calls if os.path.basename(c[0]) == "mount"]
            # Mount the partition device directly; never an offset= option.
            self.assertIn("/dev/loop9p1", mounts[0])
            self.assertTrue(all("offset=" not in " ".join(m) for m in mounts))
            os.unlink(img)


class TestIntegrity(unittest.TestCase):
    def test_before_hash_recorded_on_open(self):
        data = b"the-evidence"
        expected = hashlib.sha256(data).hexdigest()
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image(data)
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            self.assertEqual(sess.integrity().before_sha256, expected)
            sess.close()
            os.unlink(img)

    def test_clean_close_verifies_integrity(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work)
            sess.open()
            sess.close()
            rec = sess.integrity()
            self.assertEqual(rec.after_sha256, rec.before_sha256)
            self.assertTrue(rec.verified)
            os.unlink(img)

    def test_spoliation_detected_on_close(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image(b"original")
            sess = EvidenceSession(img, runner=runner, work_dir=work)
            sess.open()
            with open(img, "wb") as f:
                f.write(b"tampered!")
            with self.assertRaises(SpoliationError):
                sess.close()
            os.unlink(img)


class TestOsDetection(unittest.TestCase):
    def test_detects_windows(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            os.makedirs(os.path.join(work, "mnt", "vol0", "Windows", "System32"))
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            self.assertEqual(sess.os, "windows")
            self.assertEqual(sess.profile, "windows")
            os.unlink(img)

    def test_detects_linux(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            os.makedirs(os.path.join(work, "mnt", "vol0", "etc"))
            os.makedirs(os.path.join(work, "mnt", "vol0", "var"))
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            self.assertEqual(sess.os, "linux")
            os.unlink(img)


class TestAccessors(unittest.TestCase):
    def test_image_path_and_roots(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            self.assertEqual(sess.image_path(), img)
            self.assertTrue(sess.roots())
            self.assertTrue(all(os.path.isabs(r) for r in sess.roots()))
            os.unlink(img)


class TestRawImage(unittest.TestCase):
    def test_dd_image_skips_ewfmount(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image(b"RAW-DD", suffix=".dd")
            EvidenceSession(img, runner=runner, work_dir=work).open()
            seq = runner.command_sequence()
            self.assertNotIn("ewfmount", seq)
            self.assertEqual(seq[0], "losetup")
            attach = next(c for c in runner.calls if "--show" in c)
            self.assertIn(img, attach)  # loop attaches the image itself
            os.unlink(img)


class TestOpenIsTransactional(unittest.TestCase):
    def test_open_failure_after_loop_tears_down_loop(self):
        # A non-numeric partition START makes _enumerate_volumes raise after the
        # loop device is already attached. open() must clean up (detach the loop)
        # before re-raising, so no FUSE mount / loop device / partition mount
        # leaks.
        runner = RecordingRunner(
            _partitioned_script(parts=[("p1", "ntfs", "not-a-number")])
        )
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work)
            # A non-numeric partition start makes int() parsing raise ValueError.
            with self.assertRaises(ValueError):
                sess.open()
            detach = [c for c in runner.calls if "losetup" in c[0] and "-d" in c]
            self.assertTrue(detach, "expected losetup -d teardown after failed open")
            os.unlink(img)


class TestMountFailureIsGraceful(unittest.TestCase):
    def test_failed_mount_volume_absent_from_roots(self):
        # One partition's mount fails (e.g. missing driver / corrupt fs); the
        # other mounts fine. The failed volume must not appear in roots(), the
        # good one must, and open() must not raise.
        def mount_fn(argv):
            # Fail the mount of the second partition device only.
            if any(a.endswith("p2") for a in argv):
                return _ok(stderr="mount: bad fs", rc=32)
            return _ok()

        script = _partitioned_script(
            parts=[("p1", "ext4", "2048"), ("p2", "ntfs", "500000")]
        )
        script["mount"] = mount_fn
        runner = RecordingRunner(script)
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work).open()
            good = os.path.join(work, "mnt", "vol0")
            bad = os.path.join(work, "mnt", "vol1")
            self.assertIn(good, sess.roots())
            self.assertNotIn(bad, sess.roots())
            # The failed volume is still known (enumerated), just not mounted.
            self.assertEqual(len(sess.volumes()), 2)
            os.unlink(img)


class TestMaterialize(unittest.TestCase):
    """materialize(): live-in-place, real-copy, and icat extraction.

    Three storage buckets (design §13, C3):
      - live + read-in-place  -> return the mount path (zero copy, the default)
      - live + copy=True      -> real local copy for mmap/sidecar/seek tools
      - inode                 -> icat non-addressable bytes (deleted / $MFT)
    No size guard (2026-06-09 decision). Symlink-escape + content dedup kept.
    """

    def _open(self, work, runner):
        img = _write_image()
        sess = EvidenceSession(img, runner=runner, work_dir=work).open()
        self.addCleanup(lambda: os.path.exists(img) and os.unlink(img))
        return sess

    def test_live_file_read_in_place_is_zero_copy(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            root = os.path.join(work, "mnt", "vol0")
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "ntuser.dat"), "w") as f:
                f.write("hive")
            sess = self._open(work, runner)
            path = sess.materialize(Locator(kind="live", path="ntuser.dat"))
            # Returns the in-place mount path, no copy under the cache.
            self.assertEqual(path, os.path.join(root, "ntuser.dat"))
            self.assertNotIn("cache", path)
            with open(path) as f:
                self.assertEqual(f.read(), "hive")

    def test_live_file_copy_makes_readonly_cache_copy(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            root = os.path.join(work, "mnt", "vol0")
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "places.sqlite"), "wb") as f:
                f.write(b"SQLITE-DB")
            sess = self._open(work, runner)
            path = sess.materialize(
                Locator(kind="live", path="places.sqlite"), copy=True
            )
            self.assertTrue(path.startswith(os.path.join(work, "cache")))
            with open(path, "rb") as f:
                self.assertEqual(f.read(), b"SQLITE-DB")
            # Extracted copies are read-only (0444).
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o444)

    def test_symlink_escape_is_rejected(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            root = os.path.join(work, "mnt", "vol0")
            os.makedirs(root, exist_ok=True)
            # A symlink inside the evidence pointing outside the mount root.
            secret = os.path.join(work, "outside_secret")
            with open(secret, "w") as f:
                f.write("host-secret")
            os.symlink(secret, os.path.join(root, "evil_link"))
            sess = self._open(work, runner)
            with self.assertRaises(ValueError):
                sess.materialize(Locator(kind="live", path="evil_link"))

    def test_inode_extracted_via_icat(self):
        runner = RecordingRunner(
            _partitionless_script(loop="/dev/loop9"),
            file_script={"icat": b"DELETED-FILE-CONTENT"},
        )
        with tempfile.TemporaryDirectory() as work:
            sess = self._open(work, runner)
            path = sess.materialize(
                Locator(kind="inode", volume_index=0, inode="5-128-4")
            )
            with open(path, "rb") as f:
                self.assertEqual(f.read(), b"DELETED-FILE-CONTENT")
            # icat ran against the volume's partition device + inode.
            icat = next(c for c in runner.calls if os.path.basename(c[0]) == "icat")
            self.assertIn("/dev/loop9", icat)
            self.assertIn("5-128-4", icat)

    def test_no_size_guard_large_extraction_succeeds(self):
        big = b"A" * (5 * 1024 * 1024)  # 5 MiB stand-in for a large artifact
        runner = RecordingRunner(_partitionless_script(), file_script={"icat": big})
        with tempfile.TemporaryDirectory() as work:
            sess = self._open(work, runner)
            path = sess.materialize(
                Locator(kind="inode", volume_index=0, inode="9-128-1")
            )
            self.assertEqual(os.path.getsize(path), len(big))

    def test_identical_content_is_deduplicated(self):
        runner = RecordingRunner(
            _partitionless_script(), file_script={"icat": b"SAME-BYTES"}
        )
        with tempfile.TemporaryDirectory() as work:
            sess = self._open(work, runner)
            p1 = sess.materialize(Locator(kind="inode", inode="1-1-1"))
            p2 = sess.materialize(Locator(kind="inode", inode="2-2-2"))
            self.assertEqual(p1, p2)  # content-addressed -> same cache file
            cache = os.path.join(work, "cache")
            self.assertEqual(len(os.listdir(cache)), 1)

    def test_custody_log_records_each_extraction(self):
        runner = RecordingRunner(_partitionless_script(), file_script={"icat": b"x"})
        with tempfile.TemporaryDirectory() as work:
            sess = self._open(work, runner)
            sess.materialize(Locator(kind="inode", inode="1-1-1", reason="deleted exe"))
            log = os.path.join(work, "evidence_access.jsonl")
            self.assertTrue(os.path.exists(log))
            with open(log) as f:
                entries = [json.loads(line) for line in f if line.strip()]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["reason"], "deleted exe")
            self.assertIn("sha256", entries[0])

    def test_live_copy_of_large_file_is_exact(self):
        # Copying a file larger than the streaming buffer must reproduce it byte
        # for byte (exercises the chunk boundary; large evidence is the point).
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            root = os.path.join(work, "mnt", "vol0")
            os.makedirs(root, exist_ok=True)
            data = bytes(range(256)) * 9000  # ~2.3 MB, spans multiple chunks
            with open(os.path.join(root, "big.bin"), "wb") as f:
                f.write(data)
            sess = self._open(work, runner)
            path = sess.materialize(Locator(kind="live", path="big.bin"), copy=True)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), data)

    def test_inode_extraction_leaves_only_the_cached_file(self):
        # After extraction the cache holds just the content-addressed file — no
        # leftover temp file that a concurrent writer could have collided with.
        runner = RecordingRunner(
            _partitionless_script(), file_script={"icat": b"recovered"}
        )
        with tempfile.TemporaryDirectory() as work:
            sess = self._open(work, runner)
            path = sess.materialize(Locator(kind="inode", inode="5-128-4"))
            cache = os.path.join(work, "cache")
            self.assertEqual(os.listdir(cache), [os.path.basename(path)])


class _FakeExecutor:
    """Stand-in for the LLM executor; records runtime-registered roots (W5)."""

    def __init__(self):
        self.roots: list[str] = []

    def add_evidence_root(self, path: str) -> None:
        self.roots.append(path)


class TestCrashSafety(unittest.TestCase):
    """W10: teardown must always run — context manager + atexit + signals —
    and must not leak loops (btrfs scan pins them, so forget before detach)."""

    def test_context_manager_opens_and_tears_down(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            with EvidenceSession(img, runner=runner, work_dir=work) as sess:
                self.assertTrue(sess.roots())
            seq = runner.command_sequence()
            self.assertIn("umount", seq)
            self.assertTrue(any("losetup" in c[0] and "-d" in c for c in runner.calls))
            os.unlink(img)

    def test_close_is_idempotent(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work)
            sess.open()
            sess.close()
            detaches = sum(1 for c in runner.calls if "losetup" in c[0] and "-d" in c)
            sess.close()  # second close must be a no-op
            detaches2 = sum(1 for c in runner.calls if "losetup" in c[0] and "-d" in c)
            self.assertEqual(detaches, detaches2)
            os.unlink(img)

    def test_btrfs_forget_runs_before_loop_detach(self):
        runner = RecordingRunner(_partitioned_script(parts=[("p1", "btrfs", "2048")]))
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work)
            sess.open()
            sess.close()
            seq = runner.command_sequence()
            self.assertIn("btrfs", seq)
            detach_idx = next(
                i for i, c in enumerate(runner.calls) if "losetup" in c[0] and "-d" in c
            )
            self.assertLess(seq.index("btrfs"), detach_idx)
            os.unlink(img)

    def test_no_btrfs_forget_without_btrfs_volume(self):
        runner = RecordingRunner(_partitionless_script(fstype="ntfs"))
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work)
            sess.open()
            sess.close()
            self.assertNotIn("btrfs", runner.command_sequence())
            os.unlink(img)

    def test_crash_handlers_registered_on_open(self):
        import signal as _sig

        atexit_fns = []
        signals = []
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(
                img,
                runner=runner,
                work_dir=work,
                atexit_register=atexit_fns.append,
                signal_register=lambda s, h: signals.append(s),
            )
            sess.open()
            self.assertTrue(atexit_fns, "teardown must be registered with atexit")
            self.assertIn(_sig.SIGTERM, signals)
            self.assertIn(_sig.SIGINT, signals)
            sess.close()
            os.unlink(img)

    def test_signal_handlers_restored_on_close(self):
        # The session must not permanently hijack the process's signal handling:
        # whatever handler was installed before open() is restored on close().
        import signal as _sig

        installed = {}  # sig -> currently-installed handler (simulates the OS)

        def fake_register(sig, handler):
            previous = installed.get(sig, "ORIGINAL-HANDLER")
            installed[sig] = handler
            return previous  # signal.signal returns the prior handler

        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(
                img,
                runner=runner,
                work_dir=work,
                atexit_register=lambda fn: None,
                signal_register=fake_register,
            )
            sess.open()
            self.assertEqual(installed[_sig.SIGTERM], sess._on_signal)
            sess.close()
            # The caller's original handlers are back in place.
            self.assertEqual(installed[_sig.SIGTERM], "ORIGINAL-HANDLER")
            self.assertEqual(installed[_sig.SIGINT], "ORIGINAL-HANDLER")
            os.unlink(img)

    def test_close_handles_none_previous_handler(self):
        # A handler installed outside Python reads back as None. Restoring it
        # must not raise (signal.signal rejects None); close() has to complete
        # its teardown rather than abort partway through.
        import signal as _sig

        installed = {}

        def fake_register(sig, handler):
            previous = installed.get(sig, None)  # no prior Python handler
            installed[sig] = handler
            return previous

        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(
                img,
                runner=runner,
                work_dir=work,
                atexit_register=lambda fn: None,
                signal_register=fake_register,
            )
            sess.open()
            sess.close()  # must not raise on the None previous handler
            # Teardown still ran: the loop was detached.
            detach = [c for c in runner.calls if "losetup" in c[0] and "-d" in c]
            self.assertTrue(detach, "teardown must run despite a None prior handler")
            # The default disposition stands in for the None handler.
            self.assertEqual(installed[_sig.SIGTERM], _sig.SIG_DFL)
            self.assertEqual(installed[_sig.SIGINT], _sig.SIG_DFL)
            os.unlink(img)

    def test_close_idempotent_with_none_previous_handler(self):
        # The same None-handler path must remain idempotent: a second close()
        # is a no-op and never tears down (or restores handlers) twice.
        installed = {}

        def fake_register(sig, handler):
            previous = installed.get(sig, None)
            installed[sig] = handler
            return previous

        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(
                img,
                runner=runner,
                work_dir=work,
                atexit_register=lambda fn: None,
                signal_register=fake_register,
            )
            sess.open()
            sess.close()
            detaches = sum(1 for c in runner.calls if "losetup" in c[0] and "-d" in c)
            sess.close()  # second close must be a no-op
            detaches2 = sum(1 for c in runner.calls if "losetup" in c[0] and "-d" in c)
            self.assertEqual(detaches, detaches2)
            os.unlink(img)

    def test_open_failure_tears_down_partial_state(self):
        # If a step after the loop is attached raises, open() must tear the loop
        # back down rather than leak it — the failure path the teardown exists
        # for. (A non-numeric partition start makes enumeration raise here.)
        script = _partitioned_script(parts=[("p1", "ntfs", "not-a-number")])
        runner = RecordingRunner(script)
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(
                img,
                runner=runner,
                work_dir=work,
                atexit_register=lambda fn: None,
                signal_register=lambda s, h: None,
            )
            # A non-numeric partition start makes int() parsing raise ValueError.
            with self.assertRaises(ValueError):
                sess.open()
            detached = [c for c in runner.calls if "losetup" in c[0] and "-d" in c]
            self.assertTrue(detached, "the attached loop must be detached on failure")
            os.unlink(img)

    def test_integrity_report_written_on_close(self):
        runner = RecordingRunner(_partitionless_script())
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work)
            sess.open()
            sess.close()
            report = os.path.join(work, "integrity_report.json")
            self.assertTrue(os.path.exists(report))
            with open(report) as f:
                rep = json.load(f)
            self.assertTrue(rep["verified"])
            self.assertEqual(rep["before_sha256"], rep["after_sha256"])
            os.unlink(img)


class TestExecutorRegistration(unittest.TestCase):
    """The session registers its mount roots + cache with the executor at mount
    time, so commands run through the executor are allowed to read the live
    mount points and the extraction cache."""

    def test_session_registers_roots_and_cache(self):
        runner = RecordingRunner(_partitionless_script())
        ex = _FakeExecutor()
        with tempfile.TemporaryDirectory() as work:
            img = _write_image()
            sess = EvidenceSession(img, runner=runner, work_dir=work, executor=ex)
            sess.open()
            for r in sess.roots():
                self.assertIn(r, ex.roots)
            self.assertIn(os.path.join(work, "cache"), ex.roots)
            sess.close()
            os.unlink(img)


class TestSubprocessRunner(unittest.TestCase):
    def test_runs_and_captures_stdout(self):
        res = SubprocessPrivilegedRunner(use_sudo=False).run(["echo", "hi-ev"])
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout.strip(), "hi-ev")

    def test_nonzero_exit_captured(self):
        res = SubprocessPrivilegedRunner(use_sudo=False).run(["false"])
        self.assertNotEqual(res.returncode, 0)

    def test_missing_binary_does_not_raise(self):
        res = SubprocessPrivilegedRunner(use_sudo=False).run(["no-such-bin-xyz"])
        self.assertNotEqual(res.returncode, 0)
        self.assertTrue(res.stderr)

    def test_sudo_prefix_applied(self):
        argv = SubprocessPrivilegedRunner(use_sudo=True)._build_argv(["losetup"])
        self.assertEqual(argv[0], "sudo")
        self.assertIn("losetup", argv)


class TestSubprocessRunnerIO(unittest.TestCase):
    """The runner owns host-side IO — sha256 / makedirs / isdir — so that
    EvidenceSession's integrity hash, work-dir creation, and OS detection run on
    the host where the image and mount actually live: the local machine here, and
    the remote VM when an SSH runner is used. The local runner implements them
    directly (hashlib/os), behaving exactly like the in-process calls they
    replace."""

    def test_sha256_matches_hashlib(self):
        data = b"integrity-bytes"
        fd, p = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            self.assertEqual(
                SubprocessPrivilegedRunner(use_sudo=False).sha256(p),
                hashlib.sha256(data).hexdigest(),
            )
        finally:
            os.unlink(p)

    def test_makedirs_creates_nested_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "a", "b", "c")
            r = SubprocessPrivilegedRunner(use_sudo=False)
            r.makedirs(target)
            self.assertTrue(os.path.isdir(target))
            r.makedirs(target)  # idempotent: a second call must not raise
            self.assertTrue(os.path.isdir(target))

    def test_isdir_true_for_dir_false_for_missing(self):
        with tempfile.TemporaryDirectory() as d:
            r = SubprocessPrivilegedRunner(use_sudo=False)
            self.assertTrue(r.isdir(d))
            self.assertFalse(r.isdir(os.path.join(d, "does-not-exist")))


if __name__ == "__main__":
    unittest.main()
