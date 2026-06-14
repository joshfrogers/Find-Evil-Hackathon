"""The analysis surface for one piece of evidence.

Different kinds of evidence are accessed in fundamentally different ways. A disk
image is a filesystem container: its partitions can be mounted read-only so that
ordinary tools (ls, find, grep, cat) and file parsers work directly on the files
inside it. A memory dump or a packet capture is not a filesystem — it is read
whole by a specialized tool (a memory analyzer, a packet dissector), so there is
nothing to mount.

This module hides that distinction behind one value object, ``EvidenceView``,
and two functions that manage its lifecycle. The orchestrator opens a view at
the start of an investigation, hands the mounted roots (when present) and the
raw path to its sub-agents, and closes the view at the end. Closing re-hashes
the image and reports whether it was altered during the run.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Optional

from evidence.session import EvidenceSession, IntegrityRecord, SpoliationError

# Evidence types whose container is a mountable filesystem image. Anything not
# listed here is read directly from the raw file — memory dumps, packet
# captures, and plain log files are not filesystems and are never mounted. New
# mountable types are added here, not in the engine.
MOUNTABLE_TYPES = frozenset({"disk"})


@dataclass
class EvidenceSpec:
    """One piece of evidence to analyze: where it is and what kind it is.

    A single investigation may take several specs — for example a disk image and
    a memory capture of the same host — so that findings from each can be
    correlated together. ``evidence_type`` is one of the supported kinds (disk,
    memory, pcap, logs) and decides whether the item is mounted or read raw.
    """

    path: str
    evidence_type: str = "disk"


@dataclass
class EvidenceView:
    """How the analysis tools should reach a single piece of evidence.

    raw_path:
        The original evidence file. Always present. Tools that consume the raw
        container use this directly: a deleted-file recovery pass over a disk
        image (Sleuth Kit ``fls``/``icat``), a memory analyzer (``-f``), a
        packet dissector (``-r``).
    mount_roots:
        Read-only filesystem paths where a disk image's partitions are mounted.
        Empty when the evidence is not a mountable filesystem, or when mounting
        was unavailable. When non-empty, live files are reachable with ordinary
        filesystem tools under these paths — no offset arithmetic, no per-file
        extraction.
    session:
        The open mounting session backing ``mount_roots``, or ``None`` when
        nothing was mounted. It owns teardown and the before/after integrity
        hash of the image.
    """

    raw_path: str
    mount_roots: list[str] = field(default_factory=list)
    session: Optional[EvidenceSession] = None

    @property
    def is_mounted(self) -> bool:
        return bool(self.mount_roots)


@dataclass
class TeardownResult:
    """The outcome of releasing an ``EvidenceView``.

    integrity:
        The before/after image-hash record, or ``None`` when nothing was
        mounted (no integrity bracket was taken).
    spoliation:
        A message describing how the image hash changed during the run, or
        ``None`` if it was unchanged. A non-``None`` value means the evidence
        may have been altered while it was being analyzed, so the resulting
        report cannot be treated as forensically sound.
    """

    integrity: Optional[IntegrityRecord] = None
    spoliation: Optional[str] = None


def open_evidence(
    evidence_path: str,
    evidence_type: str,
    *,
    executor=None,
    runner=None,
    work_dir: Optional[str] = None,
    session_factory: Callable[..., EvidenceSession] = EvidenceSession,
) -> EvidenceView:
    """Open evidence for analysis, mounting it read-only when it is a disk image.

    For a disk image, the image is attached and its partitions mounted read-only
    through a mounting session, so that live files can be read with ordinary
    tools. When an executor is supplied it is granted read access to the mounted
    roots and the extraction cache, so commands run through it can reach paths
    that did not exist when the executor was constructed.

    For every other evidence type there is no filesystem to mount, so a raw-only
    view is returned and no session is created.

    Mounting is best-effort. If the image cannot be attached or mounted — an
    unsupported filesystem, a missing kernel driver, a corrupt container — the
    error is swallowed and a raw-only view is returned, because a raw image can
    still be analyzed directly (e.g. with Sleuth Kit). The investigation
    degrades to raw access rather than failing outright.
    """
    if evidence_type not in MOUNTABLE_TYPES:
        return EvidenceView(raw_path=evidence_path)

    # Pre-mounted / extracted tree: a DIRECTORY is treated as an already-mounted
    # read-only filesystem and analyzed directly — no image attach, no mount, no
    # root, no EWF/libewf. This is the portable path for environments without the
    # full forensic stack (or for an image mounted by other means / a carved file
    # tree). Live-file analysis only; raw-image deleted-file recovery (Sleuth Kit
    # on the container) is unavailable because there is no raw image.
    if os.path.isdir(evidence_path):
        if executor is not None:
            executor.add_evidence_root(evidence_path)
        return EvidenceView(
            raw_path=evidence_path, mount_roots=[evidence_path], session=None
        )

    if runner is None:
        # Imported and constructed lazily so that non-mount evidence and tests
        # never spin up the privileged runner.
        from evidence.session import SubprocessPrivilegedRunner

        runner = SubprocessPrivilegedRunner()
    # Track whether we created the work_dir, so the failure path removes only a
    # directory we own and never a caller-provided one.
    created_work_dir = work_dir is None
    if created_work_dir:
        work_dir = tempfile.mkdtemp(prefix="agentic-sift-evidence-")

    session = session_factory(
        evidence_path, runner=runner, work_dir=work_dir, executor=executor
    )
    try:
        session.open()
    except Exception:
        # open() tears its own partial state down on failure, but the work_dir
        # we created for it would otherwise leak; remove it before degrading to
        # raw-only analysis.
        if created_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)
        return EvidenceView(raw_path=evidence_path)

    return EvidenceView(
        raw_path=evidence_path,
        mount_roots=session.roots(),
        session=session,
    )


def close_evidence(view: EvidenceView) -> TeardownResult:
    """Release a view's mounts and capture the closing integrity check.

    A raw-only view has nothing to release. A mounted view is torn down
    (unmount, detach, re-hash the image). A changed hash raises inside the
    session's close(); it is caught and returned as ``spoliation`` so the caller
    can still emit a report that flags the evidence as compromised instead of
    crashing during teardown.
    """
    if view.session is None:
        return TeardownResult()
    try:
        view.session.close()
        return TeardownResult(integrity=view.session.integrity())
    except SpoliationError as exc:
        return TeardownResult(integrity=view.session.integrity(), spoliation=str(exc))
