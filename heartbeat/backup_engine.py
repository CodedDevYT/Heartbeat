"""Backup engine: walks a source tree and writes a snapshot to a repository.

Two modes:
    - Full backup:        every file gets hashed and (if new) written to the repo.
    - Incremental backup: we load the latest snapshot's manifest; a file is
                          considered unchanged if its relative path, size, and
                          mtime all match. Unchanged files reuse the previous
                          snapshot's object hash without re-reading the file.
                          Changed or new files are hashed and added.

Network drives (SMB) are handled transparently: on macOS/Linux they appear as
regular mounted paths under /Volumes or /mnt; on Windows they can be accessed
via UNC paths (\\\\server\\share) or mapped drive letters. We don't need any
special code for them, only the ability to walk a path — which `os.walk` does.

Progress callback receives a `BackupProgress` snapshot and may be called from
a worker thread. It must be cheap and thread-safe.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .logger import get_logger
from .manifest import FileEntry, Snapshot
from .repository import Repository

log = get_logger(__name__)

# Read files in 1 MiB chunks when computing SHA-256. This keeps memory
# bounded even for multi-GB files.
HASH_CHUNK = 1024 * 1024  # 1 MiB


# ---------------------------------------------------------------------------


@dataclass
class BackupProgress:
    files_total: int = 0         # best-effort estimate after the initial walk
    files_done: int = 0
    bytes_total: int = 0
    bytes_done: int = 0
    current_file: str = ""
    new_objects: int = 0         # objects actually written (not deduped)
    reused_objects: int = 0
    message: str = ""

    def percent(self) -> float:
        if self.bytes_total == 0:
            return 0.0
        return 100.0 * self.bytes_done / self.bytes_total


ProgressCb = Callable[[BackupProgress], None]
CancelCb = Callable[[], bool]


# ---------------------------------------------------------------------------


def _sha256_file(path: str) -> str:
    """Compute the SHA-256 hash of a file, reading in chunks.

    Reading in 1 MiB chunks keeps memory use low even for huge files.
    The hex digest is used both as the file's unique ID in the object
    store AND to detect whether two files have identical content (dedup).
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _iter_files(source_root: Path, ignore_hidden: bool = False) -> Iterable[tuple[str, str, int, float]]:
    """Yield (absolute_path, relative_path_posix, size, mtime) for every file."""
    source_root = source_root.resolve()
    for dirpath, dirnames, filenames in os.walk(source_root, followlinks=False):
        if ignore_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if ignore_hidden and fn.startswith("."):
                continue
            abs_p = os.path.join(dirpath, fn)
            try:
                st = os.stat(abs_p)
            except OSError as e:
                log.warning("Skipping %s: %s", abs_p, e)
                continue
            if not os.path.isfile(abs_p):
                continue
            rel = os.path.relpath(abs_p, source_root).replace(os.sep, "/")
            yield abs_p, rel, st.st_size, st.st_mtime


def _new_snapshot_id() -> str:
    # Include milliseconds so two backups in the same second don't collide.
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H-%M-%S") + f"-{now.microsecond // 1000:03d}"


# ---------------------------------------------------------------------------


@dataclass
class BackupResult:
    snapshot_id: str
    kind: str
    files: int
    bytes: int
    new_objects: int
    reused_objects: int
    duration_seconds: float
    errors: list[str] = field(default_factory=list)


class BackupEngine:
    """Runs backups against a `Repository`.

    The engine walks a source directory, hashes each file, encrypts
    new/changed files, and saves a snapshot manifest listing every file.
    Unchanged files (same path + size + mtime) reuse the existing hash
    without re-reading the file, making incremental backups fast.
    """

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def backup(
        self,
        source: str | Path,
        kind: str = "incremental",
        progress_cb: ProgressCb | None = None,
        cancel_cb: CancelCb | None = None,
        ignore_hidden: bool = False,
    ) -> BackupResult:
        """Run a backup. `kind` is "full" or "incremental"."""
        if kind not in ("full", "incremental"):
            raise ValueError(f"Bad kind: {kind}")

        source_path = Path(source).resolve()
        if not source_path.exists():
            raise FileNotFoundError(f"Source not found: {source_path}")
        if not source_path.is_dir():
            raise NotADirectoryError(f"Source is not a directory: {source_path}")

        prev_entries: dict[str, FileEntry] = {}
        if kind == "incremental":
            prev = self.repo.latest_snapshot()
            if prev is None:
                log.info("No prior snapshots — first run will be a full backup.")
                kind = "full"
            else:
                prev_entries = prev.by_path()

        progress = BackupProgress(message=f"Scanning {source_path}…")
        if progress_cb:
            progress_cb(progress)

        # First pass: enumerate files so we can report a total.
        file_list = list(_iter_files(source_path, ignore_hidden=ignore_hidden))
        progress.files_total = len(file_list)
        progress.bytes_total = sum(sz for _, _, sz, _ in file_list)
        progress.message = f"Backing up {len(file_list)} files…"
        if progress_cb:
            progress_cb(progress)

        snap = Snapshot(
            snapshot_id=_new_snapshot_id(),
            created_at=time.time(),
            source_root=str(source_path),
            kind=kind,
        )
        errors: list[str] = []
        start = time.monotonic()

        for abs_p, rel, size, mtime in file_list:
            if cancel_cb and cancel_cb():
                progress.message = "Cancelled."
                if progress_cb:
                    progress_cb(progress)
                raise RuntimeError("Backup cancelled by user.")

            progress.current_file = rel

            # Incremental check: a file is unchanged if its path, size, and
            # modification time all match the previous snapshot — the same
            # heuristic rsync uses. When unchanged we reuse the old hash
            # without re-reading the file, which makes incremental backups
            # of large trees very fast.
            prev = prev_entries.get(rel)
            unchanged = (
                prev is not None
                and prev.size == size
                and abs(prev.mtime - mtime) < 1e-6
            )

            try:
                if unchanged:
                    sha = prev.sha256
                    # Sanity: the object had better still exist.
                    if not self.repo.has_object(sha):
                        log.warning("Object %s missing — re-hashing %s", sha[:8], rel)
                        sha = _sha256_file(abs_p)
                        written = self.repo.put_object_from_file(abs_p, sha)
                    else:
                        written = False
                else:
                    sha = _sha256_file(abs_p)
                    written = self.repo.put_object_from_file(abs_p, sha)

                if written:
                    progress.new_objects += 1
                else:
                    progress.reused_objects += 1

                snap.entries.append(FileEntry(path=rel, size=size, mtime=mtime, sha256=sha))
            except Exception as e:
                msg = f"{rel}: {e}"
                log.error("Failed to back up %s", msg)
                errors.append(msg)

            progress.files_done += 1
            progress.bytes_done += size
            if progress_cb:
                progress_cb(progress)

        self.repo.save_snapshot(snap)

        duration = time.monotonic() - start
        progress.message = (
            f"Done: {progress.files_done} files, "
            f"{progress.new_objects} new / {progress.reused_objects} reused, "
            f"in {duration:.1f}s"
        )
        if progress_cb:
            progress_cb(progress)

        return BackupResult(
            snapshot_id=snap.snapshot_id,
            kind=kind,
            files=len(snap.entries),
            bytes=snap.total_size(),
            new_objects=progress.new_objects,
            reused_objects=progress.reused_objects,
            duration_seconds=duration,
            errors=errors,
        )
