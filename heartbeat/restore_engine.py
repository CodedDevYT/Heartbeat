"""Restore engine.

Restore from a specific snapshot, either:
    - the whole snapshot (full restore), or
    - a single file / subset matched by relative path prefix.

Original file mtimes are preserved so incremental comparisons keep working
after a restore.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .logger import get_logger
from .manifest import FileEntry, Snapshot
from .repository import Repository

log = get_logger(__name__)


@dataclass
class RestoreProgress:
    files_total: int = 0
    files_done: int = 0
    bytes_total: int = 0
    bytes_done: int = 0
    current_file: str = ""
    message: str = ""

    def percent(self) -> float:
        if self.bytes_total == 0:
            return 0.0
        return 100.0 * self.bytes_done / self.bytes_total


ProgressCb = Callable[[RestoreProgress], None]
CancelCb = Callable[[], bool]


@dataclass
class RestoreResult:
    snapshot_id: str
    files: int
    bytes: int
    duration_seconds: float
    errors: list[str] = field(default_factory=list)


class RestoreEngine:
    """Restores files from a snapshot back to disk.

    For each file entry in the snapshot, the engine looks up the
    encrypted object by its SHA-256 hash, decrypts it, and writes
    the plaintext to the destination directory. Original modification
    times are preserved so future incremental backups still work.
    """

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def list_files(self, snapshot_id: str) -> list[FileEntry]:
        return list(self.repo.load_snapshot(snapshot_id).entries)

    def restore(
        self,
        snapshot_id: str,
        dest: str | Path,
        path_prefix: str | None = None,
        paths: list[str] | None = None,
        overwrite: bool = False,
        progress_cb: ProgressCb | None = None,
        cancel_cb: CancelCb | None = None,
    ) -> RestoreResult:
        """Restore files from a snapshot into `dest`.

        Filtering (applied in order):
            - `paths` restricts to this exact list of relative paths.
            - `path_prefix` restricts to entries whose path starts with it.
            - If both are None, every file in the snapshot is restored.
        """
        snap: Snapshot = self.repo.load_snapshot(snapshot_id)
        dest_root = Path(dest).resolve()
        dest_root.mkdir(parents=True, exist_ok=True)

        entries = snap.entries
        if paths is not None:
            wanted = {p.replace(os.sep, "/").lstrip("/") for p in paths}
            entries = [e for e in entries if e.path in wanted]
        if path_prefix:
            prefix = path_prefix.replace(os.sep, "/").lstrip("/")
            entries = [e for e in entries if e.path == prefix or e.path.startswith(prefix + "/")]

        progress = RestoreProgress(
            files_total=len(entries),
            bytes_total=sum(e.size for e in entries),
            message=f"Restoring {len(entries)} files…",
        )
        if progress_cb:
            progress_cb(progress)

        errors: list[str] = []
        start = time.monotonic()

        for entry in entries:
            if cancel_cb and cancel_cb():
                progress.message = "Cancelled."
                if progress_cb:
                    progress_cb(progress)
                raise RuntimeError("Restore cancelled by user.")

            progress.current_file = entry.path
            target = dest_root / entry.path

            # Security: prevent path-traversal attacks. A crafted manifest
            # could contain "../../etc/passwd" to escape the destination
            # directory. We resolve symlinks and verify the target stays
            # inside dest_root before writing anything.
            try:
                target.resolve().relative_to(dest_root)
            except ValueError:
                errors.append(f"{entry.path}: path escapes destination; skipped")
                continue

            if target.exists() and not overwrite:
                errors.append(f"{entry.path}: already exists (overwrite disabled)")
                progress.files_done += 1
                progress.bytes_done += entry.size
                if progress_cb:
                    progress_cb(progress)
                continue

            try:
                self.repo.get_object_to_file(entry.sha256, target)
                # Preserve mtime so future incrementals recognize the file as unchanged.
                os.utime(target, (entry.mtime, entry.mtime))
            except Exception as e:
                log.error("Failed to restore %s: %s", entry.path, e)
                errors.append(f"{entry.path}: {e}")

            progress.files_done += 1
            progress.bytes_done += entry.size
            if progress_cb:
                progress_cb(progress)

        duration = time.monotonic() - start
        progress.message = f"Restored {progress.files_done} files in {duration:.1f}s"
        if progress_cb:
            progress_cb(progress)

        return RestoreResult(
            snapshot_id=snapshot_id,
            files=progress.files_done,
            bytes=progress.bytes_done,
            duration_seconds=duration,
            errors=errors,
        )
