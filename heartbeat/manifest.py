"""Snapshot manifest data structures.

A manifest lists every file in a single snapshot: its original path, its size,
its modification time, and the hash of its *plaintext* contents. The hash is
also the filename inside the repo's `objects/` directory (after encryption),
which gives us free deduplication across snapshots and across files.

Manifests are serialized as JSON and stored encrypted.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable


@dataclass
class FileEntry:
    """One file in a snapshot.

    The ``sha256`` field pulls double duty: it's the content hash *and*
    the filename inside the repository's ``objects/`` directory. Because
    it's computed on the *plaintext* (before encryption), two identical
    files share the same object on disk → free deduplication.
    """
    path: str           # relative path inside the source root, using forward slashes
    size: int           # plaintext size in bytes
    mtime: float        # modification time (unix seconds)
    sha256: str         # hex digest of the plaintext — also the object id

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FileEntry":
        return cls(path=d["path"], size=int(d["size"]),
                   mtime=float(d["mtime"]), sha256=d["sha256"])


@dataclass
class Snapshot:
    """A snapshot is a point-in-time listing of every file in the source.

    It is stored as encrypted JSON inside the repository's ``snapshots/``
    directory.  Each entry records the file's relative path, size, mtime,
    and content hash — everything needed to restore the file later.
    """
    snapshot_id: str                 # timestamp-based id (e.g. "2026-04-22T16-07-26-627")
    created_at: float                # unix seconds when the backup ran
    source_root: str                 # absolute source path at backup time
    kind: str                        # "full" or "incremental"
    entries: list[FileEntry] = field(default_factory=list)

    # --- serialization -----------------------------------------------------

    def to_json(self) -> bytes:
        payload = {
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at,
            "source_root": self.source_root,
            "kind": self.kind,
            "entries": [e.to_dict() for e in self.entries],
        }
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "Snapshot":
        d = json.loads(data.decode("utf-8"))
        return cls(
            snapshot_id=d["snapshot_id"],
            created_at=float(d["created_at"]),
            source_root=d["source_root"],
            kind=d["kind"],
            entries=[FileEntry.from_dict(e) for e in d["entries"]],
        )

    # --- helpers -----------------------------------------------------------

    def by_path(self) -> Dict[str, FileEntry]:
        return {e.path: e for e in self.entries}

    def total_size(self) -> int:
        return sum(e.size for e in self.entries)

    def extend(self, entries: Iterable[FileEntry]) -> None:
        self.entries.extend(entries)
