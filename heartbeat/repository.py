"""On-disk repository layout.

A repository is a directory that Heartbeat owns entirely. Layout:

    <repo>/
        repo.json                # metadata + KDF params + verifier (unencrypted container,
                                 # but the verifier inside is encrypted so the password can
                                 # be checked without storing it)
        objects/
            ab/
                cdef...          # encrypted file contents, named by sha256 of PLAINTEXT
        snapshots/
            2026-04-22T12-00-00.snap   # encrypted Snapshot manifest

Objects are content-addressed on the *plaintext* hash, which means:
    - if two files are identical, they're stored once → free dedup
    - an incremental backup that adds one file only writes one object
    - if an object already exists we can skip re-encrypting entirely
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from . import crypto
from .logger import get_logger
from .manifest import Snapshot

log = get_logger(__name__)

# ── Repository layout constants ────────────────────────────────────────────
# These names are committed to on disk; changing them would break existing repos.

REPO_VERSION = 1              # Bump when the on-disk format changes
REPO_METADATA_FILE = "repo.json"   # Stores KDF salt, iterations, and verifier
OBJECTS_DIR = "objects"        # Content-addressed encrypted file blobs
SNAPSHOTS_DIR = "snapshots"    # Encrypted snapshot manifests


class RepositoryError(Exception):
    pass


@dataclass
class RepoMetadata:
    version: int
    kdf: crypto.KdfParams
    verifier_hex: str  # encrypted known plaintext

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "kdf": self.kdf.to_dict(),
            "verifier_hex": self.verifier_hex,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RepoMetadata":
        return cls(
            version=int(d["version"]),
            kdf=crypto.KdfParams.from_dict(d["kdf"]),
            verifier_hex=d["verifier_hex"],
        )


class Repository:
    """Encrypted backup repository.

    Open in one of two ways:
        Repository.initialize(path, password)   # create a new repo
        Repository.open(path, password)         # open an existing repo
    """

    def __init__(self, root: Path, meta: RepoMetadata, key: bytes) -> None:
        self.root = Path(root)
        self.meta = meta
        self._key = key

    # --- lifecycle ---------------------------------------------------------

    @classmethod
    def initialize(cls, root: Path | str, password: str) -> "Repository":
        """Create a brand-new repository (vault) on disk.

        Steps:
          1. Create the directory structure (objects/ + snapshots/).
          2. Generate a fresh random salt for key derivation.
          3. Derive the encryption key from the password.
          4. Encrypt a known plaintext as a "verifier" — this is how
             we check the password on future opens without storing it.
          5. Write repo.json with the salt + verifier (NOT the password).
        """
        root = Path(root)
        if root.exists() and any(root.iterdir()):
            raise RepositoryError(f"Cannot initialize: {root} is not empty.")
        root.mkdir(parents=True, exist_ok=True)
        (root / OBJECTS_DIR).mkdir(exist_ok=True)
        (root / SNAPSHOTS_DIR).mkdir(exist_ok=True)

        kdf = crypto.KdfParams.new()          # random salt
        key = crypto.derive_key(password, kdf) # slow on purpose (PBKDF2)
        verifier = crypto.make_verifier(key)   # encrypted known plaintext
        meta = RepoMetadata(version=REPO_VERSION, kdf=kdf, verifier_hex=verifier.hex())

        (root / REPO_METADATA_FILE).write_text(
            json.dumps(meta.to_dict(), indent=2), encoding="utf-8"
        )
        log.info("Initialized repository at %s", root)
        return cls(root, meta, key)

    @classmethod
    def open(cls, root: Path | str, password: str) -> "Repository":
        """Open an existing repository by re-deriving the key from the
        password and verifying it against the stored verifier.

        If the password is wrong, check_verifier() will fail (the GCM
        tag won't match) and we raise RepositoryError instead of
        returning a repo with a bad key that would corrupt data.
        """
        root = Path(root)
        meta_path = root / REPO_METADATA_FILE
        if not meta_path.exists():
            raise RepositoryError(f"No repository at {root}")
        meta = RepoMetadata.from_dict(json.loads(meta_path.read_text(encoding="utf-8")))
        if meta.version != REPO_VERSION:
            raise RepositoryError(f"Unsupported repo version: {meta.version}")
        key = crypto.derive_key(password, meta.kdf)
        if not crypto.check_verifier(key, bytes.fromhex(meta.verifier_hex)):
            raise RepositoryError("Invalid password.")
        log.info("Opened repository at %s", root)
        return cls(root, meta, key)

    # --- object store ------------------------------------------------------

    def _object_path(self, sha256_hex: str) -> Path:
        """Map a hex hash to a file path under ``objects/``.

        We split the hash into a 2-char prefix directory + the rest,
        exactly like Git does (``objects/ab/cdef…``).  This avoids putting
        thousands of files in a single directory, which would slow down
        file-system lookups on older filesystems.
        """
        return self.root / OBJECTS_DIR / sha256_hex[:2] / sha256_hex[2:]

    def has_object(self, sha256_hex: str) -> bool:
        return self._object_path(sha256_hex).exists()

    def put_object_from_file(self, src_path: Path | str, sha256_hex: str) -> bool:
        """Encrypt `src_path` and store it under `sha256_hex`.

        Returns True if written, False if object already existed (dedup).

        Uses a write-to-tmp-then-rename pattern: the encrypted data is
        first written to a .tmp file, then atomically renamed into place
        with os.replace(). This prevents a half-written file from
        corrupting the repo if the app crashes mid-write.
        """
        dest = self._object_path(sha256_hex)
        if dest.exists():
            return False          # dedup — already have this content
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".tmp")
        try:
            crypto.encrypt_stream(self._key, src_path, tmp)
            os.replace(tmp, dest)  # atomic rename
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
        return True

    def get_object_to_file(self, sha256_hex: str, dest_path: Path | str) -> None:
        src = self._object_path(sha256_hex)
        if not src.exists():
            raise RepositoryError(f"Missing object {sha256_hex}")
        Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
        crypto.decrypt_stream(self._key, src, dest_path)

    # --- snapshots ---------------------------------------------------------

    def _snapshot_path(self, snapshot_id: str) -> Path:
        return self.root / SNAPSHOTS_DIR / f"{snapshot_id}.snap"

    def save_snapshot(self, snap: Snapshot) -> Path:
        path = self._snapshot_path(snap.snapshot_id)
        blob = crypto.encrypt_bytes(self._key, snap.to_json())
        path.write_bytes(blob)
        log.info("Saved snapshot %s (%d files)", snap.snapshot_id, len(snap.entries))
        return path

    def load_snapshot(self, snapshot_id: str) -> Snapshot:
        path = self._snapshot_path(snapshot_id)
        if not path.exists():
            raise RepositoryError(f"No snapshot: {snapshot_id}")
        data = crypto.decrypt_bytes(self._key, path.read_bytes())
        return Snapshot.from_json(data)

    def list_snapshots(self) -> list[str]:
        d = self.root / SNAPSHOTS_DIR
        if not d.exists():
            return []
        return sorted(p.stem for p in d.glob("*.snap"))

    def iter_snapshots(self) -> Iterator[Snapshot]:
        for sid in self.list_snapshots():
            yield self.load_snapshot(sid)

    def latest_snapshot(self) -> Snapshot | None:
        ids = self.list_snapshots()
        return self.load_snapshot(ids[-1]) if ids else None

    # --- misc --------------------------------------------------------------

    def disk_usage(self) -> int:
        total = 0
        for dirpath, _, filenames in os.walk(self.root):
            for f in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, f))
                except OSError:
                    pass
        return total

    def destroy(self) -> None:
        """Delete the repository. Irreversible."""
        shutil.rmtree(self.root)
