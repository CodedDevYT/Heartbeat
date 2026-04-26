"""Single-file encrypted vault backed by SQLite.

A vault is a single ``.hbv`` file (an SQLite database) containing three
tables:

    meta       — key-value pairs: KDF salt, iteration count, password verifier
    objects    — content-addressed encrypted file blobs, keyed by SHA-256
    snapshots  — encrypted snapshot manifests, keyed by timestamp ID

Using SQLite gives us:
    - A single file on disk that's easy to browse for and move around.
    - Atomic writes (WAL journal mode) so a crash can't corrupt the vault.
    - Efficient random access to individual objects without extracting the
      whole archive.

Objects are content-addressed on the *plaintext* hash, which means:
    - Identical files are stored once (free dedup).
    - An incremental backup that adds one file writes one new object.
    - If an object already exists we skip re-encrypting entirely.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from . import crypto
from .logger import get_logger
from .manifest import Snapshot

log = get_logger(__name__)

REPO_VERSION = 2
VAULT_EXTENSION = ".hbv"

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS objects (sha256 TEXT PRIMARY KEY, data BLOB);
CREATE TABLE IF NOT EXISTS snapshots (snapshot_id TEXT PRIMARY KEY, data BLOB);
"""


class RepositoryError(Exception):
    pass


@dataclass
class RepoMetadata:
    version: int
    kdf: crypto.KdfParams
    verifier_hex: str

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
    """Encrypted backup vault stored as a single .hbv file.

    Open in one of two ways:
        Repository.initialize(path, password)   # create a new vault
        Repository.open(path, password)          # open an existing vault
    """

    def __init__(self, path: Path, meta: RepoMetadata, key: bytes,
                 conn: sqlite3.Connection) -> None:
        self.path = Path(path)
        self.meta = meta
        self._key = key
        self._conn = conn

    # --- lifecycle ---------------------------------------------------------

    @classmethod
    def _ensure_extension(cls, path: Path) -> Path:
        if path.suffix.lower() != VAULT_EXTENSION:
            path = path.with_suffix(VAULT_EXTENSION)
        return path

    @classmethod
    def initialize(cls, path: Path | str, password: str) -> "Repository":
        """Create a brand-new vault file.

        Generates a random salt, derives the encryption key, encrypts a
        known plaintext as a verifier (so we can check the password on
        future opens without storing it), and writes everything into a
        fresh SQLite database.
        """
        path = cls._ensure_extension(Path(path))
        if path.exists():
            raise RepositoryError(f"Cannot create vault: {path} already exists.")

        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)

        kdf = crypto.KdfParams.new()
        key = crypto.derive_key(password, kdf)
        verifier = crypto.make_verifier(key)
        meta = RepoMetadata(version=REPO_VERSION, kdf=kdf,
                            verifier_hex=verifier.hex())

        conn.execute("INSERT INTO meta VALUES (?, ?)",
                     ("repo", json.dumps(meta.to_dict())))
        conn.commit()
        log.info("Created vault at %s", path)
        return cls(path, meta, key, conn)

    @classmethod
    def open(cls, path: Path | str, password: str) -> "Repository":
        """Open an existing vault by re-deriving the key and verifying it
        against the stored verifier."""
        path = Path(path)
        if not path.exists():
            raise RepositoryError(f"No vault at {path}")

        try:
            conn = sqlite3.connect(str(path), check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'repo'"
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise RepositoryError(f"Not a valid vault file: {path}") from exc

        if not row:
            conn.close()
            raise RepositoryError(f"Not a valid vault file: {path}")

        meta = RepoMetadata.from_dict(json.loads(row[0]))
        key = crypto.derive_key(password, meta.kdf)
        if not crypto.check_verifier(key, bytes.fromhex(meta.verifier_hex)):
            conn.close()
            raise RepositoryError("Invalid password.")
        log.info("Opened vault at %s", path)
        return cls(path, meta, key, conn)

    @classmethod
    def is_vault(cls, path: Path | str) -> bool:
        """Quick check whether a file looks like a Heartbeat vault."""
        path = Path(path)
        if not path.is_file():
            return False
        try:
            conn = sqlite3.connect(str(path))
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'repo'"
            ).fetchone()
            conn.close()
            return row is not None
        except Exception:
            return False

    # --- object store ------------------------------------------------------

    def has_object(self, sha256_hex: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM objects WHERE sha256 = ?", (sha256_hex,)
        ).fetchone()
        return row is not None

    def put_object_from_file(self, src_path: Path | str, sha256_hex: str) -> bool:
        """Encrypt a file and store it. Returns True if written, False if
        the object already existed (dedup)."""
        if self.has_object(sha256_hex):
            return False
        with open(str(src_path), "rb") as f:
            plaintext = f.read()
        encrypted = crypto.encrypt_bytes(self._key, plaintext)
        self._conn.execute(
            "INSERT INTO objects (sha256, data) VALUES (?, ?)",
            (sha256_hex, encrypted),
        )
        self._conn.commit()
        return True

    def get_object_to_file(self, sha256_hex: str, dest_path: Path | str) -> None:
        """Decrypt an object and write it to a file on disk."""
        row = self._conn.execute(
            "SELECT data FROM objects WHERE sha256 = ?", (sha256_hex,)
        ).fetchone()
        if not row:
            raise RepositoryError(f"Missing object {sha256_hex}")
        plaintext = crypto.decrypt_bytes(self._key, row[0])
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(plaintext)

    # --- snapshots ---------------------------------------------------------

    def save_snapshot(self, snap: Snapshot) -> None:
        data = crypto.encrypt_bytes(self._key, snap.to_json())
        self._conn.execute(
            "INSERT OR REPLACE INTO snapshots (snapshot_id, data) VALUES (?, ?)",
            (snap.snapshot_id, data),
        )
        self._conn.commit()
        log.info("Saved snapshot %s (%d files)", snap.snapshot_id,
                 len(snap.entries))

    def load_snapshot(self, snapshot_id: str) -> Snapshot:
        row = self._conn.execute(
            "SELECT data FROM snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        if not row:
            raise RepositoryError(f"No snapshot: {snapshot_id}")
        data = crypto.decrypt_bytes(self._key, row[0])
        return Snapshot.from_json(data)

    def list_snapshots(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT snapshot_id FROM snapshots ORDER BY snapshot_id"
        ).fetchall()
        return [r[0] for r in rows]

    def latest_snapshot(self) -> Snapshot | None:
        ids = self.list_snapshots()
        return self.load_snapshot(ids[-1]) if ids else None

    # --- misc --------------------------------------------------------------

    def disk_usage(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def destroy(self) -> None:
        """Delete the vault file. Irreversible."""
        self.close()
        self.path.unlink(missing_ok=True)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
