"""Password-based file encryption using AES-256-GCM.

Design:
    - Key derivation: PBKDF2-HMAC-SHA256 with a per-repository salt and a high
      iteration count. The derived key is 32 bytes (AES-256).
    - Encryption: AES-GCM with a fresh random 12-byte nonce per blob. GCM gives
      us authenticated encryption, so tampering is detected on decrypt.
    - On-disk blob layout:   [1 byte version] [12 byte nonce] [ciphertext+tag]

We intentionally do NOT store the password or the derived key. To verify a
password, we encrypt a fixed known plaintext at repo-init time and check that
it decrypts correctly on unlock.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Constants ──────────────────────────────────────────────────────────────
# These constants define the encryption scheme. Changing them would break
# backward-compatibility with existing repos, so they're effectively frozen.

BLOB_VERSION = 1        # Format version byte stored at the start of every blob
NONCE_LEN = 12          # 96-bit nonce (recommended by NIST for AES-GCM)
KEY_LEN = 32            # 256-bit key → AES-256
SALT_LEN = 16           # 128-bit random salt (one per repository)
DEFAULT_ITERATIONS = 300_000  # OWASP 2023 guidance for PBKDF2-SHA256

# A well-known string that is encrypted with the derived key at repo
# creation time. On subsequent opens we decrypt it and compare — this
# lets us reject wrong passwords without storing the password itself.
_VERIFIER_PLAINTEXT = b"heartbeat-password-check-v1"


class CryptoError(Exception):
    """Raised on any encryption/decryption/key-derivation failure."""


@dataclass(frozen=True)
class KdfParams:
    """Parameters needed to re-derive the same key from a password."""

    salt: bytes
    iterations: int = DEFAULT_ITERATIONS

    def to_dict(self) -> dict:
        return {"salt_hex": self.salt.hex(), "iterations": self.iterations}

    @classmethod
    def from_dict(cls, d: dict) -> "KdfParams":
        return cls(salt=bytes.fromhex(d["salt_hex"]), iterations=int(d["iterations"]))

    @classmethod
    def new(cls) -> "KdfParams":
        return cls(salt=secrets.token_bytes(SALT_LEN))


def derive_key(password: str, params: KdfParams) -> bytes:
    """Derive a 32-byte key from a password using PBKDF2-HMAC-SHA256.

    PBKDF2 deliberately runs SHA-256 hundreds of thousands of times to
    make brute-force attacks impractical. The random salt prevents
    pre-computed rainbow tables from working.
    """
    if not password:
        raise CryptoError("Password must not be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=params.salt,
        iterations=params.iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """Encrypt a bytes blob with AES-256-GCM.

    Returns a self-contained blob:  [1 B version][12 B nonce][ciphertext + 16 B GCM tag]

    AES-GCM is "authenticated encryption" — it both encrypts the data
    AND produces a 16-byte authentication tag. If anyone tampers with the
    ciphertext, decryption will fail rather than silently return garbage.

    A fresh random nonce is generated every time, so encrypting the same
    plaintext twice produces different ciphertexts (important for security).
    """
    if len(key) != KEY_LEN:
        raise CryptoError("Invalid key length.")
    nonce = os.urandom(NONCE_LEN)        # fresh nonce for every encryption
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return bytes([BLOB_VERSION]) + nonce + ct


def decrypt_bytes(key: bytes, blob: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt a blob produced by ``encrypt_bytes``.

    If the key is wrong or the data has been tampered with, GCM's
    authentication tag will fail and we raise ``CryptoError``.
    """
    if len(blob) < 1 + NONCE_LEN + 16:
        raise CryptoError("Ciphertext is too short.")
    version = blob[0]
    if version != BLOB_VERSION:
        raise CryptoError(f"Unsupported blob version: {version}")
    nonce = blob[1 : 1 + NONCE_LEN]     # extract the nonce
    ct = blob[1 + NONCE_LEN :]           # everything after the nonce is ciphertext+tag
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, associated_data)
    except Exception as e:  # InvalidTag, etc.
        raise CryptoError("Decryption failed (wrong password or corrupted data).") from e


def make_verifier(key: bytes) -> bytes:
    """Create a verifier blob used to check a password at unlock time."""
    return encrypt_bytes(key, _VERIFIER_PLAINTEXT)


def check_verifier(key: bytes, verifier: bytes) -> bool:
    """Try to decrypt the stored verifier with the given key.

    If the password is correct, the decrypted text will match
    _VERIFIER_PLAINTEXT. If not, the GCM tag check fails and
    we know the password is wrong — without ever storing it.
    """
    try:
        return decrypt_bytes(key, verifier) == _VERIFIER_PLAINTEXT
    except CryptoError:
        return False


def encrypt_stream(key: bytes, src_path, dest_path, chunk_size: int = 4 * 1024 * 1024) -> int:
    """Encrypt a file on disk. Returns the number of plaintext bytes read.

    Two on-disk formats, chosen automatically by file size:

    Small files (≤ chunk_size, default 4 MiB):
        [b"S"][encrypt_bytes blob]
        The whole file is one GCM blob in memory. Fast and simple.

    Large files (> chunk_size):
        [b"C"][4-byte chunk len][blob][4-byte chunk len][blob]…
        Each chunk is its own GCM blob so memory stays bounded even for
        multi-GB backups.
    """
    src_path = str(src_path)
    dest_path = str(dest_path)
    size = os.path.getsize(src_path)

    # Fast path: small files — single blob.
    if size <= chunk_size:
        with open(src_path, "rb") as f:
            data = f.read()
        blob = encrypt_bytes(key, data)
        with open(dest_path, "wb") as f:
            f.write(b"S")  # single-blob marker
            f.write(blob)
        return size

    # Chunked path for large files.
    total = 0
    with open(src_path, "rb") as src, open(dest_path, "wb") as dst:
        dst.write(b"C")  # chunked marker
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            blob = encrypt_bytes(key, chunk)
            dst.write(len(blob).to_bytes(4, "big"))
            dst.write(blob)
            total += len(chunk)
    return total


def decrypt_stream(key: bytes, src_path, dest_path) -> int:
    """Inverse of `encrypt_stream`. Returns plaintext bytes written."""
    src_path = str(src_path)
    dest_path = str(dest_path)
    total = 0
    with open(src_path, "rb") as src, open(dest_path, "wb") as dst:
        marker = src.read(1)
        if marker == b"S":
            data = decrypt_bytes(key, src.read())
            dst.write(data)
            total = len(data)
        elif marker == b"C":
            while True:
                header = src.read(4)
                if not header:
                    break
                n = int.from_bytes(header, "big")
                blob = src.read(n)
                if len(blob) != n:
                    raise CryptoError("Truncated encrypted chunk.")
                chunk = decrypt_bytes(key, blob)
                dst.write(chunk)
                total += len(chunk)
        else:
            raise CryptoError("Unknown encrypted file format.")
    return total
