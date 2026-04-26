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


