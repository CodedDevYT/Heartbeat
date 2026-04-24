"""Thin wrapper around the OS keychain via the `keyring` library.

We store per-job passwords under service name "Heartbeat" and username
"job:<job_name>". If `keyring` isn't installed or no backend is available
(e.g. headless Linux with no Secret Service), every operation degrades to a
safe no-op and `is_available()` returns False — the UI uses this to hide the
"save password" option and force the user to type their password each run.
"""

from __future__ import annotations

from .logger import get_logger

log = get_logger(__name__)

SERVICE_NAME = "Heartbeat"


def _keyring():
    try:
        import keyring
        import keyring.errors  # noqa: F401
        return keyring
    except Exception:
        return None


def _username(job_name: str) -> str:
    return f"job:{job_name}"


def is_available() -> bool:
    """True if the OS keychain backend is usable for storing secrets."""
    kr = _keyring()
    if kr is None:
        return False
    try:
        backend = kr.get_keyring()
    except Exception:
        return False
    # The `fail` and `null` backends both advertise themselves via their
    # module path — treat them as unavailable so we don't pretend to save.
    module = getattr(backend, "__module__", "") or ""
    name = type(backend).__name__.lower()
    if "fail" in module or "null" in module or "fail" in name:
        return False
    return True


def set_password(job_name: str, password: str) -> bool:
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.set_password(SERVICE_NAME, _username(job_name), password)
        return True
    except Exception as e:
        log.warning("Could not store password for job %s: %s", job_name, e)
        return False


def get_password(job_name: str) -> str | None:
    kr = _keyring()
    if kr is None:
        return None
    try:
        return kr.get_password(SERVICE_NAME, _username(job_name))
    except Exception as e:
        log.warning("Could not fetch password for job %s: %s", job_name, e)
        return None


def delete_password(job_name: str) -> None:
    kr = _keyring()
    if kr is None:
        return
    try:
        kr.delete_password(SERVICE_NAME, _username(job_name))
    except Exception:
        # Typically raised when no entry exists — safe to ignore.
        pass
