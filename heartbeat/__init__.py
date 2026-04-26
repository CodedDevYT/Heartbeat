"""Heartbeat — an encrypted desktop backup tool.

This package provides everything needed to back up folders, external drives,
and network shares into password-protected, versioned vaults:

    crypto          AES-256-GCM encryption + PBKDF2 key derivation
    manifest        Snapshot / FileEntry data structures (JSON-serializable)
    repository      Single-file encrypted vault (SQLite-backed .hbv)
    backup_engine   Full + incremental backup logic
    restore_engine  File-level and full restore
    config          Persisted job configuration (~/.heartbeat/config.json)
    schedule        Schedule model (manual, interval, daily, weekly)
    scheduler       Background daemon thread that fires due jobs
    secret_store    OS keychain wrapper (macOS Keychain / Windows Credential
                    Manager / Linux Secret Service)
    logger          Centralized logging with an in-memory buffer for the UI
    cli             Command-line interface (fallback when PySide6 isn't installed)
    ui/             PySide6 graphical interface

The entry point is ``main.py`` at the project root.
"""

__version__ = "0.1.0"
