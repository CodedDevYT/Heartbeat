# Heartbeat

An encrypted desktop backup tool built with Python and PySide6.

Heartbeat backs up folders, external drives, and network shares into
**password-protected vaults** with full version history. It supports
incremental and full backups, file-level restore, flexible scheduling,
and optional OS-keychain password storage for unattended runs.

---

## Features

| Feature | Details |
|---------|---------|
| **Encryption** | AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation (300 000 iterations) |
| **Deduplication** | Content-addressed object store — identical files are stored once |
| **Incremental backups** | Only changed files are re-encrypted (path + size + mtime heuristic) |
| **Version history** | Every backup creates a new snapshot; older versions are preserved |
| **File-level restore** | Restore an entire snapshot or pick individual files |
| **Scheduling** | Manual, every N min/hr/day, daily at HH:MM, or weekly on picked days |
| **Password storage** | Optionally save vault passwords in the OS keychain for unattended runs |
| **Large-file support** | Files over 4 MiB are encrypted in chunks to keep memory bounded |
| **Network drives** | Transparent support for SMB shares and mounted external drives |
| **Dual interface** | Full PySide6 GUI, plus a CLI fallback for headless / scripted use |

---

## Requirements

- **Python 3.10+** (uses modern type hints: `X | Y`, `list[T]`)
- Dependencies listed in `requirements.txt`:
  - `PySide6 >= 6.6` — Qt-based GUI toolkit
  - `cryptography >= 42.0` — AES-GCM encryption and PBKDF2
  - `keyring >= 24` — OS keychain integration (macOS Keychain, Windows
    Credential Manager, Linux Secret Service)

---

## Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd Heartbeat

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Graphical UI (default)

```bash
python main.py
```

The app opens with a dashboard showing quick-start cards. The four tabs
are **Home**, **Backup**, **Restore**, and **Jobs**.

### Command-line interface

```bash
python main.py --cli init      /path/to/vault
python main.py --cli backup    /path/to/vault /path/to/source
python main.py --cli backup    /path/to/vault /path/to/source --full
python main.py --cli snapshots /path/to/vault
python main.py --cli list      /path/to/vault <snapshot-id>
python main.py --cli restore   /path/to/vault <snapshot-id> /path/to/dest --overwrite
```

Passwords are prompted with `getpass` so they never appear in shell history.

### Network drives / external drives

Pass their mounted path — Heartbeat doesn't need any special code:

- macOS: `/Volumes/BackupDrive`
- Windows: `\\server\share` or `E:\`
- Linux: `/mnt/backup`

---

## Project structure

```
Heartbeat/
├── main.py                     # Entry point (GUI or --cli)
├── requirements.txt            # Python dependencies
├── LICENSE                     # MIT license
│
└── heartbeat/                  # Main package
    ├── __init__.py             # Package docstring + version
    ├── crypto.py               # AES-256-GCM encryption + PBKDF2 key derivation
    ├── manifest.py             # Snapshot + FileEntry data structures
    ├── repository.py           # Content-addressed object store on disk
    ├── backup_engine.py        # Full + incremental backup logic
    ├── restore_engine.py       # File-level + full restore
    ├── config.py               # Job configuration (persisted to ~/.heartbeat/)
    ├── schedule.py             # Schedule model (manual, interval, daily, weekly)
    ├── scheduler.py            # Background thread that fires due jobs
    ├── secret_store.py         # OS keychain wrapper (keyring library)
    ├── logger.py               # Centralized logging + in-memory buffer for UI
    ├── cli.py                  # Command-line interface
    │
    └── ui/                     # PySide6 graphical interface
        ├── __init__.py
        ├── main_window.py      # MainWindow + all tabs + dialogs + stylesheet
        ├── utils.py            # Text formatting helpers + programmatic app icon
        └── workers.py          # QThread workers for backup / restore
```

---

## How it works

### Encryption

- **Algorithm:** AES-256-GCM (authenticated encryption — tamper-detection is built in).
- **Key derivation:** PBKDF2-HMAC-SHA256 with 300 000 iterations and a 16-byte
  random salt per vault. The salt and iteration count are stored in `repo.json`;
  the password itself is **never** stored.
- **Password verification:** At vault creation a known plaintext is encrypted with
  the derived key and saved as a "verifier". On subsequent opens we decrypt the
  verifier and compare — if it doesn't match, the password is wrong.
- **Nonces:** Every encrypted blob gets a fresh random 12-byte nonce. This means
  encrypting the same file twice produces different ciphertext.
- **Large files:** Files over 4 MiB are encrypted in chunks (each chunk is its own
  GCM blob prefixed by a 4-byte length), keeping memory use bounded even for
  multi-GB backups.

### Content-addressed object store

Each file's SHA-256 hash (computed on the *plaintext*) serves as both its content
fingerprint and its filename in the `objects/` directory (split into a 2-char prefix
subdirectory, like Git: `objects/ab/cdef…`).

This gives us **free deduplication**: if two files in different snapshots — or even
different folders — have the same content, only one encrypted copy is stored.

### Incremental backups

A file is considered unchanged if its **path**, **size**, and **mtime** all match
the previous snapshot (the same heuristic `rsync` uses). Unchanged files reuse the
old snapshot's hash without re-reading the file, making incremental backups of large
directory trees very fast.

### Scheduling

Jobs can be scheduled in four modes:
- **Manual** — only runs when you click "Run Now"
- **Interval** — every N minutes / hours / days
- **Daily** — at a specific time (e.g. 09:00)
- **Weekly** — on selected weekdays at a specific time

The scheduler runs on a daemon thread inside the application. Scheduling logic lives
in the pure function `next_due()` in `schedule.py`, which takes the current time as
a parameter for easy unit testing.

### Password storage

Jobs can optionally save their vault password in the operating system's keychain:
- macOS: Keychain
- Windows: Credential Manager
- Linux: Secret Service (GNOME Keyring / KDE Wallet)

This is handled by the `keyring` library. If no usable keychain backend is available,
Heartbeat gracefully disables the option and always prompts for the password.

---

## Architecture highlights (for the presentation)

1. **Separation of concerns** — The backup/restore engines, encryption, and
   repository are pure Python with no UI dependency. The UI layer (`ui/`) is a
   thin presentation shell that delegates all work to those modules.

2. **Threading with Qt Signals** — Long operations run on `QThread` workers.
   Progress updates and completion are communicated back to the UI thread via
   Qt's `Signal`/`Slot` mechanism, keeping the interface responsive.

3. **Testability** — Core logic (encryption, scheduling, config migration) is
   exposed as pure functions that can be unit-tested without mocking the clock,
   the filesystem, or the UI.

4. **Atomic file writes** — Configuration and snapshot manifests are written to
   a `.tmp` file first, then atomically renamed into place with `os.replace()`.
   This prevents corruption if the app crashes mid-write.

5. **Security by design** — Passwords are never stored on disk (the keychain is
   OS-managed). Path-traversal attacks in manifests are blocked by validating
   that restore targets stay within the destination directory.

---

## Notes

- **Compression** is not applied. AES-GCM makes compression-after-encrypt
  pointless, and compress-before-encrypt can leak information in some threat
  models. We chose simplicity.
- **The scheduler** is an in-process timer. For production, you'd wire backups
  into `cron` / `launchd` / Windows Task Scheduler.
- **The app icon** is drawn programmatically with `QPainter` (a dark rounded
  square with a blue ECG line), so there's no separate image asset to ship.

---

## License

[MIT](LICENSE)
