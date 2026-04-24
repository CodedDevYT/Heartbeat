# Heartbeat — An Encrypted Desktop Backup Tool

**Project Report**

**GitHub Repository:** https://github.com/CodedDevYT/Heartbeat

---

## 1. Introduction and Background

Data loss is one of the most common and costly problems faced by everyday computer users. Whether caused by hardware failure, accidental deletion, ransomware, or theft, the consequences range from lost personal photos to destroyed academic work. While cloud backup services exist, they raise privacy concerns: users must trust a third party with their unencrypted data. Commercial backup software that offers local encryption tends to be expensive, closed-source, and opaque about its security guarantees.

Heartbeat addresses this gap as an open-source, desktop backup tool that encrypts all data locally before it ever leaves the user's machine. It targets a specific use case that existing tools handle poorly: backing up folders, external drives, and network shares (SMB/NFS mounts) into password-protected vaults with full version history, while remaining simple enough for a non-technical user to operate through a graphical interface.

The project is relevant from both a practical and an educational standpoint. Practically, it solves a real problem — secure, versioned, local backups — with zero dependence on cloud infrastructure. Educationally, it touches on several core computer science topics: authenticated encryption, cryptographic key derivation, content-addressed storage, file-system traversal, concurrent programming with threads and signals, and GUI application architecture.

The core requirements we set for the project were:

- **Confidentiality:** All stored data must be encrypted with a strong, modern cipher. The password must never be stored on disk.
- **Integrity:** Tampering with encrypted data must be detectable.
- **Efficiency:** Repeated backups of the same source should be fast (incremental) and storage-efficient (deduplicated).
- **Usability:** The tool must be operable through a graphical interface without any command-line knowledge, while also offering a CLI fallback for scripted or headless use.

---

## 2. Approach and Methodology

### 2.1 Architecture

Heartbeat follows a strict separation-of-concerns architecture. The project is divided into three layers:

1. **Core layer** — Pure Python modules with no UI dependency: encryption (`crypto.py`), data structures (`manifest.py`), on-disk storage (`repository.py`), backup logic (`backup_engine.py`), and restore logic (`restore_engine.py`). These modules can be used independently, tested in isolation, and driven from any interface.

2. **Service layer** — Job configuration (`config.py`), scheduling (`schedule.py`, `scheduler.py`), OS keychain integration (`secret_store.py`), and logging (`logger.py`). These provide the plumbing that ties the core logic to a persistent, automated workflow.

3. **Interface layer** — A PySide6 graphical interface (`ui/`) and a CLI fallback (`cli.py`). The UI never performs encryption, hashing, or file I/O directly; it delegates everything to the core layer through well-defined function calls.

This layering was a deliberate design choice: it ensures that the security-critical code (encryption, key derivation, path validation) is concentrated in a small number of modules that can be reviewed independently of the 2,500-line UI.

### 2.2 Encryption Design

We chose **AES-256-GCM** for encryption, an authenticated encryption scheme that provides both confidentiality and integrity in a single operation. If anyone tampers with the ciphertext, the GCM authentication tag check will fail on decryption, and the data is rejected rather than silently returned as garbage.

The encryption key is never stored. Instead, the user's password is stretched into a 256-bit key using **PBKDF2-HMAC-SHA256** with 300,000 iterations and a random 16-byte salt (per OWASP 2023 guidelines). At vault creation time, a known plaintext is encrypted with the derived key and stored as a "verifier." On subsequent opens, we re-derive the key from the password, decrypt the verifier, and compare — if it does not match, the password is wrong. This approach avoids storing either the password or the key on disk.

Every encrypted blob receives a fresh random 12-byte nonce, so encrypting the same file twice produces different ciphertext. Files larger than 4 MiB are encrypted in chunks (each chunk is its own GCM blob with a length prefix), keeping memory usage bounded even for multi-gigabyte backups.

### 2.3 Content-Addressed Storage and Deduplication

Each file's SHA-256 hash (computed on the plaintext before encryption) serves as both its unique identifier and its filename within the repository's `objects/` directory. The directory is split into 256 two-character prefix subdirectories (like Git's object store) to avoid slow directory listings on older filesystems.

This content-addressing gives us free deduplication: if two files across different snapshots — or even different folders — have identical content, only one encrypted copy is stored on disk. An incremental backup that adds one file writes exactly one new object.

### 2.4 Incremental Backup Strategy

A file is considered unchanged if its relative path, size, and modification time all match the previous snapshot — the same heuristic used by rsync. Unchanged files reuse the previous snapshot's content hash without re-reading or re-hashing the file. This makes incremental backups of large directory trees very fast: only genuinely changed or new files incur I/O.

### 2.5 Threading Model

Long-running operations (backup, restore) run on background QThreads using Qt's "worker-object" pattern. A QObject subclass (the worker) is moved to a dedicated QThread; the thread's `started` signal triggers the worker's `run()` method. Progress updates and completion are communicated back to the UI thread through Qt Signals with `QueuedConnection`, which ensures that all UI widget access happens on the main thread — a requirement enforced by macOS with a runtime crash if violated.

Thread lifecycle is managed carefully: `deleteLater()` is used for safe C++ object destruction, and references are held until the thread's own `finished` signal confirms it has fully stopped.

---

## 3. Programming Tools and Methods

### 3.1 Language and Libraries

| Component | Tool | Role |
|-----------|------|------|
| Language | Python 3.10+ | Modern type hints (`X \| Y`, `list[T]`) |
| GUI | PySide6 (Qt 6) | Cross-platform desktop interface |
| Encryption | `cryptography` | AES-256-GCM, PBKDF2-HMAC-SHA256 |
| Keychain | `keyring` | OS-native secret storage |
| Stdlib | `hashlib`, `os`, `json`, `threading`, `pathlib` | Hashing, file I/O, serialization, concurrency |

### 3.2 Key Algorithms

- **PBKDF2-HMAC-SHA256** (key derivation): Deliberately slow (300,000 iterations) to resist brute-force attacks. The random salt prevents precomputed rainbow-table attacks.
- **AES-256-GCM** (authenticated encryption): Encrypts and authenticates data in a single pass. The 16-byte authentication tag detects any tampering.
- **SHA-256** (content hashing): Produces a 256-bit fingerprint of each file's plaintext content, used as the object ID for deduplication and as the filename in the object store.
- **Incremental comparison** (path + size + mtime): A fast heuristic that avoids re-reading unchanged files, reducing incremental backup time from O(total data) to O(changed data).

### 3.3 Design Patterns

- **Atomic writes:** Configuration files and snapshot manifests are written to a `.tmp` file first, then atomically renamed with `os.replace()`. This prevents corruption if the application crashes mid-write.
- **Worker-object threading:** QThread workers communicate with the UI via Qt Signals, keeping the interface responsive during long operations without shared mutable state.
- **Lazy loading with caching:** Snapshot manifests are decrypted on-demand and cached in a dictionary, so switching between previously viewed versions is instant.
- **Signal blocking:** During bulk table population, Qt table signals are blocked with `blockSignals(True)` to prevent redundant cascading updates that would freeze the UI.
- **Path-traversal protection:** Before restoring any file, the resolved target path is checked to ensure it remains within the destination directory, preventing crafted manifests from writing to arbitrary filesystem locations.

### 3.4 Project Structure

The project consists of 16 Python source files totalling approximately 4,650 lines of code, organized as follows:

```
Heartbeat/
  main.py                  # Entry point (GUI or --cli)
  requirements.txt         # Python dependencies
  heartbeat/               # Main package
    crypto.py              # AES-256-GCM + PBKDF2 key derivation
    manifest.py            # Snapshot/FileEntry data structures
    repository.py          # Content-addressed object store
    backup_engine.py       # Full + incremental backup logic
    restore_engine.py      # File-level + full restore
    config.py              # Job configuration persistence
    schedule.py            # Schedule model + next_due() function
    scheduler.py           # Background daemon thread
    secret_store.py        # OS keychain wrapper
    logger.py              # Centralized logging
    cli.py                 # Command-line interface
    ui/
      main_window.py       # All UI tabs, dialogs, and stylesheet
      utils.py             # Text formatters + programmatic app icon
      workers.py           # QThread backup/restore workers
```

---

## 4. Results

### 4.1 Functional Results

Heartbeat meets all of its design requirements:

- **Encryption:** All data in a vault is encrypted with AES-256-GCM. Passwords are never stored on disk; they are either prompted each time or stored in the OS keychain (macOS Keychain, Windows Credential Manager, or Linux Secret Service). The PBKDF2 key derivation with 300,000 iterations follows current OWASP guidance.

- **Deduplication:** The content-addressed object store ensures that identical files are stored exactly once, regardless of how many snapshots reference them. In our testing, a 500 MB source directory with three incremental backups (each modifying ~5% of files) consumed approximately 550 MB of vault space rather than the 1.5 GB that three full copies would require.

- **Incremental speed:** Incremental backups skip unchanged files entirely. A source directory of 1,597 files completes an incremental backup in under 2 seconds when fewer than 10 files have changed, compared to approximately 15 seconds for a full backup of the same source.

- **Version history:** Every backup creates a new snapshot. Users can browse all versions in the Restore tab, select any version, inspect its file list, and restore individual files or the entire snapshot.

- **Scheduling:** Jobs support four scheduling modes (manual, interval, daily at a specific time, weekly on selected days). The scheduler runs as an in-process daemon thread and fires due jobs automatically when a stored password is available. When no password is stored, the user is prompted with a dialog.

- **Cross-platform UI:** The PySide6 interface runs on macOS, Windows, and Linux with a consistent dark theme. A system tray icon allows the window to be hidden while the scheduler continues running in the background.

### 4.2 User Interface

The application presents four tabs:

1. **Home** — A dashboard with quick-start cards, job statistics, and navigation buttons.
2. **Backup** — A guided three-step form: choose a source folder, choose or create a vault, configure and run the backup with a live progress bar.
3. **Restore** — A two-pane layout with a versions table and a file browser with search filtering and selective restore via checkboxes.
4. **Jobs** — Saved backup configurations with scheduling, password storage options, and a "Run Now" button.

The interface uses softened vocabulary for non-technical users: "Vault" instead of "Repository," "Version" instead of "Snapshot," "Quick" instead of "Incremental," and "Complete" instead of "Full."

### 4.3 Security Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256-GCM encryption of all stored data |
| Integrity | GCM authentication tag detects tampering |
| Key security | PBKDF2 with 300,000 iterations + random salt |
| No password storage | Verifier-based password checking |
| Nonce uniqueness | Fresh random 12-byte nonce per blob |
| Path-traversal defence | Resolved-path validation before file writes |
| Atomic writes | Write-to-tmp-then-rename prevents corruption |

### 4.4 Limitations and Future Work

- **No compression:** AES-GCM makes post-encryption compression ineffective, and pre-encryption compression can leak information in some threat models. We chose simplicity over marginal space savings.
- **In-process scheduler:** For production use, backup jobs should be registered with the OS scheduler (cron, launchd, Task Scheduler) so they run even when the application is closed.
- **No remote backends:** The current design only supports local and mounted-network paths. Adding cloud storage backends (S3, SFTP) would broaden the tool's applicability.
- **Single-threaded hashing:** SHA-256 hashing is sequential. Parallelizing it across CPU cores would improve full-backup performance on NVMe storage.

---

## References

1. Dworkin, M. (2007). *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC.* NIST Special Publication 800-38D.
2. Krawczyk, H., & Eronen, P. (2010). *HMAC-based Extract-and-Expand Key Derivation Function (HKDF).* RFC 5869.
3. OWASP Foundation (2023). *Password Storage Cheat Sheet.* https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
4. The Qt Company (2024). *Qt for Python (PySide6) Documentation.* https://doc.qt.io/qtforpython-6/
5. Python Cryptographic Authority (2024). *cryptography library documentation.* https://cryptography.io/en/latest/
6. Jaraco (2024). *keyring library documentation.* https://pypi.org/project/keyring/
