"""Command-line interface — fallback when no UI is desired.

Usage:
    heartbeat --cli init   <repo>
    heartbeat --cli backup <repo> <source> [--full] [--ignore-hidden]
    heartbeat --cli restore <repo> <snapshot_id> <dest> [--path PREFIX] [--overwrite]
    heartbeat --cli snapshots <repo>
    heartbeat --cli list    <repo> <snapshot_id>

Passwords are prompted with getpass so they don't appear in shell history.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .backup_engine import BackupEngine, BackupProgress
from .logger import configure, get_logger
from .repository import Repository, RepositoryError
from .restore_engine import RestoreEngine, RestoreProgress

log = get_logger(__name__)


def _prompt_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Repository password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm password:     ")
        if pw != pw2:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(2)
    return pw


def _print_backup_progress(p: BackupProgress) -> None:
    bar = f"[{p.files_done}/{p.files_total}] {p.percent():5.1f}%"
    msg = p.current_file[:60] if p.current_file else p.message
    sys.stdout.write(f"\r{bar}  {msg:<60}")
    sys.stdout.flush()


def _print_restore_progress(p: RestoreProgress) -> None:
    bar = f"[{p.files_done}/{p.files_total}] {p.percent():5.1f}%"
    msg = p.current_file[:60] if p.current_file else p.message
    sys.stdout.write(f"\r{bar}  {msg:<60}")
    sys.stdout.flush()


# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    pw = _prompt_password(confirm=True)
    try:
        Repository.initialize(Path(args.repo), pw)
    except RepositoryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(f"Initialized repository at {args.repo}")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    pw = _prompt_password()
    try:
        repo = Repository.open(Path(args.repo), pw)
    except RepositoryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    engine = BackupEngine(repo)
    kind = "full" if args.full else "incremental"
    result = engine.backup(
        args.source,
        kind=kind,
        progress_cb=_print_backup_progress,
        ignore_hidden=args.ignore_hidden,
    )
    print()  # newline after the progress line
    print(f"Snapshot {result.snapshot_id}: {result.files} files, "
          f"{result.new_objects} new / {result.reused_objects} reused, "
          f"{result.duration_seconds:.1f}s")
    if result.errors:
        print(f"{len(result.errors)} error(s):", file=sys.stderr)
        for e in result.errors[:10]:
            print(f"  - {e}", file=sys.stderr)
    return 0 if not result.errors else 1


def cmd_restore(args: argparse.Namespace) -> int:
    pw = _prompt_password()
    try:
        repo = Repository.open(Path(args.repo), pw)
    except RepositoryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    engine = RestoreEngine(repo)
    result = engine.restore(
        snapshot_id=args.snapshot_id,
        dest=args.dest,
        path_prefix=args.path,
        overwrite=args.overwrite,
        progress_cb=_print_restore_progress,
    )
    print()
    print(f"Restored {result.files} files ({result.bytes} bytes) "
          f"in {result.duration_seconds:.1f}s")
    if result.errors:
        print(f"{len(result.errors)} error(s):", file=sys.stderr)
        for e in result.errors[:10]:
            print(f"  - {e}", file=sys.stderr)
    return 0 if not result.errors else 1


def cmd_snapshots(args: argparse.Namespace) -> int:
    pw = _prompt_password()
    repo = Repository.open(Path(args.repo), pw)
    ids = repo.list_snapshots()
    if not ids:
        print("(no snapshots)")
        return 0
    for sid in ids:
        snap = repo.load_snapshot(sid)
        print(f"{sid}  kind={snap.kind:11}  files={len(snap.entries):6}  "
              f"bytes={snap.total_size()}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    pw = _prompt_password()
    repo = Repository.open(Path(args.repo), pw)
    snap = repo.load_snapshot(args.snapshot_id)
    for entry in snap.entries:
        print(f"{entry.size:12}  {entry.path}")
    return 0


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="Heartbeat", description="Heartbeat — encrypted backup tool.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Create a new repository.")
    sp.add_argument("repo")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("backup", help="Back up a source folder into a repository.")
    sp.add_argument("repo")
    sp.add_argument("source")
    sp.add_argument("--full", action="store_true", help="Force a full backup.")
    sp.add_argument("--ignore-hidden", action="store_true")
    sp.set_defaults(func=cmd_backup)

    sp = sub.add_parser("restore", help="Restore files from a snapshot.")
    sp.add_argument("repo")
    sp.add_argument("snapshot_id")
    sp.add_argument("dest")
    sp.add_argument("--path", default=None, help="Restore only entries under this prefix.")
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(func=cmd_restore)

    sp = sub.add_parser("snapshots", help="List snapshots in a repository.")
    sp.add_argument("repo")
    sp.set_defaults(func=cmd_snapshots)

    sp = sub.add_parser("list", help="List files in a snapshot.")
    sp.add_argument("repo")
    sp.add_argument("snapshot_id")
    sp.set_defaults(func=cmd_list)

    return p


def main(argv: list[str] | None = None) -> int:
    configure()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
