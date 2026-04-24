"""QThread workers that keep long-running backup and restore operations off
the UI thread. They expose Qt signals for progress, completion, and errors.

How this works (the Qt "worker-object" pattern):
  1. Create a QObject subclass (the worker) with a run() method.
  2. Create a QThread (a managed OS thread).
  3. Move the worker to the new thread with moveToThread().
  4. Connect the thread's started signal to the worker's run() slot.
  5. When run() finishes, the worker emits finished or failed,
     which tells the thread to quit.

Why threads, not multiprocessing: the operations are I/O-bound (file reads,
disk writes, network mount traffic), so releasing the GIL during blocking I/O
is enough. Threading also keeps the derived encryption key in a single
process, which avoids any ugly IPC around secret material.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal

from ..backup_engine import BackupEngine, BackupProgress, BackupResult
from ..repository import Repository
from ..restore_engine import RestoreEngine, RestoreProgress, RestoreResult


# ---------------------------------------------------------------------------


class BackupWorker(QObject):
    """Runs a backup on a background QThread.

    Communication with the UI thread uses three Qt Signals:
      - ``progress`` — emitted periodically with a dict of progress info
      - ``finished`` — emitted once with the final result dict
      - ``failed``   — emitted with an error message if something goes wrong

    The ``cancel()`` method sets a flag that the backup engine checks
    between files, allowing a clean abort without killing the thread.
    """
    progress = Signal(dict)            # BackupProgress as dict
    finished = Signal(dict)            # BackupResult as dict
    failed = Signal(str)

    def __init__(self, repo: Repository, source: str, kind: str,
                 ignore_hidden: bool = False, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.repo = repo
        self.source = source
        self.kind = kind
        self.ignore_hidden = ignore_hidden
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            engine = BackupEngine(self.repo)
            result: BackupResult = engine.backup(
                source=self.source,
                kind=self.kind,
                ignore_hidden=self.ignore_hidden,
                progress_cb=lambda p: self.progress.emit(asdict(p)),
                cancel_cb=lambda: self._cancel,
            )
            self.finished.emit(asdict(result))
        except Exception as e:
            self.failed.emit(str(e))


class RestoreWorker(QObject):
    progress = Signal(dict)
    finished = Signal(dict)
    failed = Signal(str)

    def __init__(self, repo: Repository, snapshot_id: str, dest: str,
                 path_prefix: str | None = None,
                 paths: list[str] | None = None,
                 overwrite: bool = False,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.repo = repo
        self.snapshot_id = snapshot_id
        self.dest = dest
        self.path_prefix = path_prefix
        self.paths = paths
        self.overwrite = overwrite
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            engine = RestoreEngine(self.repo)
            result: RestoreResult = engine.restore(
                snapshot_id=self.snapshot_id,
                dest=self.dest,
                path_prefix=self.path_prefix,
                paths=self.paths,
                overwrite=self.overwrite,
                progress_cb=lambda p: self.progress.emit(asdict(p)),
                cancel_cb=lambda: self._cancel,
            )
            self.finished.emit(asdict(result))
        except Exception as e:
            self.failed.emit(str(e))


# ---------------------------------------------------------------------------


def run_in_thread(worker: QObject) -> QThread:
    """Attach ``worker`` to a fresh QThread and start it.

    This is the standard Qt "worker-object" pattern:
      1. Create a QThread (a managed OS thread).
      2. Move the worker QObject to that thread.
      3. Connect the thread's ``started`` signal to the worker's ``run`` slot.
      4. Connect the worker's ``finished``/``failed`` signals to the thread's
         ``quit`` slot so the thread exits cleanly when work is done.

    The caller must keep a reference to the returned QThread (and the worker)
    to prevent premature garbage collection.
    """
    thread = QThread()
    worker.moveToThread(thread)
    thread.started.connect(worker.run)

    # Use QueuedConnection so thread.quit() is dispatched on the thread's
    # own event loop rather than called directly from within worker.run().
    # This avoids a race where the thread is destroyed while still inside
    # run(), and ensures all pending signals are delivered before the
    # thread stops.
    from PySide6.QtCore import Qt
    if hasattr(worker, "finished"):
        worker.finished.connect(thread.quit, Qt.QueuedConnection)
    if hasattr(worker, "failed"):
        worker.failed.connect(thread.quit, Qt.QueuedConnection)
    thread.start()
    return thread
