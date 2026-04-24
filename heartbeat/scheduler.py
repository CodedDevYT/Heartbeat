"""In-process scheduler for backup jobs.

A background daemon thread ticks every few seconds and fires any job whose
`Schedule` says it's due. Firing runs on the scheduler thread via `runner`;
if the job has no stored password, we log a hint and skip rather than
blocking on a UI prompt from a non-UI thread.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Callable

from . import secret_store
from .config import AppConfig, BackupJob
from .logger import get_logger
from .schedule import next_due

log = get_logger(__name__)

# runner receives the job plus the password it should use (or None).
JobRunner = Callable[[BackupJob, str | None], None]


class Scheduler:
    """Background daemon thread that checks for due jobs every N seconds.

    The thread is a daemon so it dies automatically when the main app
    exits. The ``runner`` callback receives the job + password; it runs
    on the scheduler thread, so if it touches UI it must bounce to the
    main thread (which MainWindow does via a Qt Signal).
    """

    def __init__(self, config: AppConfig, runner: JobRunner, tick_seconds: float = 10.0) -> None:
        self.config = config
        self.runner = runner
        self.tick_seconds = tick_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="heartbeat-scheduler", daemon=True)
        self._thread.start()
        log.info("Scheduler started.")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        log.info("Scheduler stopped.")

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = datetime.now()
            for job in list(self.config.jobs):
                due = next_due(job.schedule, job.last_run, now)
                if due is None or due > now:
                    continue

                password = secret_store.get_password(job.name) if job.save_password else None
                if job.save_password and password is None:
                    log.warning(
                        "Job '%s' is due but no stored password was found. "
                        "Open the app and click Run Now, or re-save the password.",
                        job.name,
                    )
                    job.last_run = time.time()
                    continue

                log.info("Scheduler triggering job %s", job.name)
                try:
                    self.runner(job, password)
                except Exception as e:
                    log.exception("Scheduled job %s failed: %s", job.name, e)

            self._stop.wait(self.tick_seconds)
