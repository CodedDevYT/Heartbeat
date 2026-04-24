"""Persisted backup-job configuration.

Backup jobs (source + vault + schedule) are stored as JSON in the user's
config directory. Passwords are never written here; when a job opts into
unattended runs, the password lives in the OS keychain (see `secret_store`).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .schedule import Schedule


def default_config_path() -> Path:
    """Platform-appropriate config file path."""
    home = Path.home()
    return home / ".heartbeat" / "config.json"


@dataclass
class BackupJob:
    name: str
    source: str                # folder, drive mount, or SMB path
    repo: str                  # repository directory
    kind: str = "incremental"  # default mode for scheduled runs
    ignore_hidden: bool = False
    schedule: Schedule = field(default_factory=Schedule)
    save_password: bool = False   # if True, password lives in the OS keychain
    last_run: float = 0.0      # unix seconds
    last_snapshot: str = ""    # latest snapshot id

    def to_dict(self) -> dict:
        d = asdict(self)
        d["schedule"] = self.schedule.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "BackupJob":
        # Backward compatibility: older configs stored scheduling as a single
        # integer field ``schedule_minutes``. If we find that instead of a
        # ``schedule`` dict, convert it to the new Schedule dataclass.
        sched_raw = d.get("schedule")
        if isinstance(sched_raw, dict):
            schedule = Schedule.from_dict(sched_raw)
        else:
            old_minutes = int(d.get("schedule_minutes", 0) or 0)
            if old_minutes > 0:
                schedule = Schedule(
                    kind="interval",
                    interval_value=old_minutes,
                    interval_unit="minutes",
                )
            else:
                schedule = Schedule()
        return cls(
            name=d.get("name", ""),
            source=d.get("source", ""),
            repo=d.get("repo", ""),
            kind=d.get("kind", "incremental"),
            ignore_hidden=bool(d.get("ignore_hidden", False)),
            schedule=schedule,
            save_password=bool(d.get("save_password", False)),
            last_run=float(d.get("last_run", 0.0) or 0.0),
            last_snapshot=d.get("last_snapshot", "") or "",
        )


@dataclass
class AppConfig:
    jobs: list[BackupJob] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"jobs": [j.to_dict() for j in self.jobs]}

    @classmethod
    def from_dict(cls, d: dict) -> "AppConfig":
        return cls(jobs=[BackupJob.from_dict(j) for j in d.get("jobs", [])])

    # --- CRUD --------------------------------------------------------------

    def find(self, name: str) -> BackupJob | None:
        return next((j for j in self.jobs if j.name == name), None)

    def upsert(self, job: BackupJob) -> None:
        for i, existing in enumerate(self.jobs):
            if existing.name == job.name:
                self.jobs[i] = job
                return
        self.jobs.append(job)

    def remove(self, name: str) -> bool:
        before = len(self.jobs)
        self.jobs = [j for j in self.jobs if j.name != name]
        return len(self.jobs) != before


class ConfigStore:
    """Loads and saves AppConfig atomically to disk.

    Uses the same write-to-tmp-then-rename pattern as the repository
    to prevent corruption if the app crashes while writing.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_config_path()

    def load(self) -> AppConfig:
        if not self.path.exists():
            return AppConfig()
        try:
            return AppConfig.from_dict(json.loads(self.path.read_text(encoding="utf-8")))
        except Exception:
            backup = self.path.with_suffix(".corrupt.bak")
            try:
                self.path.rename(backup)
            except OSError:
                pass
            return AppConfig()

    def save(self, cfg: AppConfig) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg.to_dict(), indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
