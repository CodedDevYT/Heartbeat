"""Schedule model for backup jobs.

A `Schedule` is a lightweight dataclass covering four common rhythms:

    - manual   — only runs when the user clicks Run
    - interval — every N minutes / hours / days
    - daily    — once a day at HH:MM (local time)
    - weekly   — on selected weekdays at HH:MM (local time)

`next_due()` is a pure function so the scheduling logic is testable without
threads, timers, or wall-clock dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time as dtime, timedelta


WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@dataclass
class Schedule:
    kind: str = "manual"                # manual | interval | daily | weekly
    interval_value: int = 0             # N in "every N units"
    interval_unit: str = "minutes"      # minutes | hours | days
    time_of_day: str = "09:00"          # HH:MM, 24-hour, local time
    weekdays: list[int] = field(default_factory=list)  # 0=Mon … 6=Sun

    # --- serialization ----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "interval_value": self.interval_value,
            "interval_unit": self.interval_unit,
            "time_of_day": self.time_of_day,
            "weekdays": list(self.weekdays),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Schedule":
        return cls(
            kind=d.get("kind", "manual"),
            interval_value=int(d.get("interval_value", 0) or 0),
            interval_unit=d.get("interval_unit", "minutes"),
            time_of_day=d.get("time_of_day", "09:00"),
            weekdays=list(d.get("weekdays", []) or []),
        )

    # --- human description -----------------------------------------------

    def describe(self) -> str:
        if self.kind == "interval" and self.interval_value > 0:
            n = self.interval_value
            unit = self.interval_unit
            if n == 1:
                unit = unit.rstrip("s")
            return f"every {n} {unit}"
        if self.kind == "daily":
            return f"daily at {self.time_of_day}"
        if self.kind == "weekly":
            if not self.weekdays:
                return "weekly (no days picked)"
            days = ", ".join(WEEKDAY_NAMES[d] for d in sorted(self.weekdays))
            return f"{days} at {self.time_of_day}"
        return "manual"


def parse_time_of_day(s: str) -> dtime:
    """Parse 'HH:MM' into a datetime.time, falling back to 09:00 on error."""
    try:
        h, m = s.split(":", 1)
        return dtime(int(h) % 24, int(m) % 60)
    except Exception:
        return dtime(9, 0)


def _interval_delta(sched: Schedule) -> timedelta | None:
    n = max(0, sched.interval_value)
    if n <= 0:
        return None
    if sched.interval_unit == "minutes":
        return timedelta(minutes=n)
    if sched.interval_unit == "hours":
        return timedelta(hours=n)
    if sched.interval_unit == "days":
        return timedelta(days=n)
    return None


def next_due(sched: Schedule, last_run: float, now: datetime) -> datetime | None:
    """Return the next datetime the job should fire, or None if never.

    This is a **pure function** — it takes the current time as a parameter
    instead of calling ``datetime.now()`` internally. That makes it trivial
    to unit-test every scheduling mode without mocking the clock.

    Args:
        sched:    The schedule configuration for the job.
        last_run: Unix timestamp of the job's most recent run (0 = never ran).
        now:      The "current" local datetime (passed in for testability).

    Returns:
        The next datetime the job is due, or ``None`` if the schedule is
        manual or otherwise doesn't have a next occurrence.
    """
    if sched.kind == "manual":
        return None

    if sched.kind == "interval":
        delta = _interval_delta(sched)
        if delta is None:
            return None
        if last_run <= 0:
            return now  # run immediately the first time
        return datetime.fromtimestamp(last_run) + delta

    tod = parse_time_of_day(sched.time_of_day)

    if sched.kind == "daily":
        # Today at HH:MM, or tomorrow if already past and we've run today.
        today_at = datetime.combine(now.date(), tod)
        if last_run <= 0:
            # Never run → next occurrence that hasn't passed; if already past,
            # run now (the user likely expects it to catch up on first launch).
            return today_at if today_at >= now else now
        last_dt = datetime.fromtimestamp(last_run)
        if last_dt.date() < now.date() and today_at <= now:
            return now  # missed today's slot, catch up
        if today_at > last_dt and today_at > now:
            return today_at
        return datetime.combine(now.date() + timedelta(days=1), tod)

    if sched.kind == "weekly":
        if not sched.weekdays:
            return None
        # Find the next datetime >= now whose weekday is selected, at HH:MM.
        # Cap search at 8 days to terminate cleanly.
        last_dt = datetime.fromtimestamp(last_run) if last_run > 0 else None
        for offset in range(0, 8):
            day = now.date() + timedelta(days=offset)
            if day.weekday() not in sched.weekdays:
                continue
            candidate = datetime.combine(day, tod)
            if candidate < now:
                # Today's slot already passed — skip unless we missed it entirely
                # (never run, or last run was before today's slot).
                if offset == 0 and (last_dt is None or last_dt < candidate):
                    return now
                continue
            if last_dt and candidate <= last_dt:
                continue
            return candidate
        return None

    return None
