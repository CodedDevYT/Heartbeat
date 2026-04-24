"""Small UI helpers: text formatting + the programmatically-drawn app icon.

Keeping these in a separate module makes the main window file shorter and
lets us share them across tabs and the launcher.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap


def format_size(n_bytes: int) -> str:
    """'12345' → '12.1 KB'. Uses binary units (KiB/MiB) but shortens the label."""
    if n_bytes < 0:
        return "–"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(n_bytes)
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.1f} {units[idx]}"


def format_timestamp(ts: float) -> str:
    """Unix seconds → a compact human string like 'Apr 22, 2026 at 6:07 PM'."""
    if ts <= 0:
        return "never"
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%b %d, %Y at %I:%M %p").replace(" 0", " ")


_SNAP_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2})-(\d{2})-(\d{2})(?:-(\d{3}))?$")


def format_snapshot_id(snapshot_id: str) -> str:
    """Turn '2026-04-22T16-07-26-627' into 'Apr 22, 2026 at 4:07 PM'.

    Falls back to the raw id if the format is unexpected.
    """
    m = _SNAP_RE.match(snapshot_id)
    if not m:
        return snapshot_id
    year, month, day, hour, minute, second, _ = m.groups()
    dt = datetime(int(year), int(month), int(day), int(hour), int(minute),
                  int(second), tzinfo=timezone.utc).astimezone()
    return dt.strftime("%b %d, %Y at %I:%M %p").replace(" 0", " ")


def make_app_icon(size: int = 256) -> QIcon:
    """Return the Heartbeat app icon, drawn with QPainter.

    Doing it programmatically avoids shipping a separate asset file. The
    result is a rounded dark square with a blue ECG/heartbeat line across
    the middle — matches the app name and the UI's accent colour.
    """
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)

    p = QPainter(pix)
    try:
        p.setRenderHint(QPainter.Antialiasing, True)

        inset = size * 0.06
        rect_w = size - 2 * inset
        radius = size * 0.22

        # Background — deep navy square, subtle outline.
        p.setBrush(QColor("#111319"))
        p.setPen(QPen(QColor("#2a2d34"), max(2, size // 64)))
        p.drawRoundedRect(int(inset), int(inset), int(rect_w), int(rect_w),
                          radius, radius)

        # Heartbeat line — scaled relative to size so it looks sharp at
        # every resolution Qt asks for (16×16 tray vs 512×512 dock).
        stroke_w = max(4, size // 20)
        p.setPen(QPen(QColor("#3b82f6"), stroke_w,
                      Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))

        cy = size / 2
        path = QPainterPath()
        path.moveTo(size * 0.16, cy)
        path.lineTo(size * 0.32, cy)
        path.lineTo(size * 0.40, cy - size * 0.18)
        path.lineTo(size * 0.50, cy + size * 0.22)
        path.lineTo(size * 0.60, cy - size * 0.12)
        path.lineTo(size * 0.68, cy)
        path.lineTo(size * 0.84, cy)
        p.drawPath(path)
    finally:
        p.end()

    icon = QIcon(pix)
    # Pre-render a couple of common sizes so macOS/Windows tray/dock don't
    # have to re-scale the 256-px version badly.
    for s in (16, 24, 32, 48, 64, 128):
        small = QPixmap(s, s)
        small.fill(Qt.transparent)
        pp = QPainter(small)
        try:
            pp.setRenderHint(QPainter.Antialiasing, True)
            pp.setRenderHint(QPainter.SmoothPixmapTransform, True)
            pp.drawPixmap(0, 0, s, s, pix)
        finally:
            pp.end()
        icon.addPixmap(small)
    return icon


def password_strength(pw: str) -> tuple[int, str]:
    """Return (score 0..4, label). Very rough, only meant as a hint.

    Checks length and character variety (lowercase, uppercase, digits,
    symbols). This is NOT a cryptographic strength check — just a
    simple heuristic to nudge users toward better passwords.
    """
    if not pw:
        return 0, "Enter a password"
    score = 0
    if len(pw) >= 8:
        score += 1
    if len(pw) >= 14:
        score += 1
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if classes >= 2:
        score += 1
    if classes >= 3 and len(pw) >= 10:
        score += 1
    labels = ["Very weak", "Weak", "Okay", "Good", "Strong"]
    return score, labels[min(score, 4)]
