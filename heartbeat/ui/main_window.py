"""Heartbeat main window — the PySide6 graphical interface.

Architecture:
    MainWindow (QMainWindow) owns a QTabWidget with four tabs and a
    persistent activity-log panel at the bottom.

    Tab layout (in order):
        1. Home     — Plain-English explanation, quick stats, and action
                      buttons that navigate to the other tabs.
        2. Backup   — A guided three-step form: choose source → choose vault
                      → configure & run. Buttons stay disabled until every
                      required field is filled in.
        3. Restore  — Two-pane layout: versions table on the left, files
                      table (with checkboxes and a search filter) on the right.
        4. Jobs     — Saved source/vault pairs with optional scheduling.

    Long operations (backup, restore) run on background QThreads via the
    ``BackupWorker`` / ``RestoreWorker`` classes in ``workers.py``. Progress
    is communicated back to the UI thread through Qt Signals.

UI vocabulary is deliberately softened for non-technical users:
    Repository → Vault          Snapshot   → Version
    Incremental → Quick          Full       → Complete

Style:
    A single STYLESHEET constant defines a dark theme with a consistent
    colour palette. Every card, button, input, and table is styled through
    Qt Style Sheets (QSS), which work similarly to CSS.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTime, QTimer, Signal
from PySide6.QtGui import QAction, QFont, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressBar,
    QPushButton, QRadioButton, QScrollArea, QSpinBox, QStackedWidget,
    QSystemTrayIcon, QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit,
    QTimeEdit, QVBoxLayout, QWidget,
)

from .. import crypto, secret_store
from ..config import AppConfig, BackupJob, ConfigStore
from ..logger import get_logger, memory_handler
from ..repository import Repository, RepositoryError
from ..schedule import Schedule, WEEKDAY_NAMES
from ..scheduler import Scheduler

# Short label shown in the header badge. Pulled from the crypto module so the
# UI always reflects the actual algorithm/KDF used under the hood.
ENCRYPTION_LABEL = f"AES-256-GCM  ·  PBKDF2-SHA256 ({crypto.DEFAULT_ITERATIONS:,} iter)"
from .utils import (format_size, format_snapshot_id, format_timestamp,
                    make_app_icon, password_strength)
from .workers import BackupWorker, RestoreWorker, run_in_thread

log = get_logger(__name__)

# Tab indices — used by the Home dashboard shortcuts and the View menu
# so we can navigate to tabs by number instead of by widget reference.
TAB_HOME, TAB_BACKUP, TAB_RESTORE, TAB_JOBS = 0, 1, 2, 3


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------

STYLESHEET = """
/*  Palette
 *  ----------------------------------------------------------
 *  bg      #0f1014   app background (near-black, slight blue)
 *  card    #1b1d22   cards sit clearly above bg (+7 L)
 *  border  #2a2d34   subtle highlight
 *  text    #f1f2f4   not pure-white — easier on the eyes
 *  muted   #b4b9c2   passes WCAG AA on card bg
 *  helper  #868c96   for small helper captions only
 *  accent  #3b82f6   blue — used sparingly
 */

/* Apply the app background to the main window only. Descendant widgets
 * inherit the color but keep transparent backgrounds so they don't paint
 * a dark box over the lighter cards they sit on. */
QMainWindow, QDialog { background-color: #0f1014; }
QWidget     { color: #f1f2f4; background: transparent; }
QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; }
QLabel, QCheckBox, QRadioButton { background: transparent; }

QLabel#h1      { font-size: 26px; font-weight: 700; color: #f1f2f4; }
QLabel#h2      { font-size: 17px; font-weight: 600; color: #f1f2f4; }
QLabel#h3      { font-size: 14px; font-weight: 600; color: #f1f2f4; }
QLabel#muted   { color: #b4b9c2; }
QLabel#step    { font-size: 11px; font-weight: 700; color: #60a5fa;
                 letter-spacing: 1.4px; }
QLabel#helper  { color: #868c96; font-size: 12px; }
QLabel#warning { color: #f59e0b; font-weight: 600; }
QLabel#danger  { color: #f87171; font-weight: 600; }
QLabel#badge {
    background-color: #1b1d22; color: #9aa3b0;
    border: 1px solid #2a2d34; border-radius: 10px;
    padding: 3px 10px; font-size: 11px; font-weight: 600;
    letter-spacing: 0.4px;
}

QPushButton {
    background-color: #3b82f6; color: white; border: none;
    padding: 8px 18px; border-radius: 6px; font-weight: 500;
    min-height: 20px;
}
QPushButton:hover    { background-color: #5b97f8; }
QPushButton:pressed  { background-color: #2563eb; }
QPushButton:disabled { background-color: #2a2d34; color: #5a5f69; }

QPushButton#primary-lg { padding: 12px 24px; font-size: 14px; font-weight: 600; }
QPushButton#ghost {
    background: transparent; color: #d1d5db;
    border: 1px solid #2a2d34; font-weight: 500;
}
QPushButton#ghost:hover   { color: #f1f2f4; border-color: #3b82f6; }
QPushButton#ghost:pressed { background-color: #1b1d22; }
QPushButton#link {
    background: transparent; color: #60a5fa; border: none;
    padding: 2px 4px; text-align: left; font-weight: 500;
}
QPushButton#link:hover { color: #93c5fd; }

QLineEdit, QComboBox, QSpinBox, QTimeEdit, QTextEdit, QListWidget, QTableWidget {
    background-color: #13151a; border: 1px solid #2a2d34;
    border-radius: 6px; padding: 7px 10px; color: #f1f2f4;
    selection-background-color: #3b82f6;
    selection-color: white;
    min-height: 22px;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QTimeEdit:focus, QTextEdit:focus {
    border-color: #3b82f6;
}
QTimeEdit::up-button, QTimeEdit::down-button { width: 16px; }
QSpinBox::up-button, QSpinBox::down-button { width: 16px; }
QLineEdit::placeholder { color: #5a5f69; }

QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background: #1b1d22; border: 1px solid #2a2d34;
    selection-background-color: #3b82f6;
}

QTabWidget::pane { border: none; padding-top: 8px; background: transparent; }
QTabBar { background: transparent; qproperty-drawBase: 0; }
QTabBar::tab {
    background: transparent; color: #9aa3b0;
    padding: 10px 20px; margin-right: 2px;
    border: none; border-bottom: 2px solid transparent;
    font-weight: 500;
}
QTabBar::tab:hover    { color: #f1f2f4; }
QTabBar::tab:selected {
    color: #f1f2f4; font-weight: 600;
    border-bottom: 2px solid #3b82f6;
}

QProgressBar {
    border: none; border-radius: 4px;
    background: #13151a; text-align: center;
    color: #f1f2f4; height: 8px; font-size: 11px;
}
QProgressBar::chunk { background-color: #3b82f6; border-radius: 4px; }

QFrame#card {
    background-color: #1b1d22; border: 1px solid #2a2d34;
    border-radius: 10px;
}

QFrame#strengthBar { background-color: #13151a; border-radius: 3px; }
QFrame#strengthFill-0 { background-color: #ef4444; border-radius: 3px; }
QFrame#strengthFill-1 { background-color: #f59e0b; border-radius: 3px; }
QFrame#strengthFill-2 { background-color: #eab308; border-radius: 3px; }
QFrame#strengthFill-3 { background-color: #84cc16; border-radius: 3px; }
QFrame#strengthFill-4 { background-color: #22c55e; border-radius: 3px; }

QHeaderView::section {
    background-color: #13151a; color: #9aa3b0;
    padding: 8px 10px; border: none;
    border-bottom: 1px solid #2a2d34;
    font-weight: 600; font-size: 11px; letter-spacing: 0.4px;
}
QTableWidget { gridline-color: transparent; }
QTableWidget::item { padding: 6px 8px; }
QTableWidget::item:selected { background: #1e3a5f; color: #f1f2f4; }

QListWidget::item { padding: 8px 10px; border-radius: 4px; }
QListWidget::item:selected { background: #1e3a5f; }

QCheckBox, QRadioButton { color: #f1f2f4; padding: 3px 0; spacing: 8px; }
QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; }

QScrollBar:vertical {
    background: transparent; width: 10px; margin: 2px;
}
QScrollBar::handle:vertical {
    background: #2a2d34; min-height: 20px; border-radius: 5px;
}
QScrollBar::handle:vertical:hover { background: #3b82f6; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }

QScrollBar:horizontal {
    background: transparent; height: 10px; margin: 2px;
}
QScrollBar::handle:horizontal {
    background: #2a2d34; min-width: 20px; border-radius: 5px;
}
QScrollBar::handle:horizontal:hover { background: #3b82f6; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
"""


# ---------------------------------------------------------------------------
# Reusable widgets
# ---------------------------------------------------------------------------


def _time_from_str(s: str) -> QTime:
    try:
        h, m = s.split(":", 1)
        return QTime(int(h) % 24, int(m) % 60)
    except Exception:
        return QTime(9, 0)


def _card(parent: QWidget | None = None) -> QFrame:
    """Create a styled card container — a rounded dark panel used as a
    visual grouping element throughout the UI. Styled via QSS #card."""
    f = QFrame(parent)
    f.setObjectName("card")
    return f


def _helper_text(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("helper")
    lbl.setWordWrap(True)
    return lbl


def _scroll_wrap(inner: QWidget) -> QScrollArea:
    """Wrap a widget in a frameless QScrollArea so the tab can shrink.

    The inner widget keeps its natural size; when the window is smaller, a
    vertical scrollbar appears. We use `setWidgetResizable(True)` so the
    inner widget tracks the viewport width (no horizontal scrolling for
    page content — tables have their own).
    """
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
    scroll.setWidget(inner)
    return scroll


def _badge(text: str) -> QLabel:
    """Small pill used for status chips (e.g. 'AES-256-GCM')."""
    lbl = QLabel(text)
    lbl.setObjectName("badge")
    lbl.setAlignment(Qt.AlignCenter)
    return lbl


def _step_label(num: int, title: str) -> QWidget:
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 0)
    v.setSpacing(2)
    step = QLabel(f"STEP {num}")
    step.setObjectName("step")
    t = QLabel(title)
    t.setObjectName("h2")
    v.addWidget(step)
    v.addWidget(t)
    return w


# ---------------------------------------------------------------------------
# Password dialog — with warning, show/hide, strength meter
# ---------------------------------------------------------------------------


class PasswordDialog(QDialog):
    """Password prompt. Two modes:

    - confirm=False: existing vault; shows a short unlock prompt.
    - confirm=True:  new vault;     shows a danger warning + strength meter.
    """

    def __init__(self, parent: QWidget | None, confirm: bool = False,
                 title: str | None = None, vault_name: str | None = None) -> None:
        super().__init__(parent)
        self._confirm = confirm
        self.setWindowTitle(title or ("Create Vault Password" if confirm else "Unlock Vault"))
        self.setModal(True)
        self.setMinimumWidth(460)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 22, 22, 22)
        outer.setSpacing(14)

        heading = QLabel("Create a vault password" if confirm else "Unlock your vault")
        heading.setObjectName("h2")
        outer.addWidget(heading)

        if vault_name:
            sub = QLabel(vault_name)
            sub.setObjectName("muted")
            outer.addWidget(sub)

        if confirm:
            warn = QLabel(
                "This password encrypts everything. Write it down somewhere safe: "
                "if you lose it, your backup data cannot be recovered."
            )
            warn.setObjectName("danger")
            warn.setWordWrap(True)
            outer.addWidget(warn)
        else:
            warn = QLabel("Enter the password you used when creating this vault.")
            warn.setObjectName("muted")
            warn.setWordWrap(True)
            outer.addWidget(warn)

        form = QFormLayout()
        form.setSpacing(8)

        # Password row with show/hide.
        pw_row = QWidget()
        pw_layout = QHBoxLayout(pw_row)
        pw_layout.setContentsMargins(0, 0, 0, 0)
        self.pw1 = QLineEdit()
        self.pw1.setEchoMode(QLineEdit.Password)
        self.pw1.textChanged.connect(self._on_changed)
        self.toggle_btn = QPushButton("Show")
        self.toggle_btn.setProperty("flat", "true")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setFixedWidth(72)
        self.toggle_btn.toggled.connect(self._toggle_visibility)
        pw_layout.addWidget(self.pw1, 1)
        pw_layout.addWidget(self.toggle_btn)
        form.addRow("Password:", pw_row)

        self.pw2: QLineEdit | None = None
        if confirm:
            self.pw2 = QLineEdit()
            self.pw2.setEchoMode(QLineEdit.Password)
            self.pw2.textChanged.connect(self._on_changed)
            form.addRow("Confirm:", self.pw2)

        outer.addLayout(form)

        # Strength meter (confirm mode only).
        if confirm:
            meter_row = QHBoxLayout()
            meter_row.setSpacing(4)
            self.meter_blocks: list[QFrame] = []
            for _ in range(4):
                b = QFrame()
                b.setObjectName("strengthBar")
                b.setFixedHeight(6)
                self.meter_blocks.append(b)
                meter_row.addWidget(b, 1)
            outer.addLayout(meter_row)

            self.strength_label = QLabel("Enter a password")
            self.strength_label.setObjectName("helper")
            outer.addWidget(self.strength_label)

        # Buttons.
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(
            "Create Vault" if confirm else "Unlock"
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

        self._on_changed()

    def _toggle_visibility(self, checked: bool) -> None:
        self.pw1.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        self.toggle_btn.setText("Hide" if checked else "Show")

    def _on_changed(self) -> None:
        if not self._confirm:
            return
        score, label = password_strength(self.pw1.text())
        for i, block in enumerate(self.meter_blocks):
            if i < score:
                block.setObjectName(f"strengthFill-{score - 1}")
            else:
                block.setObjectName("strengthBar")
            block.style().unpolish(block)
            block.style().polish(block)
        self.strength_label.setText(label)

    def _accept(self) -> None:
        if not self.pw1.text():
            QMessageBox.warning(self, "Heartbeat", "Password must not be empty.")
            return
        if self._confirm and self.pw2 is not None and self.pw1.text() != self.pw2.text():
            QMessageBox.warning(self, "Heartbeat", "Passwords do not match.")
            return
        if self._confirm:
            score, _ = password_strength(self.pw1.text())
            if score < 2:
                r = QMessageBox.question(
                    self, "Weak password",
                    "This password is quite weak. Use it anyway?",
                )
                if r != QMessageBox.Yes:
                    return
        self.accept()

    @property
    def password(self) -> str:
        return self.pw1.text()

    @staticmethod
    def ask(parent: QWidget | None, confirm: bool = False,
            title: str | None = None, vault_name: str | None = None) -> Optional[str]:
        dlg = PasswordDialog(parent, confirm=confirm, title=title, vault_name=vault_name)
        return dlg.password if dlg.exec() == QDialog.Accepted else None


# ---------------------------------------------------------------------------
# Help / "How it works" dialog
# ---------------------------------------------------------------------------


class HelpDialog(QDialog):
    """'How it works' dialog — card-based layout matching the app's visual style.

    Each concept (vaults, backups, restoring, scheduling, security) gets its
    own styled card so the dialog feels like part of the app rather than a
    wall of HTML text.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("How Heartbeat works")
        self.setMinimumSize(620, 520)

        # Scroll area wraps the cards so the dialog never overflows.
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(16)

        # -- Title --
        title = QLabel("How Heartbeat works")
        title.setObjectName("h1")
        layout.addWidget(title)
        subtitle = QLabel(
            "A quick guide to what Heartbeat does and how it keeps "
            "your files safe."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        layout.addSpacing(4)

        # -- Concept cards --
        self._add_card(layout,
            "1.  Vaults",
            "A vault is an encrypted folder. When you create one, Heartbeat "
            "turns any empty folder — on your disk, an external drive, or a "
            "network share — into a safe container. Everything gets encrypted "
            "with your password before it's written.",
            "Your password is never stored. Don't lose it — without the "
            "password nobody can read the vault, not even you.",
            warning=True,
        )
        self._add_card(layout,
            "2.  Backups & Versions",
            "Each time you run a backup, Heartbeat takes a snapshot of your "
            "source folder at that moment. Every version stays in the vault, "
            "so you can go back to last Tuesday or last month.",
        )
        self._add_card(layout,
            "3.  Quick vs. Complete",
            "Quick — only copies files that changed since the last backup. "
            "Fast, small, and good for daily use.\n\n"
            "Complete — re-checks every single file. Slower, but guarantees a "
            "fresh baseline if you're unsure.",
        )
        self._add_card(layout,
            "4.  Restoring files",
            "Open a vault, pick a version, and tick the files you want back. "
            "You can restore one file, a folder, or everything — to the "
            "original location or anywhere else.",
        )
        self._add_card(layout,
            "5.  Scheduling",
            "The Jobs tab lets you save a source + vault pair and schedule "
            "it to run automatically — every N minutes, daily at a set time, "
            "or on specific weekdays. Save the vault password in the system "
            "keychain so jobs can run unattended.",
        )

        # -- Security card (special treatment) --
        sec_card = _card()
        sv = QVBoxLayout(sec_card)
        sv.setContentsMargins(22, 18, 22, 18)
        sv.setSpacing(10)
        sec_title = QLabel("Security details")
        sec_title.setObjectName("h3")
        sv.addWidget(sec_title)

        chip_row = QHBoxLayout()
        chip_row.setSpacing(8)
        chip_row.addWidget(_badge("AES-256-GCM"))
        chip_row.addWidget(_badge(f"PBKDF2 {crypto.DEFAULT_ITERATIONS:,} iter"))
        chip_row.addWidget(_badge("SHA-256 dedup"))
        chip_row.addStretch(1)
        sv.addLayout(chip_row)

        details = QLabel(
            "Cipher: AES-256-GCM (authenticated encryption — tampering is "
            "detected on restore).\n\n"
            f"Key derivation: PBKDF2-HMAC-SHA256, {crypto.DEFAULT_ITERATIONS:,} "
            "iterations, 16-byte random salt per vault.\n\n"
            "Nonces: 12 bytes, freshly random per file blob.\n\n"
            "Passwords: never stored on disk. A known plaintext encrypted "
            "with the derived key is kept so the password can be verified "
            "at unlock without storing the key.\n\n"
            "Deduplication: files are addressed by SHA-256 of their plaintext, "
            "so an unchanged file is stored only once across all versions."
        )
        details.setObjectName("muted")
        details.setWordWrap(True)
        sv.addWidget(details)
        layout.addWidget(sec_card)

        # -- Storage + compatibility --
        self._add_card(layout,
            "What's stored where",
            "The vault folder contains only encrypted data. The app's own "
            "settings live in ~/.heartbeat/ (no passwords, no vault contents).",
        )
        self._add_card(layout,
            "Works with",
            "Local folders  ·  External drives (/Volumes/…, E:\\)  ·  "
            "Network shares (\\\\server\\share, /mnt/nas).",
        )

        layout.addStretch(1)
        scroll.setWidget(inner)

        # Dialog layout.
        dlg_layout = QVBoxLayout(self)
        dlg_layout.setContentsMargins(0, 0, 0, 0)
        dlg_layout.addWidget(scroll, 1)

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(18, 10, 18, 14)
        btn_row.addStretch(1)
        close_btn = QPushButton("Got it")
        close_btn.setObjectName("primary-lg")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        dlg_layout.addLayout(btn_row)

    @staticmethod
    def _add_card(layout: QVBoxLayout, title_text: str, body_text: str,
                  note_text: str = "", *, warning: bool = False) -> None:
        """Add a styled concept card to the layout."""
        card = _card()
        v = QVBoxLayout(card)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(8)

        title = QLabel(title_text)
        title.setObjectName("h3")
        v.addWidget(title)

        body = QLabel(body_text)
        body.setObjectName("muted")
        body.setWordWrap(True)
        v.addWidget(body)

        if note_text:
            note = QLabel(note_text)
            note.setObjectName("warning" if warning else "helper")
            note.setWordWrap(True)
            v.addWidget(note)

        layout.addWidget(card)


# ---------------------------------------------------------------------------
# Home tab
# ---------------------------------------------------------------------------


class HomeTab(QWidget):
    go_backup = Signal()
    go_restore = Signal()
    go_jobs = Signal()
    open_help = Signal()

    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.config = config
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        # Hero card — welcome message + explanation.
        hero = _card()
        hv = QVBoxLayout(hero)
        hv.setContentsMargins(24, 22, 24, 22)
        hv.setSpacing(10)

        title = QLabel("Welcome to Heartbeat")
        title.setObjectName("h1")
        hv.addWidget(title)

        sub = QLabel(
            "Heartbeat makes encrypted, versioned backups of your folders, "
            "drives, and network shares. Pick a folder to protect, pick a "
            "place to store the backups, and set a password — that's it."
        )
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        hv.addWidget(sub)

        hv.addSpacing(4)

        # Security chip row — always visible so users know what protects them.
        chip_row = QHBoxLayout()
        chip_row.setSpacing(8)
        chip_row.addWidget(_badge("AES-256-GCM"))
        chip_row.addWidget(_badge("PBKDF2-SHA256"))
        chip_row.addWidget(_badge("Authenticated"))
        chip_row.addStretch(1)
        btn_help = QPushButton("How does it work?")
        btn_help.setObjectName("ghost")
        btn_help.clicked.connect(self.open_help)
        chip_row.addWidget(btn_help)
        hv.addLayout(chip_row)

        layout.addWidget(hero)

        # Action cards — three side-by-side.
        actions = QHBoxLayout()
        actions.setSpacing(14)

        def action_card(step: str, title_text: str, body: str, btn_text: str, slot) -> QFrame:
            c = _card()
            cv = QVBoxLayout(c)
            cv.setContentsMargins(20, 18, 20, 18)
            cv.setSpacing(8)
            s = QLabel(step); s.setObjectName("step")
            t = QLabel(title_text); t.setObjectName("h2")
            b = QLabel(body); b.setObjectName("muted"); b.setWordWrap(True)
            cv.addWidget(s)
            cv.addWidget(t)
            cv.addWidget(b, 1)
            btn = QPushButton(btn_text)
            btn.clicked.connect(slot)
            cv.addWidget(btn)
            return c

        actions.addWidget(action_card(
            "BACK UP",
            "Protect your files",
            "Make an encrypted copy of a folder, drive, or share.",
            "Create a backup →",
            self.go_backup.emit,
        ), 1)
        actions.addWidget(action_card(
            "RESTORE",
            "Get your files back",
            "Browse past versions and restore one file or everything.",
            "Restore files →",
            self.go_restore.emit,
        ), 1)
        actions.addWidget(action_card(
            "SCHEDULE",
            "Set it and forget it",
            "Save a job and run it automatically at an interval.",
            "Manage jobs →",
            self.go_jobs.emit,
        ), 1)

        layout.addLayout(actions)

        # Stats card — saved jobs.
        stats = _card()
        sv = QVBoxLayout(stats)
        sv.setContentsMargins(20, 18, 20, 18)
        sv.setSpacing(8)
        h = QLabel("Your saved jobs")
        h.setObjectName("h2")
        sv.addWidget(h)

        self.stats_body = QVBoxLayout()
        self.stats_body.setSpacing(6)
        sv.addLayout(self.stats_body)

        layout.addWidget(stats, 1)
        self.refresh()

    def refresh(self) -> None:
        # Clear existing rows.
        while self.stats_body.count():
            item = self.stats_body.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not self.config.jobs:
            lbl = QLabel(
                "No saved jobs yet. Create a backup above, then save it as a "
                "job in the Jobs tab to run it again with one click."
            )
            lbl.setObjectName("muted")
            lbl.setWordWrap(True)
            self.stats_body.addWidget(lbl)
            return

        for j in self.config.jobs:
            row = QWidget()
            g = QGridLayout(row)
            g.setContentsMargins(0, 6, 0, 6)
            g.setHorizontalSpacing(12)
            name = QLabel(j.name)
            name.setStyleSheet("font-weight: 600;")
            sub = QLabel(f"{j.source} → {j.repo}")
            sub.setObjectName("muted")
            sched = j.schedule.describe()
            last = f"last: {format_timestamp(j.last_run)}"
            meta = QLabel(f"{sched} · {last}")
            meta.setObjectName("helper")
            g.addWidget(name, 0, 0)
            g.addWidget(meta, 0, 1, alignment=Qt.AlignRight)
            g.addWidget(sub, 1, 0, 1, 2)
            self.stats_body.addWidget(row)


# ---------------------------------------------------------------------------
# Backup tab — redesigned as 3 steps
# ---------------------------------------------------------------------------


class BackupTab(QWidget):
    log_line = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: BackupWorker | None = None
        self._thread = None
        self._build()
        self._update_button_state()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(14)

        # STEP 1 — Source.
        c1 = _card()
        v = QVBoxLayout(c1)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(10)
        v.addWidget(_step_label(1, "What do you want to back up?"))
        v.addWidget(_helper_text(
            "Choose any folder on your computer. External drives and mounted "
            "network shares (SMB) also work — just point at their folder path."
        ))
        row = QHBoxLayout()
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("e.g. /Users/me/Documents")
        self.source_edit.textChanged.connect(self._update_button_state)
        btn = QPushButton("Browse…")
        btn.setObjectName("ghost")
        btn.clicked.connect(self._pick_source)
        row.addWidget(self.source_edit, 1)
        row.addWidget(btn)
        v.addLayout(row)
        self.ignore_hidden = QCheckBox("Ignore hidden files and folders (names starting with '.')")
        v.addWidget(self.ignore_hidden)
        root.addWidget(c1)

        # STEP 2 — Destination vault.
        c2 = _card()
        v = QVBoxLayout(c2)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(10)
        v.addWidget(_step_label(2, "Where should the encrypted backup go?"))
        v.addWidget(_helper_text(
            "Pick an empty folder as your Vault, or reuse an existing one. "
            "Everything Heartbeat writes there is encrypted with your password."
        ))
        row = QHBoxLayout()
        self.repo_edit = QLineEdit()
        self.repo_edit.setPlaceholderText("e.g. /Volumes/BackupDrive/MyVault")
        self.repo_edit.textChanged.connect(self._update_button_state)
        btn_browse = QPushButton("Browse…")
        btn_browse.setObjectName("ghost")
        btn_browse.clicked.connect(self._pick_repo)
        row.addWidget(self.repo_edit, 1)
        row.addWidget(btn_browse)
        v.addLayout(row)

        row2 = QHBoxLayout()
        self.btn_init = QPushButton("Create new vault here")
        self.btn_init.setObjectName("ghost")
        self.btn_init.clicked.connect(self._init_repo)
        row2.addWidget(self.btn_init)
        row2.addStretch(1)
        v.addLayout(row2)
        root.addWidget(c2)

        # STEP 3 — Mode.
        c3 = _card()
        v = QVBoxLayout(c3)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(10)
        v.addWidget(_step_label(3, "How thorough?"))
        self.rb_quick = QRadioButton("Quick — only copy files that have changed since last time")
        self.rb_full = QRadioButton("Complete — re-check every file")
        self.rb_quick.setChecked(True)
        v.addWidget(self.rb_quick)
        v.addWidget(self.rb_full)
        v.addWidget(_helper_text(
            "Your very first backup to a new vault is always complete. After "
            "that, Quick is usually the right choice — it's fast and reuses "
            "unchanged files automatically."
        ))
        root.addWidget(c3)

        # Action row.
        row = QHBoxLayout()
        row.setSpacing(10)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("ghost")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_backup)
        self.btn_backup = QPushButton("Start Backup")
        self.btn_backup.setObjectName("primary-lg")
        self.btn_backup.clicked.connect(self._start_backup)
        row.addStretch(1)
        row.addWidget(self.btn_cancel)
        row.addWidget(self.btn_backup)
        root.addLayout(row)

        # Progress card (always visible — shows "Ready" when idle).
        self.progress_card = _card()
        pv = QVBoxLayout(self.progress_card)
        pv.setContentsMargins(22, 16, 22, 16)
        pv.setSpacing(8)
        self.progress_title = QLabel("Ready")
        self.progress_title.setObjectName("h2")
        pv.addWidget(self.progress_title)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        pv.addWidget(self.progress)
        self.progress_detail = QLabel("Fill in the steps above, then click Start Backup.")
        self.progress_detail.setObjectName("helper")
        self.progress_detail.setWordWrap(True)
        pv.addWidget(self.progress_detail)
        root.addWidget(self.progress_card)

        root.addStretch(1)

    # --- state ---

    def _update_button_state(self) -> None:
        ok = bool(self.source_edit.text().strip() and self.repo_edit.text().strip())
        self.btn_backup.setEnabled(ok)

    # --- actions ---

    def _pick_source(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose a folder to back up")
        if d:
            self.source_edit.setText(d)

    def _pick_repo(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose a Vault folder")
        if d:
            self.repo_edit.setText(d)

    def _init_repo(self) -> None:
        repo_path = self.repo_edit.text().strip()
        if not repo_path:
            QMessageBox.information(
                self, "Heartbeat",
                "First pick a folder above (Step 2) that will become the Vault, "
                "then click 'Create new vault here'."
            )
            return
        if Path(repo_path).exists() and next(Path(repo_path).iterdir(), None) is not None:
            QMessageBox.warning(
                self, "Heartbeat",
                "That folder isn't empty. Pick a different (empty or non-existent) "
                "folder to create a new vault."
            )
            return
        pw = PasswordDialog.ask(self, confirm=True, vault_name=repo_path)
        if pw is None:
            return
        try:
            Repository.initialize(Path(repo_path), pw)
        except RepositoryError as e:
            QMessageBox.critical(self, "Heartbeat", str(e))
            return
        QMessageBox.information(
            self, "Vault created",
            f"New vault created at\n{repo_path}\n\n"
            "You can now run your first backup."
        )
        self.log_line.emit(f"Created vault at {repo_path}")

    def _start_backup(self) -> None:
        source = self.source_edit.text().strip()
        repo_path = self.repo_edit.text().strip()
        if not source or not repo_path:
            return
        if not Path(repo_path).exists() or not (Path(repo_path) / "repo.json").exists():
            r = QMessageBox.question(
                self, "Heartbeat",
                "There's no vault at that location yet. Create one now?",
            )
            if r != QMessageBox.Yes:
                return
            self._init_repo()
            return

        pw = PasswordDialog.ask(self, vault_name=repo_path)
        if pw is None:
            return
        try:
            repo = Repository.open(Path(repo_path), pw)
        except RepositoryError as e:
            QMessageBox.critical(self, "Heartbeat", str(e))
            return

        kind = "full" if self.rb_full.isChecked() else "incremental"
        self._worker = BackupWorker(repo, source, kind, ignore_hidden=self.ignore_hidden.isChecked())
        # QueuedConnection ensures these slots run on the UI thread even
        # though the worker emits from the background QThread. Without this,
        # touching any QWidget from the worker thread crashes on macOS.
        self._worker.progress.connect(self._on_progress, Qt.QueuedConnection)
        self._worker.finished.connect(self._on_finished, Qt.QueuedConnection)
        self._worker.failed.connect(self._on_failed, Qt.QueuedConnection)
        self.btn_backup.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress.setValue(0)
        self.progress_title.setText("Scanning…")
        self.progress_detail.setText("Looking at the files in your source folder.")
        self.log_line.emit(f"Starting {kind} backup: {source} → {repo_path}")
        self._thread = run_in_thread(self._worker)

    def _cancel_backup(self) -> None:
        if self._worker:
            self._worker.cancel()
            self.progress_title.setText("Cancelling…")

    def _on_progress(self, p: dict) -> None:
        total = p.get("bytes_total") or 1
        done = p.get("bytes_done", 0)
        self.progress.setValue(int(100 * done / total))
        done_files = p.get("files_done", 0)
        total_files = p.get("files_total", 0)
        current = p.get("current_file", "")
        msg = p.get("message", "")
        self.progress_title.setText(f"Backing up — {done_files} of {total_files} files")
        pretty_done = format_size(done)
        pretty_total = format_size(p.get("bytes_total", 0))
        if current:
            self.progress_detail.setText(f"{pretty_done} of {pretty_total}  ·  {current}")
        else:
            self.progress_detail.setText(msg or "Working…")

    def _on_finished(self, r: dict) -> None:
        # Schedule safe cleanup — must wait for the QThread to fully stop
        # before dropping references, otherwise the C++ destructor aborts.
        self._cleanup_worker()
        self.btn_backup.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self._update_button_state()
        self.progress.setValue(100)
        self.progress_title.setText("Backup complete")
        self.progress_detail.setText(
            f"Version saved as {format_snapshot_id(r['snapshot_id'])} — "
            f"{r['files']} files, {r['new_objects']} new, "
            f"{r['reused_objects']} reused from previous versions, "
            f"in {r['duration_seconds']:.1f}s."
        )
        self.log_line.emit(
            f"Backup complete: {r['files']} files, {r['new_objects']} new."
        )
        if r.get("errors"):
            QMessageBox.warning(self, "Heartbeat",
                                f"Backup finished with {len(r['errors'])} error(s). "
                                "Check the activity log.")

    def _on_failed(self, msg: str) -> None:
        self._cleanup_worker()
        self.btn_backup.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self._update_button_state()
        self.progress_title.setText("Backup failed")
        self.progress_detail.setText(msg)
        self.log_line.emit(f"Backup failed: {msg}")
        QMessageBox.critical(self, "Heartbeat", msg)

    def _cleanup_worker(self) -> None:
        """Safely release the worker and thread references.

        deleteLater() lets Qt destroy the C++ objects on the next event-loop
        tick, after the thread has fully stopped — preventing the
        'QThread destroyed while still running' abort.
        """
        if self._thread is not None:
            self._thread.deleteLater()
        if self._worker is not None:
            self._worker.deleteLater()
        self._worker = None
        self._thread = None


# ---------------------------------------------------------------------------
# Restore tab — redesigned with tables
# ---------------------------------------------------------------------------


class RestoreTab(QWidget):
    log_line = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._repo: Repository | None = None
        self._repo_path: str = ""
        self._snapshot_cache: dict = {}
        self._current_entries: list = []
        self._worker: RestoreWorker | None = None
        self._thread = None
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(14)

        # STEP 1 — Open a vault.
        c1 = _card()
        v = QVBoxLayout(c1)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(10)
        v.addWidget(_step_label(1, "Open a vault"))
        v.addWidget(_helper_text(
            "Point at the vault folder you used when backing up, and enter its password."
        ))
        row = QHBoxLayout()
        self.repo_edit = QLineEdit()
        self.repo_edit.setPlaceholderText("Vault folder")
        btn = QPushButton("Browse…")
        btn.setObjectName("ghost")
        btn.clicked.connect(self._pick_repo)
        self.btn_open = QPushButton("Unlock")
        self.btn_open.clicked.connect(self._open_repo)
        row.addWidget(self.repo_edit, 1)
        row.addWidget(btn)
        row.addWidget(self.btn_open)
        v.addLayout(row)
        root.addWidget(c1)

        # STEP 2 / 3 panel — shown once a vault is open.
        self.body_stack = QStackedWidget()

        # Empty state.
        empty = _card()
        ev = QVBoxLayout(empty)
        ev.setContentsMargins(22, 40, 22, 40)
        ev.setSpacing(10)
        lbl = QLabel("No vault open")
        lbl.setObjectName("h2")
        lbl.setAlignment(Qt.AlignCenter)
        ev.addWidget(lbl)
        sub = QLabel("Unlock a vault above to see its backup versions.")
        sub.setObjectName("muted")
        sub.setAlignment(Qt.AlignCenter)
        sub.setWordWrap(True)
        ev.addWidget(sub)
        self.body_stack.addWidget(empty)

        # Real body.
        body = QWidget()
        bv = QVBoxLayout(body)
        bv.setContentsMargins(0, 0, 0, 0)
        bv.setSpacing(14)

        # Versions table.
        c2 = _card()
        v = QVBoxLayout(c2)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(8)
        v.addWidget(_step_label(2, "Pick a version"))
        self.versions_table = QTableWidget(0, 4)
        self.versions_table.setHorizontalHeaderLabels(["When", "Mode", "Files", "Size"])
        self.versions_table.horizontalHeader().setStretchLastSection(True)
        self.versions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.versions_table.verticalHeader().setVisible(False)
        self.versions_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.versions_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.versions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.versions_table.setMaximumHeight(170)
        self.versions_table.itemSelectionChanged.connect(self._load_files_for_selected)
        v.addWidget(self.versions_table)
        bv.addWidget(c2)

        # Files table.
        c3 = _card()
        v = QVBoxLayout(c3)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(8)
        v.addWidget(_step_label(3, "Pick files to restore"))
        v.addWidget(_helper_text(
            "Tick the files you want back, or leave everything unticked to "
            "restore the whole version."
        ))

        filter_row = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by name or path…")
        self.filter_edit.textChanged.connect(self._apply_filter)
        btn_check_all = QPushButton("Select all visible")
        btn_check_all.setObjectName("ghost")
        btn_check_all.clicked.connect(lambda: self._bulk_check(True))
        btn_uncheck_all = QPushButton("Clear selection")
        btn_uncheck_all.setObjectName("ghost")
        btn_uncheck_all.clicked.connect(lambda: self._bulk_check(False))
        filter_row.addWidget(self.filter_edit, 1)
        filter_row.addWidget(btn_check_all)
        filter_row.addWidget(btn_uncheck_all)
        v.addLayout(filter_row)

        self.files_table = QTableWidget(0, 3)
        self.files_table.setHorizontalHeaderLabels(["File", "Size", "Modified"])
        self.files_table.horizontalHeader().setStretchLastSection(False)
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.files_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.files_table.verticalHeader().setVisible(False)
        self.files_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        v.addWidget(self.files_table, 1)
        bv.addWidget(c3, 1)

        # Options + action row.
        opt_row = QHBoxLayout()
        self.overwrite = QCheckBox("Overwrite existing files at the destination")
        opt_row.addWidget(self.overwrite)
        opt_row.addStretch(1)
        self.btn_restore = QPushButton("Restore…")
        self.btn_restore.setObjectName("primary-lg")
        self.btn_restore.clicked.connect(self._start_restore)
        opt_row.addWidget(self.btn_restore)
        bv.addLayout(opt_row)

        # Progress card.
        self.progress_card = _card()
        pv = QVBoxLayout(self.progress_card)
        pv.setContentsMargins(22, 14, 22, 14)
        pv.setSpacing(8)
        self.progress_title = QLabel("Ready")
        self.progress_title.setObjectName("h2")
        pv.addWidget(self.progress_title)
        self.progress = QProgressBar()
        pv.addWidget(self.progress)
        self.progress_detail = QLabel("Pick a version above and click Restore.")
        self.progress_detail.setObjectName("helper")
        self.progress_detail.setWordWrap(True)
        pv.addWidget(self.progress_detail)
        bv.addWidget(self.progress_card)

        self.body_stack.addWidget(body)
        root.addWidget(self.body_stack, 1)

    # --- actions ---

    def _pick_repo(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Pick a vault folder")
        if d:
            self.repo_edit.setText(d)

    def _open_repo(self) -> None:
        repo_path = self.repo_edit.text().strip()
        if not repo_path:
            QMessageBox.information(self, "Heartbeat", "Pick a vault folder first.")
            return
        if not (Path(repo_path) / "repo.json").exists():
            QMessageBox.warning(self, "Heartbeat",
                                "That folder isn't a Heartbeat vault.")
            return
        pw = PasswordDialog.ask(self, vault_name=repo_path)
        if pw is None:
            return
        try:
            self._repo = Repository.open(Path(repo_path), pw)
        except RepositoryError as e:
            QMessageBox.critical(self, "Heartbeat", str(e))
            return
        self._repo_path = repo_path
        self._populate_versions()
        self.body_stack.setCurrentIndex(1)
        self.log_line.emit(f"Opened vault {repo_path}")

    def _populate_versions(self) -> None:
        """Fill the versions table from the vault's snapshot list.

        Only the snapshot IDs are read here (a fast directory glob).
        Full manifests are loaded lazily when the user selects a row,
        avoiding a multi-second freeze on vaults with many snapshots.

        Each row stores the snapshot ID in the first column's UserRole
        data so that lookups remain correct even if the table is sorted.
        """
        assert self._repo is not None
        ids = self._repo.list_snapshots()
        self._snapshot_cache: dict = {}
        t = self.versions_table

        # Block signals while we fill the table so that
        # itemSelectionChanged doesn't fire for every intermediate
        # state (setRowCount, setSortingEnabled, etc.).  Without this,
        # each spurious signal triggers a full snapshot decrypt + file
        # table render, freezing the UI on vaults with many versions.
        t.blockSignals(True)
        t.setSortingEnabled(False)
        t.setUpdatesEnabled(False)
        t.setRowCount(len(ids))
        for i, sid in enumerate(ids):
            when_item = QTableWidgetItem(format_snapshot_id(sid))
            when_item.setData(Qt.UserRole, sid)
            t.setItem(i, 0, when_item)
            t.setItem(i, 1, QTableWidgetItem("—"))
            t.setItem(i, 2, QTableWidgetItem("—"))
            t.setItem(i, 3, QTableWidgetItem("—"))
        t.setUpdatesEnabled(True)
        t.setSortingEnabled(True)
        t.blockSignals(False)

        # Now trigger exactly one selection (and one file-list load).
        if ids:
            t.selectRow(len(ids) - 1)

    def _load_snapshot(self, sid: str):
        """Load and cache a snapshot manifest.  Cached so switching back
        to a previously viewed version is instant."""
        if sid not in self._snapshot_cache:
            self._snapshot_cache[sid] = self._repo.load_snapshot(sid)
        return self._snapshot_cache[sid]

    def _selected_snapshot_id(self) -> str | None:
        """Return the snapshot ID stored in the currently selected
        versions-table row, or None if nothing is selected."""
        rows = self.versions_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.versions_table.item(rows[0].row(), 0)
        if item is None:
            return None
        return item.data(Qt.UserRole)

    def _load_files_for_selected(self) -> None:
        """Called when the user clicks a row in the versions table.
        Loads the snapshot manifest (from cache if available) and
        fills the files table with its entries."""
        if self._repo is None:
            return
        sid = self._selected_snapshot_id()
        if sid is None:
            return
        snap = self._load_snapshot(sid)

        # Back-fill the version row with details now that we have them.
        rows = self.versions_table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        t = self.versions_table
        kind = "Quick" if snap.kind == "incremental" else "Complete"
        for col, text in ((1, kind),
                          (2, str(len(snap.entries))),
                          (3, format_size(snap.total_size()))):
            cell = t.item(row, col)
            if cell is not None:
                cell.setText(text)

        self._current_entries = list(snap.entries)
        self._render_files(self._current_entries)

    def _render_files(self, entries: list) -> None:
        """Fill the files table with the entries from a snapshot.

        Sorting and visual updates are disabled while we bulk-fill
        the table, otherwise Qt re-sorts and repaints after every
        single setItem() call — that freezes the UI on snapshots
        with thousands of files.
        """
        t = self.files_table
        t.setSortingEnabled(False)
        t.setUpdatesEnabled(False)
        t.setRowCount(len(entries))
        for i, e in enumerate(entries):
            name_item = QTableWidgetItem(e.path)
            name_item.setFlags(name_item.flags() | Qt.ItemIsUserCheckable)
            name_item.setCheckState(Qt.Unchecked)
            size_item = QTableWidgetItem(format_size(e.size))
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            mtime_item = QTableWidgetItem(format_timestamp(e.mtime))
            t.setItem(i, 0, name_item)
            t.setItem(i, 1, size_item)
            t.setItem(i, 2, mtime_item)
        t.setUpdatesEnabled(True)
        t.setSortingEnabled(True)

    def _apply_filter(self, text: str) -> None:
        needle = text.lower().strip()
        for i in range(self.files_table.rowCount()):
            item = self.files_table.item(i, 0)
            if item is None:
                continue
            visible = not needle or needle in item.text().lower()
            self.files_table.setRowHidden(i, not visible)

    def _bulk_check(self, checked: bool) -> None:
        state = Qt.Checked if checked else Qt.Unchecked
        for i in range(self.files_table.rowCount()):
            if self.files_table.isRowHidden(i):
                continue
            item = self.files_table.item(i, 0)
            if item is not None:
                item.setCheckState(state)

    def _collect_checked_paths(self) -> list[str]:
        paths = []
        for i in range(self.files_table.rowCount()):
            item = self.files_table.item(i, 0)
            if item is not None and item.checkState() == Qt.Checked:
                paths.append(item.text())
        return paths

    def _start_restore(self) -> None:
        if self._repo is None:
            return
        sid = self._selected_snapshot_id()
        if sid is None:
            QMessageBox.information(self, "Heartbeat", "Pick a version first.")
            return
        snap = self._load_snapshot(sid)

        dest = QFileDialog.getExistingDirectory(self, "Restore to which folder?")
        if not dest:
            return

        checked = self._collect_checked_paths()
        if checked:
            confirm = QMessageBox.question(
                self, "Restore files",
                f"Restore {len(checked)} selected file(s) to\n{dest}?",
            )
            paths = checked
        else:
            confirm = QMessageBox.question(
                self, "Restore entire version",
                f"No files are ticked. Restore the entire version "
                f"({len(snap.entries)} files) to\n{dest}?",
            )
            paths = None
        if confirm != QMessageBox.Yes:
            return

        self._worker = RestoreWorker(
            repo=self._repo,
            snapshot_id=sid,
            dest=dest,
            paths=paths,
            overwrite=self.overwrite.isChecked(),
        )
        self._worker.progress.connect(self._on_progress, Qt.QueuedConnection)
        self._worker.finished.connect(self._on_finished, Qt.QueuedConnection)
        self._worker.failed.connect(self._on_failed, Qt.QueuedConnection)
        self.btn_restore.setEnabled(False)
        self.progress.setValue(0)
        self.progress_title.setText("Starting restore…")
        self.progress_detail.setText("")
        self.log_line.emit(f"Starting restore of {sid} → {dest}")
        self._thread = run_in_thread(self._worker)

    def _on_progress(self, p: dict) -> None:
        total = p.get("bytes_total") or 1
        done = p.get("bytes_done", 0)
        self.progress.setValue(int(100 * done / total))
        self.progress_title.setText(
            f"Restoring — {p.get('files_done', 0)} of {p.get('files_total', 0)} files"
        )
        cf = p.get("current_file", "")
        self.progress_detail.setText(cf or p.get("message", ""))

    def _on_finished(self, r: dict) -> None:
        self._cleanup_worker()
        self.btn_restore.setEnabled(True)
        self.progress.setValue(100)
        self.progress_title.setText("Restore complete")
        self.progress_detail.setText(
            f"{r['files']} files · {format_size(r['bytes'])} · "
            f"{r['duration_seconds']:.1f}s"
        )
        self.log_line.emit(f"Restored {r['files']} files.")
        if r.get("errors"):
            QMessageBox.warning(self, "Heartbeat",
                                f"Restore finished with {len(r['errors'])} "
                                "error(s). Check the activity log.")

    def _on_failed(self, msg: str) -> None:
        self._cleanup_worker()
        self.btn_restore.setEnabled(True)
        self.progress_title.setText("Restore failed")
        self.progress_detail.setText(msg)
        self.log_line.emit(f"Restore failed: {msg}")
        QMessageBox.critical(self, "Heartbeat", msg)

    def _cleanup_worker(self) -> None:
        if self._thread is not None:
            self._thread.deleteLater()
        if self._worker is not None:
            self._worker.deleteLater()
        self._worker = None
        self._thread = None


# ---------------------------------------------------------------------------
# Jobs tab (lightly polished — same logic)
# ---------------------------------------------------------------------------


class JobEditorDialog(QDialog):
    """Dialog for creating or editing a backup job.

    The dialog is split into three sections:
      1. **General** — job name, source folder, vault folder, backup mode.
      2. **Schedule** — four scheduling modes (manual, interval, daily, weekly).
      3. **Password** — prompt every time vs. save in the OS keychain.

    Every section lives inside a styled "card" (rounded rectangle) so the
    form never feels like a dense spreadsheet.

    Design patterns used:
      - QFormLayout for the label + field pairs (General section).
      - QRadioButton groups so exactly one option is selected per card.
      - QFileDialog.getExistingDirectory for native folder pickers.
      - Live validation: a helper label at the bottom updates as the user
        types, and the Save button stays disabled until all required fields
        are filled.
    """

    # Minimum width for text inputs so placeholders are readable.
    _INPUT_MIN_W = 280

    def __init__(self, parent: QWidget | None, job: BackupJob | None = None,
                 existing_jobs: list[BackupJob] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Job" if job else "New Job")
        self.setModal(True)
        # Wide enough that inputs don't get squished on any screen.
        self.setMinimumWidth(680)
        self._existing_jobs = existing_jobs or []

        # The entire dialog is wrapped in a QScrollArea so it can't
        # overflow the screen on small displays.
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        # Inner widget holds all the actual form content.
        inner = QWidget()
        outer = QVBoxLayout(inner)
        outer.setContentsMargins(28, 28, 28, 28)
        outer.setSpacing(18)

        # -- Heading -------------------------------------------------------
        heading = QLabel("Edit job" if job else "Create a new job")
        heading.setObjectName("h2")
        outer.addWidget(heading)
        intro = QLabel(
            "Jobs save a source and vault together so you can run the same "
            "backup again with one click. Schedule it to run automatically "
            "while the app is open."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        outer.addWidget(intro)

        # -- General card --------------------------------------------------
        general_card = _card()
        gc = QVBoxLayout(general_card)
        gc.setContentsMargins(22, 18, 22, 18)
        gc.setSpacing(12)

        gc_title = QLabel("General")
        gc_title.setObjectName("h3")
        gc.addWidget(gc_title)

        form = QFormLayout()
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignLeft)
        # Let the field column stretch to fill available space.
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        self.name_edit = QLineEdit(job.name if job else "")
        self.name_edit.setPlaceholderText("e.g. Documents — daily")
        self.name_edit.setMinimumWidth(self._INPUT_MIN_W)
        form.addRow(QLabel("Name"), self.name_edit)

        # Source row — text field + Browse button.
        self.source_edit = QLineEdit(job.source if job else "")
        self.source_edit.setPlaceholderText("Folder, drive, or network share")
        self.source_edit.setMinimumWidth(self._INPUT_MIN_W)
        src_row = self._path_row(self.source_edit, self._pick_source)
        form.addRow(QLabel("Source folder"), src_row)

        # Vault row — text field + Browse + optional "reuse from…" dropdown.
        self.repo_edit = QLineEdit(job.repo if job else "")
        self.repo_edit.setPlaceholderText("An empty folder, or an existing vault")
        self.repo_edit.setMinimumWidth(self._INPUT_MIN_W)
        vault_row = self._vault_row()
        form.addRow(QLabel("Vault folder"), vault_row)

        self.kind_combo = QComboBox()
        self.kind_combo.addItem("Quick (only changed files) — recommended", "incremental")
        self.kind_combo.addItem("Complete (re-check everything)", "full")
        self.kind_combo.setMinimumWidth(self._INPUT_MIN_W)
        if job and job.kind == "full":
            self.kind_combo.setCurrentIndex(1)
        form.addRow(QLabel("Mode"), self.kind_combo)

        self.ignore_hidden = QCheckBox("Ignore hidden files (names starting with '.')")
        if job:
            self.ignore_hidden.setChecked(job.ignore_hidden)
        form.addRow(QLabel(""), self.ignore_hidden)

        gc.addLayout(form)
        outer.addWidget(general_card)

        # -- Schedule card -------------------------------------------------
        outer.addWidget(self._build_schedule_card(job))

        # -- Password card -------------------------------------------------
        outer.addWidget(self._build_password_card(job))

        # -- Validation hint -----------------------------------------------
        self.hint = QLabel("")
        self.hint.setObjectName("helper")
        self.hint.setWordWrap(True)
        outer.addWidget(self.hint)

        # Debounce validation: _revalidate checks the filesystem
        # (Path.exists, iterdir) so we don't want it firing on every
        # keystroke — that would freeze the UI when typing paths to
        # large directories. A 300ms debounce timer restarts on each
        # key press and only fires once the user pauses.
        self._validate_timer = QTimer(self)
        self._validate_timer.setSingleShot(True)
        self._validate_timer.setInterval(300)
        self._validate_timer.timeout.connect(self._revalidate)
        self.name_edit.textChanged.connect(lambda: self._validate_timer.start())
        self.source_edit.textChanged.connect(lambda: self._validate_timer.start())
        self.repo_edit.textChanged.connect(lambda: self._validate_timer.start())

        # -- Dialog buttons ------------------------------------------------
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.ok_btn = buttons.button(QDialogButtonBox.Ok)
        self.ok_btn.setText("Save job")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

        scroll.setWidget(inner)

        # The QDialog's own layout just holds the scroll area.
        dlg_layout = QVBoxLayout(self)
        dlg_layout.setContentsMargins(0, 0, 0, 0)
        dlg_layout.addWidget(scroll)

        self._revalidate()

    # ------------------------------------------------------------------
    # Row builders — small helper methods that create the composite input
    # rows used in the General card (text field + Browse button).
    # ------------------------------------------------------------------

    def _path_row(self, edit: QLineEdit, browse_slot) -> QWidget:
        """Text field + Browse button in a horizontal row."""
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        h.addWidget(edit, 1)   # stretch=1 → field grows
        btn = QPushButton("Browse…")
        btn.setObjectName("ghost")
        btn.clicked.connect(browse_slot)
        h.addWidget(btn)
        return w

    def _vault_row(self) -> QWidget:
        """Vault path field + Browse button + optional "reuse vault" dropdown."""
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        h.addWidget(self.repo_edit, 1)
        btn = QPushButton("Browse…")
        btn.setObjectName("ghost")
        btn.clicked.connect(self._pick_vault)
        h.addWidget(btn)

        # If the user already has jobs, offer a dropdown to reuse a vault
        # from one of them — saves re-typing the path.
        reuse_combo = QComboBox()
        reuse_combo.addItem("Use vault from…", "")
        seen: set[str] = set()
        for j in self._existing_jobs:
            if j.repo and j.repo not in seen:
                reuse_combo.addItem(f"{j.name} — {j.repo}", j.repo)
                seen.add(j.repo)
        if reuse_combo.count() > 1:
            reuse_combo.setMinimumWidth(160)
            reuse_combo.currentIndexChanged.connect(
                lambda _: (self.repo_edit.setText(reuse_combo.currentData() or "")
                           if reuse_combo.currentIndex() > 0 else None)
            )
            h.addWidget(reuse_combo)
        return w

    # ------------------------------------------------------------------
    # File-picker slots
    # ------------------------------------------------------------------

    def _pick_source(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose source folder")
        if d:
            self.source_edit.setText(d)

    def _pick_vault(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose vault folder")
        if d:
            self.repo_edit.setText(d)

    # ------------------------------------------------------------------
    # Live validation — the hint label updates as the user types.
    # ------------------------------------------------------------------

    def _revalidate(self) -> None:
        name = self.name_edit.text().strip()
        src = self.source_edit.text().strip()
        repo = self.repo_edit.text().strip()
        messages = []
        if not name:
            messages.append("Give the job a memorable name.")
        if src and not Path(src).exists():
            messages.append("Source folder doesn't exist yet.")
        if repo:
            if (Path(repo) / "repo.json").exists():
                messages.append("Vault detected — backups will be added to this vault.")
            elif Path(repo).exists() and next(Path(repo).iterdir(), None) is not None:
                messages.append("Vault folder isn't empty and isn't a vault — choose an empty folder.")
            else:
                messages.append("New vault will be created here on first run.")
        self.hint.setText("  ·  ".join(messages))
        # "Save job" stays disabled until all required fields are filled.
        self.ok_btn.setEnabled(bool(name and src and repo))

    def _accept(self) -> None:
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Heartbeat", "Give the job a name.")
            return
        if not self.source_edit.text().strip() or not self.repo_edit.text().strip():
            QMessageBox.warning(self, "Heartbeat", "Source and vault are both required.")
            return
        self.accept()

    # ------------------------------------------------------------------
    # to_job / pending_password — read the dialog state back out
    # ------------------------------------------------------------------

    def to_job(self, existing: BackupJob | None = None) -> BackupJob:
        """Build a BackupJob from the current dialog state.

        If `existing` is given, update it in-place (preserves last_run,
        last_snapshot, etc.). Otherwise create a fresh job.
        """
        base = existing or BackupJob(name="", source="", repo="")
        base.name = self.name_edit.text().strip()
        base.source = self.source_edit.text().strip()
        base.repo = self.repo_edit.text().strip()
        base.kind = self.kind_combo.currentData()
        base.ignore_hidden = self.ignore_hidden.isChecked()
        base.schedule = self._collect_schedule()
        base.save_password = (self.rb_pw_save.isChecked()
                              and secret_store.is_available())
        return base

    def pending_password(self) -> str | None:
        """Return the password the user typed (for keychain storage), or None."""
        if self.rb_pw_save.isChecked() and self.pw_edit.text():
            return self.pw_edit.text()
        return None

    # ------------------------------------------------------------------
    # Schedule card — four radio modes with inline controls.
    # ------------------------------------------------------------------

    def _build_schedule_card(self, job: BackupJob | None) -> QWidget:
        """Build the Schedule card with four radio-selected modes.

        Layout:
            (o) Manual — only when I click Run
            (o) Every  [ 30 ▼ ] [ minutes ▼ ]
            (o) Daily at  [ 09:00 ]
            (o) Weekly on  [Mon] [Tue] … [Sun]  at [ 09:00 ]

        Controls that belong to an unselected mode are greyed out so the
        user can see all options at a glance without confusion.
        """
        card = _card()
        v = QVBoxLayout(card)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(12)

        title = QLabel("Schedule")
        title.setObjectName("h3")
        v.addWidget(title)
        hint = QLabel(
            "Choose when Heartbeat should run this job while the app is open."
        )
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        v.addWidget(hint)

        sched = job.schedule if job else Schedule()

        # -- Radio buttons for the four schedule modes ---------------------
        self.rb_manual = QRadioButton("Manual — only when I click Run")
        self.rb_interval = QRadioButton("Every")
        self.rb_daily = QRadioButton("Daily at")
        self.rb_weekly = QRadioButton("Weekly on")
        for rb in (self.rb_manual, self.rb_interval, self.rb_daily, self.rb_weekly):
            rb.toggled.connect(self._sync_schedule_controls)

        # -- Interval controls: spin box (value) + combo (unit) ------------
        iv_row = QHBoxLayout()
        iv_row.setContentsMargins(30, 0, 0, 0)
        iv_row.setSpacing(8)
        self.iv_spin = QSpinBox()
        self.iv_spin.setRange(1, 10_000)
        self.iv_spin.setMinimumWidth(90)
        self.iv_spin.setValue(max(1, sched.interval_value or 30))
        self.iv_unit = QComboBox()
        self.iv_unit.setMinimumWidth(110)
        for label, key in (("minutes", "minutes"), ("hours", "hours"), ("days", "days")):
            self.iv_unit.addItem(label, key)
        if sched.interval_unit in ("minutes", "hours", "days"):
            self.iv_unit.setCurrentIndex(
                {"minutes": 0, "hours": 1, "days": 2}[sched.interval_unit])
        iv_row.addWidget(self.iv_spin)
        iv_row.addWidget(self.iv_unit)
        iv_row.addStretch(1)

        # -- Daily controls: time picker -----------------------------------
        daily_row = QHBoxLayout()
        daily_row.setContentsMargins(30, 0, 0, 0)
        self.daily_time = QTimeEdit()
        self.daily_time.setDisplayFormat("hh:mm AP")
        self.daily_time.setMinimumWidth(120)
        self.daily_time.setTime(_time_from_str(sched.time_of_day))
        daily_row.addWidget(self.daily_time)
        daily_row.addStretch(1)

        # -- Weekly controls: day checkboxes + time picker -----------------
        # Two rows inside a VBox: day buttons on top, "at HH:MM" below.
        weekly_container = QVBoxLayout()
        weekly_container.setContentsMargins(30, 0, 0, 0)
        weekly_container.setSpacing(8)

        days_row = QHBoxLayout()
        days_row.setSpacing(6)
        self.weekday_boxes: list[QCheckBox] = []
        for i, name in enumerate(WEEKDAY_NAMES):
            cb = QCheckBox(name)
            cb.setChecked(i in (sched.weekdays or []))
            self.weekday_boxes.append(cb)
            days_row.addWidget(cb)
        days_row.addStretch(1)

        time_row = QHBoxLayout()
        time_row.setSpacing(8)
        time_row.addWidget(QLabel("at"))
        self.weekly_time = QTimeEdit()
        self.weekly_time.setDisplayFormat("hh:mm AP")
        self.weekly_time.setMinimumWidth(120)
        self.weekly_time.setTime(_time_from_str(sched.time_of_day))
        time_row.addWidget(self.weekly_time)
        time_row.addStretch(1)

        weekly_container.addLayout(days_row)
        weekly_container.addLayout(time_row)

        # -- Assemble into the card layout ---------------------------------
        v.addWidget(self.rb_manual)
        v.addSpacing(2)
        v.addWidget(self.rb_interval)
        v.addLayout(iv_row)
        v.addSpacing(2)
        v.addWidget(self.rb_daily)
        v.addLayout(daily_row)
        v.addSpacing(2)
        v.addWidget(self.rb_weekly)
        v.addLayout(weekly_container)

        # Pre-select the radio that matches the current schedule.
        {
            "manual": self.rb_manual,
            "interval": self.rb_interval,
            "daily": self.rb_daily,
            "weekly": self.rb_weekly,
        }.get(sched.kind, self.rb_manual).setChecked(True)
        self._sync_schedule_controls()

        return card

    def _sync_schedule_controls(self) -> None:
        """Enable only the controls that belong to the selected schedule mode.

        This is wired to every radio button's `toggled` signal so it runs
        each time the user changes their selection.
        """
        self.iv_spin.setEnabled(self.rb_interval.isChecked())
        self.iv_unit.setEnabled(self.rb_interval.isChecked())
        self.daily_time.setEnabled(self.rb_daily.isChecked())
        self.weekly_time.setEnabled(self.rb_weekly.isChecked())
        for cb in self.weekday_boxes:
            cb.setEnabled(self.rb_weekly.isChecked())

    def _collect_schedule(self) -> Schedule:
        """Read the current radio + widget state into a Schedule dataclass."""
        if self.rb_interval.isChecked():
            return Schedule(
                kind="interval",
                interval_value=self.iv_spin.value(),
                interval_unit=self.iv_unit.currentData() or "minutes",
            )
        if self.rb_daily.isChecked():
            return Schedule(kind="daily",
                            time_of_day=self.daily_time.time().toString("HH:mm"))
        if self.rb_weekly.isChecked():
            days = [i for i, cb in enumerate(self.weekday_boxes) if cb.isChecked()]
            return Schedule(kind="weekly",
                            time_of_day=self.weekly_time.time().toString("HH:mm"),
                            weekdays=days)
        return Schedule(kind="manual")

    # ------------------------------------------------------------------
    # Password card — prompt vs. save in the OS keychain.
    # ------------------------------------------------------------------

    def _build_password_card(self, job: BackupJob | None) -> QWidget:
        """Build the Password card.

        Two radio options:
          - Prompt every time (safe default).
          - Save in the system keychain (macOS Keychain / Windows Credential
            Manager / Linux Secret Service) for unattended scheduled runs.

        If `keyring` reports no usable backend, the "save" option is greyed
        out and a notice explains why.
        """
        card = _card()
        v = QVBoxLayout(card)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(12)

        title = QLabel("Password")
        title.setObjectName("h3")
        v.addWidget(title)

        available = secret_store.is_available()
        desc = (
            "Prompt every time for safety, or save the vault password in "
            "the system keychain so the scheduler can run this job "
            "unattended."
        )
        if not available:
            desc += ("\n\nYour OS keychain isn't available, so password "
                     "saving is disabled. Heartbeat will always prompt.")
        d = QLabel(desc)
        d.setObjectName("muted")
        d.setWordWrap(True)
        v.addWidget(d)

        self.rb_pw_prompt = QRadioButton("Prompt me every time (recommended)")
        self.rb_pw_save = QRadioButton(
            "Save password in system keychain for unattended runs")
        self.rb_pw_save.setEnabled(available)
        v.addWidget(self.rb_pw_prompt)
        v.addWidget(self.rb_pw_save)

        # Password input — only enabled when "save" is selected.
        pw_row = QHBoxLayout()
        pw_row.setContentsMargins(30, 0, 0, 0)
        self.pw_edit = QLineEdit()
        self.pw_edit.setEchoMode(QLineEdit.Password)
        self.pw_edit.setMinimumWidth(self._INPUT_MIN_W)
        existing_pw = secret_store.get_password(job.name) if (job and job.save_password) else None
        if existing_pw:
            self.pw_edit.setPlaceholderText("Password is stored — leave blank to keep it")
        else:
            self.pw_edit.setPlaceholderText("Vault password")
        pw_row.addWidget(self.pw_edit, 1)
        self.pw_edit.setEnabled(False)
        v.addLayout(pw_row)

        def _sync_pw():
            self.pw_edit.setEnabled(self.rb_pw_save.isChecked())
        self.rb_pw_save.toggled.connect(lambda _=None: _sync_pw())

        if job and job.save_password and available:
            self.rb_pw_save.setChecked(True)
        else:
            self.rb_pw_prompt.setChecked(True)
        _sync_pw()

        return card


class JobsTab(QWidget):
    log_line = Signal(str)
    run_requested = Signal(BackupJob)
    jobs_changed = Signal()

    def __init__(self, config: AppConfig, store: ConfigStore,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.config = config
        self.store = store
        self._build()
        self._refresh()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Intro card — what Jobs are and why.
        intro_card = _card()
        v = QVBoxLayout(intro_card)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(8)
        h = QLabel("Saved jobs")
        h.setObjectName("h2")
        v.addWidget(h)
        v.addWidget(_helper_text(
            "A job pairs a source folder with a vault. Select any row to edit, "
            "delete, or run it. Schedule a job to repeat automatically while "
            "the app is open."
        ))
        layout.addWidget(intro_card)

        # Main card — table of jobs + empty state.
        self.main_card = _card()
        mv = QVBoxLayout(self.main_card)
        mv.setContentsMargins(22, 18, 22, 18)
        mv.setSpacing(10)

        self.stack = QStackedWidget()

        # Empty state.
        empty = QWidget()
        ev = QVBoxLayout(empty)
        ev.setContentsMargins(0, 32, 0, 32)
        ev.setSpacing(8)
        title = QLabel("No jobs yet")
        title.setObjectName("h2")
        title.setAlignment(Qt.AlignCenter)
        ev.addWidget(title)
        sub = QLabel("Create a job to run a backup with one click or on a schedule.")
        sub.setObjectName("muted")
        sub.setAlignment(Qt.AlignCenter)
        sub.setWordWrap(True)
        ev.addWidget(sub)
        ev.addSpacing(8)
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_new_empty = QPushButton("Create your first job")
        btn_new_empty.clicked.connect(self._new)
        btn_row.addWidget(btn_new_empty)
        btn_row.addStretch(1)
        ev.addLayout(btn_row)
        self.stack.addWidget(empty)

        # Table.
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Source", "Vault", "Schedule", "Last run"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        h.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.setMinimumHeight(200)
        self.table.doubleClicked.connect(lambda _: self._edit())
        self.table.itemSelectionChanged.connect(self._update_action_state)
        self.stack.addWidget(self.table)

        mv.addWidget(self.stack, 1)

        row = QHBoxLayout()
        self.btn_new = QPushButton("New job…")
        self.btn_edit = QPushButton("Edit…")
        self.btn_edit.setObjectName("ghost")
        self.btn_delete = QPushButton("Delete")
        self.btn_delete.setObjectName("ghost")
        self.btn_run = QPushButton("Run now")
        self.btn_new.clicked.connect(self._new)
        self.btn_edit.clicked.connect(self._edit)
        self.btn_delete.clicked.connect(self._delete)
        self.btn_run.clicked.connect(self._run_clicked)
        row.addWidget(self.btn_new)
        row.addWidget(self.btn_edit)
        row.addWidget(self.btn_delete)
        row.addStretch(1)
        row.addWidget(self.btn_run)
        mv.addLayout(row)

        layout.addWidget(self.main_card, 1)

    def _refresh(self) -> None:
        if not self.config.jobs:
            self.stack.setCurrentIndex(0)
            self._update_action_state()
            return
        self.stack.setCurrentIndex(1)
        self.table.setRowCount(len(self.config.jobs))
        for i, j in enumerate(self.config.jobs):
            sched = j.schedule.describe()
            mode = "Quick" if j.kind == "incremental" else "Complete"
            items = [
                QTableWidgetItem(j.name),
                QTableWidgetItem(j.source),
                QTableWidgetItem(j.repo),
                QTableWidgetItem(f"{mode} · {sched}"),
                QTableWidgetItem(format_timestamp(j.last_run)),
            ]
            # Show the full path on hover for truncated cells.
            items[1].setToolTip(j.source)
            items[2].setToolTip(j.repo)
            for col, it in enumerate(items):
                self.table.setItem(i, col, it)
        self.table.resizeRowsToContents()
        self._update_action_state()

    def _update_action_state(self) -> None:
        has_sel = self._selected_job() is not None
        self.btn_edit.setEnabled(has_sel)
        self.btn_delete.setEnabled(has_sel)
        self.btn_run.setEnabled(has_sel)

    def _selected_job(self) -> BackupJob | None:
        if not self.config.jobs:
            return None
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            return None
        i = rows[0].row()
        if i < 0 or i >= len(self.config.jobs):
            return None
        return self.config.jobs[i]

    def _new(self) -> None:
        dlg = JobEditorDialog(self, existing_jobs=self.config.jobs)
        if dlg.exec() == QDialog.Accepted:
            job = dlg.to_job()
            if self.config.find(job.name):
                QMessageBox.warning(self, "Heartbeat", "A job with that name already exists.")
                return
            self._persist_job_password(job, dlg.pending_password())
            self.config.upsert(job)
            self.store.save(self.config)
            self._refresh()
            self.jobs_changed.emit()

    def _edit(self) -> None:
        job = self._selected_job()
        if not job:
            return
        others = [j for j in self.config.jobs if j.name != job.name]
        dlg = JobEditorDialog(self, job, existing_jobs=others)
        if dlg.exec() == QDialog.Accepted:
            updated = dlg.to_job(existing=job)
            self._persist_job_password(updated, dlg.pending_password())
            self.config.upsert(updated)
            self.store.save(self.config)
            self._refresh()
            self.jobs_changed.emit()

    def _persist_job_password(self, job: BackupJob, new_password: str | None) -> None:
        """Sync job.save_password + the OS keychain entry.

        If save_password is off, scrub any existing keychain entry. If it's on
        and the user typed a new password, store it; if left blank, keep
        whatever was already saved.
        """
        if not job.save_password:
            secret_store.delete_password(job.name)
            return
        if new_password:
            if not secret_store.set_password(job.name, new_password):
                QMessageBox.warning(
                    self, "Heartbeat",
                    "Could not save the password to the system keychain. "
                    "The job will prompt for a password at run time.",
                )
                job.save_password = False

    def _delete(self) -> None:
        job = self._selected_job()
        if not job:
            return
        if QMessageBox.question(
            self, "Delete job", f"Delete '{job.name}'?\n(The vault itself is not deleted.)"
        ) != QMessageBox.Yes:
            return
        secret_store.delete_password(job.name)
        self.config.remove(job.name)
        self.store.save(self.config)
        self._refresh()
        self.jobs_changed.emit()

    def _run_clicked(self) -> None:
        job = self._selected_job()
        if not job:
            return
        self.run_requested.emit(job)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------


class MainWindow(QMainWindow):
    """Top-level window: owns all tabs, the activity log, the scheduler,
    the menu bar, and the system tray icon.

    Threading model:
      - The scheduler runs on a Python daemon thread. When a job fires,
        it emits the ``_scheduled_fire`` Qt Signal below. Qt auto-delivers
        cross-thread signals on the receiver's event loop, so the actual
        backup work starts on the UI thread (which then launches a QThread
        worker to keep the UI responsive).
      - Manual backups also run on QThread workers, with progress sent
        back to the UI via Qt Signals using QueuedConnection.
    """

    # Signal to bounce scheduled backups from the scheduler's background
    # thread onto the UI thread (Qt handles the cross-thread delivery).
    _scheduled_fire = Signal(BackupJob, str)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Heartbeat")
        self.setWindowIcon(make_app_icon())
        self.setStyleSheet(STYLESHEET)

        # Responsive sizing: fit 90% of the available screen on first open,
        # but don't exceed our preferred 1040×760, and never go below a size
        # that would cause crucial controls to be clipped. The QScrollAreas
        # around each tab make smaller sizes usable.
        screen = QGuiApplication.primaryScreen().availableGeometry()
        preferred_w, preferred_h = 1040, 760
        width = min(preferred_w, int(screen.width() * 0.9))
        height = min(preferred_h, int(screen.height() * 0.9))
        self.resize(width, height)
        self.setMinimumSize(720, 540)

        self.store = ConfigStore()
        self.config = self.store.load()

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        # Header.
        header = QHBoxLayout()
        header.setSpacing(12)
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title = QLabel("Heartbeat")
        title.setObjectName("h1")
        subtitle = QLabel("Encrypted backups for folders, drives, and network shares.")
        subtitle.setObjectName("muted")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch(1)

        right_box = QVBoxLayout()
        right_box.setSpacing(8)
        right_box.setAlignment(Qt.AlignRight | Qt.AlignTop)
        btn_help = QPushButton("How does this work?")
        btn_help.setObjectName("ghost")
        btn_help.clicked.connect(self._show_help)
        right_box.addWidget(btn_help, 0, Qt.AlignRight)
        encryption_badge = _badge(ENCRYPTION_LABEL)
        encryption_badge.setToolTip(
            "All data written to vaults is encrypted with AES-256-GCM. "
            "Your password is stretched into an encryption key with "
            f"PBKDF2-HMAC-SHA256 at {crypto.DEFAULT_ITERATIONS:,} iterations."
        )
        right_box.addWidget(encryption_badge, 0, Qt.AlignRight)
        header.addLayout(right_box)
        root.addLayout(header)

        # Tabs — each wrapped in a scroll area so the window can shrink
        # without clipping. Restore has its own inner scrollable tables, but
        # wrapping it is still useful when the window height is very small.
        self.tabs = QTabWidget()
        self.home_tab = HomeTab(self.config)
        self.backup_tab = BackupTab()
        self.restore_tab = RestoreTab()
        self.jobs_tab = JobsTab(self.config, self.store)
        self.tabs.addTab(_scroll_wrap(self.home_tab), "Home")
        self.tabs.addTab(_scroll_wrap(self.backup_tab), "Backup")
        self.tabs.addTab(_scroll_wrap(self.restore_tab), "Restore")
        self.tabs.addTab(_scroll_wrap(self.jobs_tab), "Jobs")
        root.addWidget(self.tabs, 1)

        # Activity log — compact, collapsible by default height.
        log_card = _card()
        lv = QVBoxLayout(log_card)
        lv.setContentsMargins(14, 10, 14, 10)
        lv.setSpacing(6)
        header_row = QHBoxLayout()
        h = QLabel("Activity")
        h.setStyleSheet("font-weight: 600;")
        header_row.addWidget(h)
        header_row.addStretch(1)
        btn_clear = QPushButton("Clear")
        btn_clear.setObjectName("link")
        btn_clear.clicked.connect(lambda: self.log_view.clear())
        header_row.addWidget(btn_clear)
        lv.addLayout(header_row)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Menlo", 10))
        self.log_view.setFixedHeight(110)
        lv.addWidget(self.log_view)
        root.addWidget(log_card)

        self.setCentralWidget(central)

        # Wire signals.
        # The tabs hold scroll-area wrappers, not the tab widgets directly,
        # so we navigate by index instead of setCurrentWidget.
        self.home_tab.go_backup.connect(lambda: self.tabs.setCurrentIndex(TAB_BACKUP))
        self.home_tab.go_restore.connect(lambda: self.tabs.setCurrentIndex(TAB_RESTORE))
        self.home_tab.go_jobs.connect(lambda: self.tabs.setCurrentIndex(TAB_JOBS))
        self.home_tab.open_help.connect(self._show_help)

        self.backup_tab.log_line.connect(self._append_log)
        self.restore_tab.log_line.connect(self._append_log)
        self.jobs_tab.log_line.connect(self._append_log)
        self.jobs_tab.run_requested.connect(self._run_job_from_tab)
        self.jobs_tab.jobs_changed.connect(self.home_tab.refresh)

        # Poll library logs into the activity view.
        self._log_timer = QTimer(self)
        self._log_timer.timeout.connect(self._drain_memory_log)
        self._log_timer.start(500)

        self._sched_worker = None
        self._sched_thread = None
        self.scheduler = Scheduler(self.config, runner=self._scheduled_run)
        self._scheduled_fire.connect(self._fire_scheduled_backup)
        self.scheduler.start()

        # Menu bar — built last so it can reference tabs/dialogs.
        self._build_menu_bar()

        # System-tray icon — sits in the macOS menu bar / Windows system tray.
        self._build_tray_icon()

        # First-run hint.
        if not self.config.jobs:
            QTimer.singleShot(0, lambda: self.tabs.setCurrentIndex(TAB_HOME))

    # --- menu bar ---

    def _build_menu_bar(self) -> None:
        """Build the application menu bar.

        On macOS, Qt merges standard actions (Quit, About, Preferences) into
        the native application menu based on each action's MenuRole. On
        Windows/Linux the same menus appear as a traditional menu bar under
        the title bar.
        """
        mbar = self.menuBar()
        # On macOS make sure the menu bar shows up globally, not inside the
        # window. (This is the default, but setting it explicitly avoids
        # surprises if the app is ever embedded.)
        mbar.setNativeMenuBar(True)

        # --- File --------------------------------------------------------
        file_menu = mbar.addMenu("&File")

        act_new_backup = QAction("&New Backup", self)
        act_new_backup.setShortcut(QKeySequence.New)          # Cmd/Ctrl+N
        act_new_backup.triggered.connect(
            lambda: self.tabs.setCurrentIndex(TAB_BACKUP))
        file_menu.addAction(act_new_backup)

        act_open_vault = QAction("&Open Vault…", self)
        act_open_vault.setShortcut(QKeySequence.Open)         # Cmd/Ctrl+O
        act_open_vault.triggered.connect(
            lambda: self.tabs.setCurrentIndex(TAB_RESTORE))
        file_menu.addAction(act_open_vault)

        file_menu.addSeparator()

        act_close = QAction("&Close Window", self)
        act_close.setShortcut(QKeySequence.Close)             # Cmd/Ctrl+W
        act_close.triggered.connect(self.close)
        file_menu.addAction(act_close)

        act_quit = QAction("&Quit Heartbeat", self)
        act_quit.setShortcut(QKeySequence.Quit)               # Cmd/Ctrl+Q
        act_quit.setMenuRole(QAction.QuitRole)                # native app menu on macOS
        act_quit.triggered.connect(QGuiApplication.quit)
        file_menu.addAction(act_quit)

        # --- View --------------------------------------------------------
        view_menu = mbar.addMenu("&View")
        for idx, label, seq in (
            (TAB_HOME,    "&Home",    "Ctrl+1"),
            (TAB_BACKUP,  "&Backup",  "Ctrl+2"),
            (TAB_RESTORE, "&Restore", "Ctrl+3"),
            (TAB_JOBS,    "&Jobs",    "Ctrl+4"),
        ):
            act = QAction(label, self)
            # Qt automatically translates Ctrl → Cmd on macOS.
            act.setShortcut(QKeySequence(seq))
            act.triggered.connect(lambda _checked=False, i=idx: self.tabs.setCurrentIndex(i))
            view_menu.addAction(act)

        # --- Window ------------------------------------------------------
        window_menu = mbar.addMenu("&Window")

        act_toggle = QAction("&Show / Hide Window", self)
        act_toggle.setShortcut(QKeySequence("Ctrl+Shift+H"))
        act_toggle.triggered.connect(self._toggle_visibility)
        window_menu.addAction(act_toggle)

        act_show = QAction("Bring to &Front", self)
        act_show.triggered.connect(self._bring_to_front)
        window_menu.addAction(act_show)

        act_minimize = QAction("Mi&nimize", self)
        act_minimize.setShortcut(QKeySequence("Ctrl+M"))
        act_minimize.triggered.connect(self.showMinimized)
        window_menu.addAction(act_minimize)

        # --- Help --------------------------------------------------------
        help_menu = mbar.addMenu("&Help")

        act_how = QAction("How Heartbeat &works", self)
        act_how.triggered.connect(self._show_help)
        help_menu.addAction(act_how)

        act_about = QAction("&About Heartbeat", self)
        act_about.setMenuRole(QAction.AboutRole)              # native app menu on macOS
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    def _build_tray_icon(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self._tray = QSystemTrayIcon(make_app_icon(), self)
        self._tray.setToolTip("Heartbeat")
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _on_tray_activated(self, reason) -> None:
        self._toggle_visibility()

    def _toggle_visibility(self) -> None:
        """Toggle the main window between visible and hidden.

        When hidden the scheduler keeps running in the background, so
        scheduled backups still fire. The user can bring the window back
        from the menu bar (macOS) or the taskbar (Windows/Linux).
        """
        if self.isVisible() and not self.isMinimized():
            self.hide()
        else:
            self._bring_to_front()

    def _bring_to_front(self) -> None:
        """Restore + focus the main window."""
        if self.isMinimized():
            self.showNormal()
        else:
            self.show()
        self.raise_()
        self.activateWindow()

    def _show_about(self) -> None:
        from .. import __version__
        QMessageBox.about(
            self, "About Heartbeat",
            f"<h3>Heartbeat {__version__}</h3>"
            "<p>Encrypted, versioned backups for folders, drives, and network "
            "shares.</p>"
            f"<p><b>Encryption:</b> {ENCRYPTION_LABEL}.</p>"
            "<p style='color:#9aa3b0'>A small desktop backup tool.</p>",
        )

    # --- header help ---

    def _show_help(self) -> None:
        HelpDialog(self).exec()

    # --- logs ---

    def _append_log(self, line: str) -> None:
        self.log_view.append(line)

    def _drain_memory_log(self) -> None:
        lines = memory_handler().drain()
        # Library logs are technical — strip the leading boilerplate for readability.
        for line in lines:
            # "2026-04-22 18:07:12 [INFO] heartbeat.repository: xxx" → "xxx"
            short = line
            if "] " in line:
                short = line.split("] ", 1)[-1]
            if ": " in short:
                short = short.split(": ", 1)[-1]
            self.log_view.append(short)

    # --- job execution ---

    def _run_job_from_tab(self, job: BackupJob) -> None:
        pw = secret_store.get_password(job.name) if job.save_password else None
        if pw is None:
            pw = PasswordDialog.ask(self, vault_name=f"'{job.name}' — {job.repo}")
        if pw is None:
            return
        try:
            repo = Repository.open(Path(job.repo), pw)
        except RepositoryError as e:
            QMessageBox.critical(self, "Heartbeat", str(e))
            return

        self.tabs.setCurrentIndex(TAB_BACKUP)
        self.backup_tab.source_edit.setText(job.source)
        self.backup_tab.repo_edit.setText(job.repo)
        if job.kind == "full":
            self.backup_tab.rb_full.setChecked(True)
        else:
            self.backup_tab.rb_quick.setChecked(True)
        self.backup_tab.ignore_hidden.setChecked(job.ignore_hidden)

        worker = BackupWorker(repo, job.source, job.kind, ignore_hidden=job.ignore_hidden)
        worker.progress.connect(self.backup_tab._on_progress, Qt.QueuedConnection)
        worker.finished.connect(lambda r, j=job: self._on_job_done(j, r), Qt.QueuedConnection)
        worker.finished.connect(self.backup_tab._on_finished, Qt.QueuedConnection)
        worker.failed.connect(self.backup_tab._on_failed, Qt.QueuedConnection)
        self.backup_tab.btn_backup.setEnabled(False)
        self.backup_tab.btn_cancel.setEnabled(True)
        self.backup_tab._worker = worker
        self.backup_tab._thread = run_in_thread(worker)

    def _on_job_done(self, job: BackupJob, result: dict) -> None:
        job.last_run = time.time()
        job.last_snapshot = result.get("snapshot_id", "")
        self.store.save(self.config)
        self.jobs_tab._refresh()
        self.home_tab.refresh()

    def _scheduled_run(self, job: BackupJob, password: str | None) -> None:
        """Called on the scheduler thread. Bounce onto the UI thread to
        actually open the vault and start the backup worker."""
        if password is None:
            log.info("Scheduler skipped '%s' — no stored password.", job.name)
            job.last_run = time.time()
            return
        # Qt auto-delivers cross-thread signals via the target's event loop.
        self._scheduled_fire.emit(job, password)

    def _fire_scheduled_backup(self, job: BackupJob, password: str) -> None:
        """UI-thread handler: run a scheduled job in the background.

        Unlike _run_job_from_tab this does NOT take over the Backup tab UI —
        it creates its own worker and thread so the user can keep using the
        app while the scheduled backup runs silently.

        Thread lifecycle: the worker's finished/failed signals tell us the
        result, but we must NOT drop the QThread reference until the thread
        has fully stopped. We connect the thread's own ``finished`` signal
        (emitted after quit() completes) to ``_sched_cleanup`` which nulls
        the references and calls deleteLater().
        """
        try:
            repo = Repository.open(Path(job.repo), password)
        except RepositoryError as e:
            log.error("Scheduled job '%s' could not open vault: %s", job.name, e)
            return

        if getattr(self, "_sched_worker", None) is not None:
            log.info("Skipping scheduled run of '%s' — another scheduled "
                     "backup is still in progress.", job.name)
            return

        self._append_log(f"Scheduler: starting '{job.name}'…")

        worker = BackupWorker(repo, job.source, job.kind,
                              ignore_hidden=job.ignore_hidden)
        # QueuedConnection: the worker emits from its QThread, but our
        # slots touch UI widgets which must only be accessed from the
        # main thread. Without this, macOS aborts with
        # "NSWindow should only be instantiated on the main thread".
        worker.finished.connect(
            lambda r, j=job: self._on_sched_done(j, r), Qt.QueuedConnection)
        worker.failed.connect(
            lambda msg, j=job: self._on_sched_failed(j, msg), Qt.QueuedConnection)

        self._sched_worker = worker
        self._sched_thread = run_in_thread(worker)

        # Only drop references once the thread has fully exited.
        self._sched_thread.finished.connect(self._sched_cleanup)

    def _sched_cleanup(self) -> None:
        """Release the scheduled-backup worker and thread after the thread
        has fully stopped. Using deleteLater() is the Qt-safe way to destroy
        QObjects that live on another thread."""
        if self._sched_thread is not None:
            self._sched_thread.deleteLater()
        if self._sched_worker is not None:
            self._sched_worker.deleteLater()
        self._sched_worker = None
        self._sched_thread = None

    def _on_sched_done(self, job: BackupJob, result: dict) -> None:
        self._on_job_done(job, result)
        self._append_log(
            f"Scheduler: '{job.name}' done — {result.get('files', 0)} files, "
            f"{result.get('new_objects', 0)} new."
        )

    def _on_sched_failed(self, job: BackupJob, msg: str) -> None:
        log.error("Scheduled job '%s' failed: %s", job.name, msg)
        self._append_log(f"Scheduler: '{job.name}' failed — {msg}")

    def closeEvent(self, event) -> None:  # noqa: N802
        self.scheduler.stop()
        if hasattr(self, "_tray"):
            self._tray.hide()
        if self._sched_thread is not None:
            self._sched_thread.quit()
            self._sched_thread.wait(5000)
        super().closeEvent(event)
