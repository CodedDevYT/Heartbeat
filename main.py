"""Heartbeat — entry point.

This script is the single entry point for both the graphical UI and the
command-line interface:

    heartbeat                                       # GUI (default)
    heartbeat --cli init /path/to/repo              # CLI — create vault
    heartbeat --cli backup /path/to/repo /src       # CLI — run backup
    heartbeat --cli snapshots /path/to/repo         # CLI — list versions
    heartbeat --cli restore /repo <id> /dest        # CLI — restore files

The GUI depends on PySide6. If PySide6 isn't installed the script prints a
friendly error message instead of a traceback, and suggests the CLI fallback.
"""

from __future__ import annotations

import sys
from pathlib import Path

from heartbeat.logger import configure


def run_ui() -> int:
    """Launch the graphical PySide6 interface.

    PySide6 is imported inside this function (not at the top of the
    file) so that the CLI mode can work even if PySide6 isn't installed.
    """
    from PySide6.QtWidgets import QApplication

    from heartbeat import __version__
    from heartbeat.ui.main_window import MainWindow
    from heartbeat.ui.utils import make_app_icon

    app = QApplication(sys.argv)
    # Identity shown in the macOS menu bar, Windows taskbar, Linux dock.
    app.setApplicationName("Heartbeat")
    app.setApplicationDisplayName("Heartbeat")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("Heartbeat")
    app.setWindowIcon(make_app_icon())

    window = MainWindow()
    window.show()
    return app.exec()


def main(argv: list[str]) -> int:
    # Log to ~/.heartbeat/heartbeat.log so errors during UI runs are recoverable.
    log_file = Path.home() / ".heartbeat" / "heartbeat.log"
    configure(log_file=log_file)

    if len(argv) > 1 and argv[1] == "--cli":
        from heartbeat.cli import main as cli_main
        return cli_main(argv[2:])

    try:
        return run_ui()
    except ImportError as e:
        print(
            "PySide6 is not installed. Install with:\n"
            "    pip install -r requirements.txt\n"
            "…or run Heartbeat in CLI mode with:  heartbeat --cli <command>",
            file=sys.stderr,
        )
        print(f"(underlying error: {e})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
