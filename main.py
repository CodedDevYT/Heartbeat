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


def _set_macos_app_name() -> None:
    """Override the process name so macOS shows 'Heartbeat' in the menu
    bar instead of 'Python'.  Must be called before QApplication is created.

    Uses the Objective-C runtime directly via ctypes so we don't need
    pyobjc as a dependency.  Fails silently on non-macOS or if the
    runtime isn't available.
    """
    if sys.platform != "darwin":
        return
    try:
        import ctypes
        lib = ctypes.cdll.LoadLibrary("libobjc.dylib")
        lib.objc_getClass.restype = ctypes.c_void_p
        lib.sel_registerName.restype = ctypes.c_void_p
        lib.objc_msgSend.restype = ctypes.c_void_p
        lib.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        NSBundle = lib.objc_getClass(b"NSBundle")
        bundle = lib.objc_msgSend(NSBundle,
                                  lib.sel_registerName(b"mainBundle"))
        info = lib.objc_msgSend(bundle,
                                lib.sel_registerName(b"infoDictionary"))

        lib.objc_msgSend.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        nsstr = lib.objc_getClass(b"NSString")
        lib.objc_msgSend.restype = ctypes.c_void_p

        def _nsstr(s: bytes) -> ctypes.c_void_p:
            lib.objc_msgSend.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
            ]
            lib.objc_msgSend.restype = ctypes.c_void_p
            return lib.objc_msgSend(
                nsstr, lib.sel_registerName(b"stringWithUTF8String:"), s)

        key = _nsstr(b"CFBundleName")
        val = _nsstr(b"Heartbeat")
        lib.objc_msgSend.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        lib.objc_msgSend.restype = None
        lib.objc_msgSend(info,
                         lib.sel_registerName(b"setObject:forKey:"),
                         val, key)
    except Exception:
        pass


def run_ui() -> int:
    """Launch the graphical PySide6 interface.

    PySide6 is imported inside this function (not at the top of the
    file) so that the CLI mode can work even if PySide6 isn't installed.
    """
    _set_macos_app_name()

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
