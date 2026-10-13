"""Tkinter user interface."""

from __future__ import annotations

import sys


def _enable_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass


def run(ctx) -> int:
    import tkinter as tk

    from local_mail_cleaner.ui.main_window import MainWindow

    _enable_dpi_awareness()
    root = tk.Tk()
    MainWindow(root, ctx)
    root.mainloop()
    return 0
