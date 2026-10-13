"""Run blocking work off the Tk thread and deliver results back on it."""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from collections.abc import Callable

log = logging.getLogger(__name__)


class BackgroundTask:
    """Call ``func(progress, cancel_event)`` in a daemon thread.

    ``on_progress``, ``on_done`` and ``on_error`` run on the Tk thread.
    """

    POLL_MS = 100

    def __init__(
        self,
        widget: tk.Misc,
        func: Callable[[Callable[[object], None], threading.Event], object],
        *,
        on_done: Callable[[object], None],
        on_error: Callable[[BaseException], None],
        on_progress: Callable[[object], None] | None = None,
    ):
        self.widget = widget
        self.on_done = on_done
        self.on_error = on_error
        self.on_progress = on_progress
        self.cancel = threading.Event()
        self.finished = False
        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._run, args=(func,), daemon=True)
        self._thread.start()
        self.widget.after(self.POLL_MS, self._poll)

    def _run(self, func) -> None:
        try:
            result = func(lambda p: self._queue.put(("progress", p)), self.cancel)
        except BaseException as exc:  # reported on the Tk thread
            log.warning("Background task failed: %s", type(exc).__name__, exc_info=True)
            self._queue.put(("error", exc))
        else:
            self._queue.put(("done", result))

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    if self.on_progress is not None:
                        self.on_progress(payload)
                    continue
                self.finished = True
                (self.on_done if kind == "done" else self.on_error)(payload)
                return
        except queue.Empty:
            pass
        try:
            self.widget.after(self.POLL_MS, self._poll)
        except tk.TclError:
            pass  # window closed
