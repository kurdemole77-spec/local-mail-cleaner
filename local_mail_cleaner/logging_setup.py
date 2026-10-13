"""Sanitized diagnostic logging.

Every handler uses :class:`RedactingFormatter`, which runs the fully formatted
record (message, arguments and traceback) through :func:`sanitize.redact`.
Log files rotate at 1 MB (3 backups) in the per-user data directory.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

from local_mail_cleaner.paths import log_dir
from local_mail_cleaner.sanitize import redact

LOG_FILE_NAME = "local_mail_cleaner.log"
_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))

    def formatException(self, ei) -> str:  # noqa: N802
        return redact(super().formatException(ei))


def setup_logging(base_dir: Path, *, debug: bool = False, console: bool = False) -> Path:
    """Configure the root logger; returns the log file path."""
    path = log_dir(base_dir) / LOG_FILE_NAME
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    formatter = RedactingFormatter(_FORMAT)

    file_handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if console and sys.stderr is not None:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(formatter)
        root.addHandler(stream)

    # Third-party libraries must not add unsanitized detail.
    for noisy in ("urllib3", "keyring", "dkim"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.captureWarnings(True)
    return path


def tail_log(path: Path, lines: int = 200) -> list[str]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [redact(line) for line in content[-lines:]]
