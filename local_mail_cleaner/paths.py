"""Locations of local data (database, logs)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR_NAME = "LocalMailCleaner"


def data_dir(override: str | os.PathLike | None = None) -> Path:
    """Per-user data directory.

    Windows: ``%LOCALAPPDATA%\\LocalMailCleaner``; elsewhere
    ``$XDG_DATA_HOME/local-mail-cleaner`` (default ``~/.local/share``).
    ``LMC_DATA_DIR`` or an explicit override take precedence.
    """
    chosen = override or os.environ.get("LMC_DATA_DIR")
    if chosen:
        path = Path(chosen)
    elif sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        path = Path(base) / APP_DIR_NAME
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        path = Path(base) / "local-mail-cleaner"
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path(base: Path) -> Path:
    return base / "local_mail_cleaner.sqlite3"


def log_dir(base: Path) -> Path:
    path = base / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent
