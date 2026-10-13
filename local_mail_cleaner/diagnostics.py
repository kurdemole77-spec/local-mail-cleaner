"""Sanitized diagnostic report (safe to share: no addresses, URLs or secrets)."""

from __future__ import annotations

import importlib.metadata
import platform
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from local_mail_cleaner import STAGE, __version__
from local_mail_cleaner.credentials import CredentialStore
from local_mail_cleaner.logging_setup import tail_log
from local_mail_cleaner.sanitize import redact

PACKAGES = ("dkimpy", "dnspython", "keyring")


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def _tk_status() -> str:
    try:
        import tkinter

        return f"available (Tk {tkinter.TkVersion})"
    except Exception as exc:  # ImportError or a broken Tcl installation
        return f"unavailable ({type(exc).__name__})"


def _hide_home(path: Path | str) -> str:
    text = str(path)
    home = str(Path.home())
    return text.replace(home, "~") if home and home != "/" else text


def build_report(base_dir: Path, log_path: Path | None, storage=None,
                 credentials: CredentialStore | None = None, log_lines: int = 200) -> str:
    lines = [
        "Local Mail Cleaner - raport diagnostyczny / diagnostic report",
        f"generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"app version: {__version__} (stage {STAGE}, read-only)",
        f"python: {sys.version.split()[0]} ({platform.python_implementation()})",
        f"platform: {platform.system()} {platform.release()} ({platform.machine()})",
        f"sqlite: {sqlite3.sqlite_version}",
        f"tkinter: {_tk_status()}",
        f"data dir: {_hide_home(base_dir)}",
    ]
    lines += [f"package {name}: {_package_version(name)}" for name in PACKAGES]
    if credentials is not None:
        lines.append(f"credential store: {credentials.backend_name()}")
    if storage is not None:
        for key, value in sorted(storage.stats().items()):
            lines.append(f"{key}: {value}")
        for account_id, run in sorted(storage.last_scan_runs().items()):
            lines.append(
                f"last scan account {account_id}: status={run['status']} folders={run['folders_scanned']}"
                f" fetched={run['messages_fetched']} candidates={run['candidates']} error={run['error_kind'] or '-'}"
            )
    if log_path is not None:
        lines.append("")
        lines.append(f"--- last {log_lines} log lines (sanitized) ---")
        lines += tail_log(log_path, log_lines)
    return "\n".join(redact(_hide_home(line)) for line in lines) + "\n"
