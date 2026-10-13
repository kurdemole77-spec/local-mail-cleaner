"""Command line entry point.

    python -m local_mail_cleaner                 start the GUI
    python -m local_mail_cleaner --demo          GUI with synthetic demo data
    python -m local_mail_cleaner scan-demo       headless demo scan, prints the table
    python -m local_mail_cleaner diagnostics     print a sanitized diagnostic report
    python -m local_mail_cleaner check           check the runtime environment
"""

from __future__ import annotations

import argparse
import logging
import sys

from local_mail_cleaner import STAGE, __version__
from local_mail_cleaner import strings_pl as S
from local_mail_cleaner.paths import data_dir

log = logging.getLogger(__name__)

MIN_PYTHON = (3, 10)


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (OSError, ValueError):
                pass


def _print(text: str = "") -> None:
    if sys.stdout is not None:
        print(text)


def run_check() -> int:
    """Check Python, Tkinter, dependencies and the credential store."""
    ok = True
    version_ok = sys.version_info >= MIN_PYTHON
    _print(f"[{'OK' if version_ok else 'BLAD'}] Python {sys.version.split()[0]} (wymagany >= 3.10)")
    ok &= version_ok
    try:
        import tkinter  # noqa: F401

        _print("[OK] Tkinter")
    except Exception as exc:
        ok = False
        _print(f"[BLAD] Tkinter niedostepny ({type(exc).__name__}). Zainstaluj Pythona z python.org z opcja 'tcl/tk'.")
    for module, package in (("dkim", "dkimpy"), ("dns.resolver", "dnspython"), ("keyring", "keyring")):
        try:
            __import__(module)
            _print(f"[OK] {package}")
        except Exception as exc:
            ok = False
            _print(f"[BLAD] brak pakietu {package} ({type(exc).__name__})")
    from local_mail_cleaner.credentials import CredentialStore

    backend = CredentialStore().backend_name()
    secure = not backend.startswith("unavailable")
    _print(f"[{'OK' if secure else 'UWAGA'}] magazyn hasel systemu: {backend}")
    return 0 if ok else 1


def run_scan_demo(verify: bool) -> int:
    from local_mail_cleaner.app import AppContext

    ctx = AppContext(data_dir(), demo=True)
    try:
        for result in ctx.scan():
            _print(f"{result.account}: {result.status}, foldery={result.folders_scanned}, "
                   f"naglowki={result.messages_fetched}, kandydaci={result.candidates}")
        subscriptions = ctx.subscriptions()
        if verify:
            ctx.verify(subscriptions)
            subscriptions = ctx.subscriptions()
        _print()
        for sub in subscriptions:
            date = sub.latest_date.strftime("%Y-%m-%d") if sub.latest_date else "-"
            mailto = " +mailto" if sub.has_mailto else ""
            _print(f"{sub.account_name:<11} | {sub.sender_addr:<32} | {sub.list_id or '-':<28} | "
                   f"{sub.message_count:>3} | {date} | {S.METHODS[sub.method.value]}{mailto} | "
                   f"{S.VERIFICATION[sub.verification.value]}")
            for reason in sub.reasons:
                _print(f"{'':>14}- {S.reason_text(reason)}")
        _print(f"\n{len(subscriptions)} subskrypcji (dane syntetyczne).")
    finally:
        ctx.close()
    return 0


def run_diagnostics(base) -> int:
    from local_mail_cleaner.credentials import CredentialStore
    from local_mail_cleaner.diagnostics import build_report
    from local_mail_cleaner.logging_setup import LOG_FILE_NAME
    from local_mail_cleaner.paths import database_path, log_dir
    from local_mail_cleaner.storage import Storage

    storage = Storage(database_path(base)) if database_path(base).exists() else None
    try:
        _print(build_report(base, log_dir(base) / LOG_FILE_NAME, storage, CredentialStore()))
    finally:
        if storage is not None:
            storage.close()
    return 0


def run_gui(base, demo: bool, log_path=None) -> int:
    try:
        from local_mail_cleaner.ui import run
    except ImportError as exc:
        _print(f"Nie mozna uruchomic interfejsu: {type(exc).__name__}. "
               "Zainstaluj Pythona z python.org z opcja 'tcl/tk and IDLE'.")
        log.error("GUI unavailable: %s", exc)
        return 2
    from local_mail_cleaner.app import AppContext

    ctx = AppContext(base, demo=demo)
    ctx.log_path = log_path
    try:
        return run(ctx)
    except Exception:
        # Under pythonw.exe there is no console: log the error and tell the user.
        log.exception("The user interface stopped because of an unexpected error")
        _show_fatal_error(log_path)
        return 1
    finally:
        ctx.close()


def _show_fatal_error(log_path) -> None:
    try:
        import tkinter
        from tkinter import messagebox

        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror("Local Mail Cleaner", f"{S.error_text('internal')}\n\nLog: {log_path}")
        root.destroy()
    except Exception:
        _print(S.error_text("internal"))


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(
        prog="local_mail_cleaner",
        description=f"Local Mail Cleaner {__version__} (etap {STAGE}, tylko odczyt)",
    )
    parser.add_argument("command", nargs="?", default="gui", choices=["gui", "scan-demo", "diagnostics", "check"])
    parser.add_argument("--demo", action="store_true", help="dane syntetyczne, bez prawdziwych skrzynek")
    parser.add_argument("--verify", action="store_true", help="scan-demo: uruchom tez lokalna weryfikacje DKIM")
    parser.add_argument("--data-dir", help="katalog danych (domyslnie %%LOCALAPPDATA%%\\LocalMailCleaner)")
    parser.add_argument("--debug", action="store_true", help="szczegolowy log (nadal zanonimizowany)")
    parser.add_argument("--console", action="store_true", help="wypisuj log rowniez na konsole")
    args = parser.parse_args(argv)

    if args.command == "check":
        return run_check()

    base = data_dir(args.data_dir)
    from local_mail_cleaner.logging_setup import setup_logging

    log_path = setup_logging(base, debug=args.debug, console=args.console)
    log.info("Local Mail Cleaner %s starting (stage %s, command=%s, demo=%s)", __version__, STAGE,
             args.command, args.demo)
    if args.command == "scan-demo":
        return run_scan_demo(args.verify)
    if args.command == "diagnostics":
        return run_diagnostics(base)
    return run_gui(base, args.demo, log_path)
