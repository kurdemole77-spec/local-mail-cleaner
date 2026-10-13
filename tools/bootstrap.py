"""First-run dependency installer used by start_windows.bat and start_ubuntu.sh.

Run it with the virtual environment's interpreter. It installs the pinned,
hash-verified dependencies only when the lock files changed (or on
--reinstall), in two steps so that no unverified build tool is downloaded:

1. requirements-build.txt  (setuptools, needed to build dkimpy from source)
2. requirements.txt         with --no-build-isolation

Standard library only. Messages are ASCII so any console code page works.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK_FILES = ("requirements-build.txt", "requirements.txt")
STAMP_NAME = "lmc-requirements.sha256"
REQUIRED_MODULES = ("dkim", "dns.resolver", "keyring")
MIN_PYTHON = (3, 10)


def lock_digest(root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    for name in LOCK_FILES:
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return digest.hexdigest()


def stamp_path() -> Path:
    return Path(sys.prefix) / STAMP_NAME


def modules_importable() -> bool:
    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except Exception:
            return False
    return True


def needs_install(reinstall: bool, root: Path = ROOT) -> bool:
    if reinstall:
        return True
    stamp = stamp_path()
    if not stamp.exists() or stamp.read_text(encoding="ascii").strip() != lock_digest(root):
        return True
    return not modules_importable()


def pip(*args: str) -> int:
    command = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes",
               "--no-deps", *args]
    print("  > pip install " + " ".join(args))
    return subprocess.call(command, cwd=str(ROOT))


def install(root: Path = ROOT) -> bool:
    print("Instalowanie zaleznosci (wersje przypiete, weryfikacja sum SHA-256)...")
    if pip("-r", str(root / "requirements-build.txt")) != 0:
        return False
    if pip("--no-build-isolation", "-r", str(root / "requirements.txt")) != 0:
        return False
    importlib.invalidate_caches()
    if not modules_importable():
        print("[BLAD] Pakiety zainstalowane, ale nie daja sie zaimportowac.")
        return False
    stamp_path().write_text(lock_digest(root) + "\n", encoding="ascii")
    print("[OK] Zaleznosci zainstalowane.")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reinstall", action="store_true")
    parser.add_argument("--no-gui-check", action="store_true")
    args = parser.parse_args(argv)

    if sys.version_info < MIN_PYTHON:
        print(f"[BLAD] Wymagany Python 3.10 lub nowszy (jest {sys.version.split()[0]}).")
        return 1
    if sys.prefix == sys.base_prefix:
        print("[BLAD] bootstrap.py nalezy uruchamiac interpreterem ze srodowiska .venv.")
        return 1
    if not args.no_gui_check:
        try:
            import tkinter  # noqa: F401
        except Exception:
            print("[BLAD] Brak modulu tkinter. Zainstaluj Pythona z python.org z opcja 'tcl/tk and IDLE'")
            print("       (Ubuntu: sudo apt install python3-tk).")
            return 1
    if needs_install(args.reinstall):
        if not install():
            print("[BLAD] Instalacja zaleznosci nie powiodla sie. Sprawdz polaczenie z internetem")
            print("       i uruchom ponownie z opcja --reinstall.")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
