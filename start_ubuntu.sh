#!/usr/bin/env bash
# Local Mail Cleaner - optional Ubuntu launcher (stage A: read-only scanner).
#
# Requirements: sudo apt install python3 python3-venv python3-tk
# Options: --demo --console --check --diagnostics --reinstall
# Override the interpreter with PYTHON=python3.12 ./start_ubuntu.sh
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

VENV=".venv"
MODE="gui"
APP_ARGS=()
BOOT_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --demo) APP_ARGS+=(--demo) ;;
    --console) APP_ARGS+=(--console) ;;
    --check) MODE="check" ;;
    --diagnostics) MODE="diagnostics" ;;
    --reinstall) BOOT_ARGS+=(--reinstall) ;;
    *) echo "Nieznana opcja: $arg" >&2; exit 2 ;;
  esac
done

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "[BLAD] Brak $PY. Zainstaluj: sudo apt install python3 python3-venv python3-tk" >&2
  exit 1
fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "[BLAD] Wymagany Python 3.10 lub nowszy." >&2
  exit 1
fi
if [ ! -x "$VENV/bin/python" ]; then
  echo "Pierwsze uruchomienie: tworzenie srodowiska .venv ..."
  "$PY" -m venv "$VENV" || { echo "[BLAD] Zainstaluj: sudo apt install python3-venv" >&2; exit 1; }
fi

"$VENV/bin/python" tools/bootstrap.py ${BOOT_ARGS[@]+"${BOOT_ARGS[@]}"}

case "$MODE" in
  check) exec "$VENV/bin/python" -m local_mail_cleaner check ;;
  diagnostics) exec "$VENV/bin/python" -m local_mail_cleaner diagnostics ;;
  *) exec "$VENV/bin/python" -m local_mail_cleaner ${APP_ARGS[@]+"${APP_ARGS[@]}"} ;;
esac
