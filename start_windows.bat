@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem ==========================================================================
rem  Local Mail Cleaner - Windows launcher (stage A: read-only scanner)
rem
rem  First run: creates .venv next to this file and installs the pinned,
rem  hash-verified dependencies (needs an internet connection once).
rem  Later runs: starts the application directly.
rem
rem  Options:
rem    --demo         synthetic demo data, no real mailbox is used
rem    --console      keep a console window with the (sanitized) log
rem    --check        check Python, Tkinter, dependencies, credential store
rem    --diagnostics  print a sanitized diagnostic report
rem    --reinstall    reinstall the dependencies
rem
rem  This file is ASCII only and uses no parenthesised blocks on purpose:
rem  that keeps it working with any console code page and folder name.
rem ==========================================================================

cd /d "%~dp0"
set "VENV=%~dp0.venv"
set "VPY=%VENV%\Scripts\python.exe"
set "VPYW=%VENV%\Scripts\pythonw.exe"
set "APP_ARGS="
set "BOOT_ARGS="
set "MODE=gui"
set "CONSOLE=0"

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="--demo" set "APP_ARGS=--demo"
if /I "%~1"=="--console" set "CONSOLE=1"
if /I "%~1"=="--check" set "MODE=check"
if /I "%~1"=="--diagnostics" set "MODE=diagnostics"
if /I "%~1"=="--reinstall" set "BOOT_ARGS=--reinstall"
shift
goto parse_args
:args_done

if exist "%VPY%" goto have_venv
call :find_python
if not defined PY goto no_python
echo Pierwsze uruchomienie: tworzenie srodowiska .venv ...
%PY% -m venv "%VENV%"
if errorlevel 1 goto venv_failed
:have_venv

rem Installs dependencies only on first run or when the lock files change.
"%VPY%" "%~dp0tools\bootstrap.py" %BOOT_ARGS%
if errorlevel 1 goto bootstrap_failed

if "%MODE%"=="check" goto run_check
if "%MODE%"=="diagnostics" goto run_diagnostics
if "%CONSOLE%"=="1" goto run_console
start "" "%VPYW%" -m local_mail_cleaner %APP_ARGS%
exit /b 0

:run_console
"%VPY%" -m local_mail_cleaner %APP_ARGS% --console
exit /b

:run_check
"%VPY%" -m local_mail_cleaner check
pause
exit /b 0

:run_diagnostics
"%VPY%" -m local_mail_cleaner diagnostics
pause
exit /b 0

:find_python
rem Prefer the py launcher; skip the Microsoft Store "python" alias stub.
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto :eof
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=python"
goto :eof

:no_python
echo.
echo [BLAD] Nie znaleziono Pythona 3.10 lub nowszego.
echo Zainstaluj Pythona ze strony https://www.python.org/downloads/windows/
echo W instalatorze zaznacz: "Add python.exe to PATH" oraz "tcl/tk and IDLE".
echo Potem uruchom ten plik ponownie.
pause
exit /b 1

:venv_failed
echo.
echo [BLAD] Nie udalo sie utworzyc srodowiska .venv.
pause
exit /b 1

:bootstrap_failed
echo.
echo [BLAD] Przygotowanie srodowiska nie powiodlo sie - szczegoly powyzej.
echo Mozesz sprobowac ponownie: start_windows.bat --reinstall
pause
exit /b 1
