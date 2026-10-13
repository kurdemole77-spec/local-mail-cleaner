# Local Mail Cleaner

A small local desktop application (Python + Tkinter) that finds newsletter
subscriptions in Gmail, Yahoo and standard IONOS IMAP mailboxes.

**Current stage: A — read-only scanner and subscription table.**
Stage A cannot unsubscribe, send e-mail, move, delete or expunge anything.
Those features belong to stages B (confirmed unsubscribe) and C (confirmed
quarantine of old messages) and are not present in the code.

Polish quick-start guide: [`docs/SZYBKI_START.md`](docs/SZYBKI_START.md).
Project status and test results: [`PROJECT_STATUS.md`](PROJECT_STATUS.md).

> **Testing status.** All automated tests use synthetic e-mails and mocked
> mailbox connections. The application has **not** been tested against real
> Gmail, Yahoo or IONOS servers, and the GUI and `start_windows.bat` have
> **not** been run on Windows yet. See `PROJECT_STATUS.md`.

## What stage A does

1. Connects to each configured mailbox over IMAPS (TLS, certificate and host
   name verification) and opens folders with `EXAMINE` (read-only). If the
   server does not confirm `[READ-ONLY]`, the scan stops.
2. Fetches only selected header fields with `BODY.PEEK[HEADER.FIELDS (...)]`,
   which does not mark messages as read. Every FETCH item list is checked
   against a whitelist before it is sent.
3. Detects `List-Unsubscribe`, `List-Unsubscribe-Post` and `List-ID`.
4. Groups messages per mailbox and subscription identity — `List-ID` first,
   otherwise sender address + unsubscribe host — never by sender address alone.
   Copies of one message in several folders (Gmail labels) are counted once.
5. Shows a table: mailbox, sender, list, message count, latest date,
   unsubscribe method and verification status, with filters, sorting,
   selection checkboxes, a details pane and CSV export.
6. Optional, per selected row: **local DKIM verification** of the newest
   message (fetched with `BODY.PEEK[]`, still read-only) using DNS lookups.

### Unsubscribe methods shown

| Method | Meaning |
|---|---|
| One-click (RFC 8058) | HTTPS URI and `List-Unsubscribe-Post: List-Unsubscribe=One-Click` |
| HTTPS link | Ordinary link: a manual browser action |
| E-mail (mailto) | Needs its own preview and confirmation (stage B) |
| HTTP link | Unencrypted: manual only |
| Unsafe address | Every destination failed the static safety checks |
| None | No usable `List-Unsubscribe` header |

Destinations are checked offline: HTTPS only, no user-info, port 443 only, no
IP literals (including tricks such as `2130706433` or `0x7f.1`), no localhost,
private, link-local or reserved addresses, no local/reserved names. Stage A
never contacts these destinations. DNS validation, rebinding protection,
disabled redirects, timeouts, size and rate limits are stage B requirements
(see `CLAUDE.md`).

### Verification status (fail closed)

The presence of a `DKIM-Signature` header is never treated as proof.

* **Verified (local DKIM)** — the newest message's DKIM signature was verified
  locally (dkimpy + DNS), the signature covers `List-Unsubscribe` (and
  `List-Unsubscribe-Post` when present), uses `rsa-sha256`/`ed25519-sha256`,
  has no `l=` tag, and the signing domain is aligned with the From domain.
* **Verified (provider)** — the *topmost* `Authentication-Results` header comes
  from a trusted authserv-id and reports `dkim=pass` for a signature (matched
  by domain and `header.b`) that meets the same coverage and alignment rules.
  Only Gmail (`mx.google.com`) is trusted by default. Yahoo and IONOS get no
  provider trust by default because their header formats were not confirmed;
  an advanced per-account field allows adding trusted authserv-ids.
* **Needs manual review** — anything else, including duplicate `From` or
  `List-Unsubscribe` headers (DKIM header-injection attempts), ambiguous
  signature matches, unaligned third-party signers, unsafe destinations, or a
  local DKIM failure that contradicts the provider.

## Requirements

* Windows 10/11 with Python 3.10 or newer from python.org (installer options
  "Add python.exe to PATH" and "tcl/tk and IDLE").
* Internet access on first start to install the pinned dependencies.
* Optional: Ubuntu with `python3 python3-venv python3-tk` (`start_ubuntu.sh`).

Runtime dependencies (pinned, SHA-256 hash-verified): `dkimpy` (DKIM),
`dnspython` (DNS for DKIM keys), `keyring` (OS credential store). Tkinter,
SQLite, imaplib and ssl come with Python.

## Start on Windows

Double-click `start_windows.bat`. On the first run it:

1. finds Python 3.10+ (prefers the `py` launcher),
2. creates `.venv` next to the script,
3. runs `tools/bootstrap.py`, which installs `requirements-build.txt`
   (setuptools, needed because dkimpy ships only as source) and then
   `requirements.txt` with `--require-hashes --no-deps --no-build-isolation`,
   so every downloaded file is hash-verified,
4. starts the app with `pythonw` (no console window).

Later runs only start the app. Options: `--demo` (synthetic data, no real
mailbox), `--console`, `--check`, `--diagnostics`, `--reinstall`.

Manual installation (PowerShell or cmd, in the project folder):

```
py -3 -m venv .venv
.venv\Scripts\python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv\Scripts\python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
.venv\Scripts\python -m local_mail_cleaner check
.venv\Scripts\pythonw -m local_mail_cleaner
```

## Account setup (local, on your computer)

Never paste passwords, tokens or real e-mails into a chat or an issue. Enter
them only in the application's account dialog; they go straight to the OS
credential store.

**Gmail (OAuth 2.0).** Gmail IMAP requires the scope `https://mail.google.com/`.
You need your own OAuth client:
1. In Google Cloud Console create a project, configure the OAuth consent
   screen (audience *External*, publishing status *Testing*) and add your
   Gmail address as a test user.
2. Create an OAuth client of type **Desktop app** and download its JSON file.
3. In the app: *Konta… → Dodaj… → Gmail*, load the JSON file, save, then
   *Zaloguj przez Google…*. Sign-in happens in your browser; the app listens on
   `127.0.0.1` (random port) only for the redirect. The JSON file is not needed
   afterwards (its secret is moved to the credential store).

Google shows an "unverified app" warning for personal clients, and refresh
tokens of apps in *Testing* status expire after about 7 days, so expect to
sign in again weekly. Workspace administrators can disable IMAP or OAuth apps.

**Yahoo Mail.** Create an app password in your Yahoo account security
settings and enter it as the password. Server `imap.mail.yahoo.com`, port 993.

**IONOS.** Use the full e-mail address and the mailbox password. The IMAP host
depends on your IONOS country (e.g. `imap.ionos.de`, `imap.ionos.co.uk`,
`imap.ionos.com`); check the IONOS help or control panel. Port 993.

Step-by-step instructions in Polish: `docs/SZYBKI_START.md`.

## Data handling

* **Local only.** No telemetry, no cloud processing, no runtime LLM, no web
  interface. The only listening socket is the temporary OAuth redirect
  listener on `127.0.0.1` during Google sign-in.
* **Secrets** (IMAP passwords, Google refresh tokens, OAuth client secret)
  are stored only in the OS credential store via `keyring` (Windows Credential
  Manager). If no secure backend exists, nothing is stored (no plaintext
  fallback). Access tokens stay in memory.
* **Database** `%LOCALAPPDATA%\LocalMailCleaner\local_mail_cleaner.sqlite3`
  holds accounts (no secrets) and header metadata of subscription messages:
  sender, subject, date, Message-ID, List-ID and the raw `List-Unsubscribe`
  values (which can contain personal tokens). Message bodies are never stored;
  the optional DKIM check reads one full message in memory only.
* **Logs** `%LOCALAPPDATA%\LocalMailCleaner\logs\` (1 MB × 4, rotating) pass
  through a redaction layer: credentials, tokens, JWTs, long opaque strings,
  URL paths/queries and e-mail local parts are masked. The diagnostic report
  (*Pomoc → Zapisz raport diagnostyczny…*) is sanitized the same way and hides
  your home folder name.
* **No remote content.** Message bodies and HTML are never rendered, so no
  remote images are loaded.
* **Deleting data.** *Dane → Usuń lokalne wyniki skanowania…* clears scan
  results; deleting an account removes its row, its scan results and its
  stored secrets. To remove everything, delete the data folder and any
  `LocalMailCleaner` entries in Windows Credential Manager.

## Limitations (stage A)

* No unsubscribe, mailto, move or quarantine actions yet (stages B and C).
* Not tested against real providers or on Windows (see `PROJECT_STATUS.md`).
* Only implicit-TLS IMAP (port 993); STARTTLS on port 143 is not supported.
* Headers of at most `max_messages` newest messages per folder within the scan
  window (defaults: 365 days, 5000 messages) are fetched.
* Without `List-ID`, two different newsletters from the same sender address
  using the same unsubscribe host are shown as one subscription.
* Domain alignment uses a simple parent/child rule (no Public Suffix List):
  sibling sub-domains fall back to manual review.
* Local DKIM checks of old messages can fail when the sender has rotated its
  DNS key; the result is then "needs manual review" (fail closed).
* Provider evidence relies on the receiving provider adding its own topmost
  `Authentication-Results` header. Messages that never passed through the
  provider's inbound mail servers (for example, imported mail) may not have
  one; stage B will re-verify locally before any automatic action.
* Folder names containing commas cannot be entered in the comma-separated
  folder field.

## Development

```
python -m venv .venv
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements-dev.txt
.venv/bin/python -m pytest              # GUI smoke tests need a display: xvfb-run -a ...
.venv/bin/python -m local_mail_cleaner scan-demo
```

Layout:

```
local_mail_cleaner/
  headers.py        header parsing (untrusted input)
  url_safety.py     offline destination checks
  auth_evidence.py  Authentication-Results / DKIM-Signature evaluation
  dkim_verify.py    local DKIM verification (dkimpy, safe DNS lookup)
  verification.py   method classification and fail-closed status
  grouping.py       subscription identity and aggregation
  imap_readonly.py  read-only IMAP session (EXAMINE, BODY.PEEK whitelist)
  oauth_google.py   Gmail OAuth (PKCE, loopback, no redirects)
  credentials.py    OS credential store wrapper
  storage.py        SQLite
  scanner.py        scan and verification orchestration
  sanitize.py, logging_setup.py, diagnostics.py
  demo.py           synthetic demo mailbox (example domains only)
  ui/               Tkinter windows (Polish texts in strings_pl.py)
tests/              unit tests, fake IMAP server, mocked integration tests
tools/bootstrap.py  first-run dependency installer
```
