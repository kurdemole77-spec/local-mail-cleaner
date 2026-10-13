# Project status — Local Mail Cleaner

Last updated: 2026-10-13 (cloud session, stage A).

## Stage overview

| Stage | Scope | Status |
|---|---|---|
| A | Read-only scanner and subscription table | **Implemented, tested with synthetic data and mocks only** |
| B | Action preview + confirmed unsubscribe | Not started (no code) |
| C | Confirmed quarantine of old messages | Not started (no code) |

## Completed in stage A

- **Read-only IMAP access** (`imap_readonly.py`): IMAPS with certificate and
  host-name verification (TLS ≥ 1.2); `EXAMINE` only, scan stops if the server
  does not confirm `[READ-ONLY]`; FETCH item whitelist (`BODY.PEEK[...]`,
  `UID`, `INTERNALDATE`, `RFC822.SIZE`, `FLAGS`); only `UID SEARCH` / `UID
  FETCH`; no write commands, no `CLOSE`; modified UTF-7 folder names; robust
  FETCH parser (UID before/after literal, unsolicited responses ignored);
  locale-independent `SEARCH SINCE` dates; batched header fetch.
- **Header analysis** (`headers.py`, `url_safety.py`): `List-Unsubscribe`
  (RFC 2369), `List-Unsubscribe-Post` (RFC 8058), `List-ID` (RFC 2919),
  From/Date/Subject/Message-ID with RFC 2047 decoding, control/bidi character
  stripping, size limits, duplicate detection; offline destination checks
  (HTTPS, port 443, no user-info, no IP literals incl. integer/hex forms, no
  localhost/private/link-local/reserved/local names; mailto validation).
- **Subscription grouping** (`grouping.py`): per mailbox, by `List-ID`, else
  sender + unsubscribe host; Message-ID de-duplication across folders.
- **Unsubscribe method classification**: one-click (RFC 8058), HTTPS link
  (manual), mailto, HTTP link (manual), unsafe, none.
- **Verification status** (`auth_evidence.py`, `dkim_verify.py`,
  `verification.py`): fail-closed combination of trusted provider evidence
  (topmost `Authentication-Results`, Gmail only by default, `header.b`
  matching, all-candidates-must-qualify rule against copied signatures) and
  optional local DKIM verification (dkimpy, own DNS lookup without search
  domains, ambiguous TXT answers rejected); coverage of the unsubscribe
  headers, sender alignment, rsa-sha1 and `l=` rejected, duplicate-header
  injection forces manual review.
- **Gmail OAuth** (`oauth_google.py`): installed-app flow with PKCE (S256),
  random state (constant-time compare, forged requests ignored), loopback
  listener on 127.0.0.1 with per-connection timeout, fixed token endpoint,
  no redirects, response-size limit, ID-token e-mail check against the
  configured account, in-memory access-token cache, `invalid_grant` →
  re-login message.
- **Yahoo / IONOS**: password (app password / mailbox password) login.
- **Credentials** (`credentials.py`): OS credential store via `keyring`;
  insecure or missing backends are refused (no plaintext fallback).
- **SQLite storage** (`storage.py`): accounts without secrets, scan runs,
  header metadata; upserts keep local DKIM results across scans; UIDVALIDITY
  changes drop stale rows; schema versioning.
- **Tkinter UI in Polish** (`ui/`): read-only banner, subscription table with
  checkboxes, filters, sorting, colours, details pane (hosts only, never full
  URLs), progress and cancel, opt-in DKIM verification with confirmation,
  CSV export (formula-injection safe), account dialog (masked password field
  straight to the credential store, Gmail client JSON import + browser
  sign-in, read-only folder picker), diagnostics and data-folder menu items.
  Stage B/C buttons are visible but disabled.
- **Demo mode** (`--demo`): synthetic mailbox with 13 subscriptions covering
  verified, forged, duplicate-header, unsafe, unaligned, mailto, HTTP and
  malformed cases; temporary database; no network, no credential store.
- **Sanitized diagnostic logging** (`sanitize.py`, `logging_setup.py`,
  `diagnostics.py`): redaction of credentials, bearer/Google tokens, JWTs,
  key=value secrets, long opaque strings, URL paths/queries, mailto targets
  and e-mail local parts in every log record and traceback; rotating log
  file; shareable report that also hides the home folder.
- **Delivery**: `start_windows.bat` (first-run venv + dependency install,
  ASCII/CRLF, options `--demo --console --check --diagnostics --reinstall`),
  `start_ubuntu.sh`, `tools/bootstrap.py` (hash-verified two-step install,
  reinstall only when lock files change), hashed universal lock files,
  README (limitations, data handling), Polish quick start
  (`docs/SZYBKI_START.md`), `CLAUDE.md`.

## Test results (actually run in this cloud session, Linux container)

| Environment | Result |
|---|---|
| Python 3.12.3, dependencies installed from the hash-locked `requirements-dev.txt`, under Xvfb | **188 passed** |
| Python 3.11 (no Tkinter in this container) | **185 passed, 1 skipped** (GUI test module) |
| Python 3.13 (no Tkinter in this container) | **185 passed, 1 skipped** (GUI test module) |

Test modules (count on 3.12): URL checks 42, IMAP guard/parser 25, auth
evidence 23, logging/diagnostics 15, OAuth 15, fake-IMAP integration 14,
headers 13, local DKIM 10, credentials/storage 9, static safety guards 8,
demo/CLI/export 6, verification/grouping 5, GUI smoke 3.

What the tests cover:

- **Unit tests with synthetic e-mails** (example domains only); DKIM tests
  sign messages with a throw-away RSA key generated per test session and a
  mock DNS function (valid, tampered header, tampered body, missing coverage,
  unaligned signer, missing key, DNS errors, injected duplicate header).
- **Mocked integration tests**: real `imaplib` + `ReadOnlySession` against an
  in-process fake IMAP server (127.0.0.1, plain TCP) that records commands and
  models `\Seen`: full scans with password and XOAUTH2 login, flags unchanged,
  only allowed commands, `EXAMINE` only, missing `[READ-ONLY]` stops before any
  FETCH, wrong password and rejected/revoked tokens reported without leaking
  secrets into logs, local DKIM verification over IMAP with `BODY.PEEK[]`,
  UIDVALIDITY change detection, cancellation, read-only folder listing; plus
  a sanity test proving the fake server would detect a mark-as-read.
- **OAuth**: fake browser hitting the real loopback listener (PKCE verifier,
  forged state ignored, idle speculative connection does not block, denied
  consent, account mismatch, cancel, timeout, bad token responses).
- **Static safety guards**: no SMTP, no IMAP write commands, no non-PEEK
  fetches, folders only opened read-only, HTTP client code only in
  `oauth_google.py`, listener only on 127.0.0.1, TLS verification not
  disabled, stage flags off, every reason code translated.
- **GUI smoke tests** (Linux/Xvfb only): main window with demo data, checkbox,
  details pane without full URLs, filter, sort, disabled stage B/C buttons;
  account editor stores the password only in the (mock) credential store.

Other checks performed:

- `tools/bootstrap.py` first run in a clean Python 3.12 venv (two-step,
  hash-verified install), no-op second run, refusal outside a venv.
- `start_ubuntu.sh --check` from a fresh `.venv` (Python 3.12) and
  `start_ubuntu.sh --demo` under Xvfb: started without errors.
- `python -m local_mail_cleaner --demo` under Xvfb; screenshots inspected.
- Lock resolution for Windows (`uv pip install --dry-run --python-platform
  x86_64-pc-windows-msvc`): resolves to 8 pure-Python packages incl.
  `pywin32-ctypes` (Windows Credential Manager backend).

## Not tested (requires local setup on the owner's computer)

- **Windows**: the GUI, `start_windows.bat` (could not be executed here — no
  Windows or Wine), Windows Credential Manager via `keyring`, `pythonw`
  start, high-DPI rendering, opening files/folders with `os.startfile`.
- **Real providers**: no connection to Gmail, Yahoo or IONOS was made. IMAP
  host names, Gmail XOAUTH2, Google OAuth consent/token exchange, Yahoo app
  passwords, IONOS logins, the providers' `EXAMINE` `[READ-ONLY]` responses
  and real `Authentication-Results` formats are untested.
- **Real DNS** lookups of DKIM keys (only mocked in tests).
- Large real mailboxes (performance with thousands of headers).

## Known limitations

- Stage A only: no unsubscribe, mailto, move or quarantine.
- Only implicit-TLS IMAP on port 993.
- Provider evidence trusted only for Gmail by default; Yahoo/IONOS rows need
  local DKIM verification to become "verified".
- Simple domain-alignment rule without a Public Suffix List (sibling
  sub-domains → manual review).
- Without `List-ID`, newsletters from the same sender sharing an unsubscribe
  host are merged.
- Old messages may fail local DKIM after sender key rotation (→ manual review).
- Gmail OAuth clients in "Testing" status need a new sign-in about weekly.
- Folder names with commas cannot be entered.

## Next implementation step — stage B (preview and confirmed unsubscribe)

Before starting, ask the owner to run stage A locally (`start_windows.bat
--demo`, then a real scan) and report results via the sanitized diagnostic
report. Then implement, in this order:

1. **Action model and history**: `actions` table (subscription key, method,
   target host, request time, outcome: `accepted`, `rejected`, `ambiguous`,
   `confirmed`, `manual_done`), shown in the UI.
2. **Exact action preview dialog** per selected subscription: method, full
   destination (shown only in the dialog), what will be sent, verification
   evidence; explicit confirmation; unsubscribe separate from cleanup.
3. **Safe HTTP client** for RFC 8058 POST only: re-fetch the newest message
   and re-verify (local DKIM) immediately before sending; HTTPS only; resolve
   DNS and reject non-global addresses (`url_safety.is_forbidden_ip`); pin the
   connection to the validated IP while keeping SNI/Host; TLS verification;
   no redirects; connect/read timeouts; response-size cap; global rate limit;
   body `List-Unsubscribe=One-Click`; no cookies; no automatic retry on
   ambiguous results; 2xx = "request accepted", never "confirmed".
4. **Manual browser action** for ordinary HTTPS links (open only after
   confirmation; user marks as done).
5. **mailto**: separate preview (recipient, subject, body) and confirmation;
   decide with the owner whether to send via SMTP (new credentials) or hand
   off to the default mail client.
6. Update `tests/test_safety_static.py` narrowly for the new HTTP module, add
   mocked tests (fake HTTPS endpoint, DNS-rebinding and redirect cases), and
   keep stage C (quarantine) out of scope.
