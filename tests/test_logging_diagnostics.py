import base64
import imaplib
import logging
from pathlib import Path

import pytest

from local_mail_cleaner.credentials import CredentialStore, MemoryBackend
from local_mail_cleaner.diagnostics import build_report
from local_mail_cleaner.logging_setup import setup_logging, tail_log
from local_mail_cleaner.sanitize import redact
from local_mail_cleaner.storage import Storage
from tests.conftest import account

SECRETS = [
    ("LOGIN jan@example.com hunter2-secret", "hunter2-secret"),
    ("Authorization: Bearer ya29.SYNTHETIC-TEST-VALUE", "SYNTHETIC-TEST-VALUE"),
    ("refresh_token=1//SYNTHETIC-REFRESH-VALUE", "SYNTHETIC-REFRESH-VALUE"),
    ('{"client_secret": "GOCSPX-SYNTHETIC"}', "GOCSPX-SYNTHETIC"),
    ("password: 'tajne haslo'", "tajne haslo"),
    ("POST https://shop.example.com/u/one-click?t=TOKEN123 failed", "TOKEN123"),
    ("POST https://shop.example.com/u/one-click?t=TOKEN123 failed", "/u/one-click"),
    ("unsubscribe via mailto:unsub-8f7a@lists.example.com?subject=x", "unsub-8f7a"),
    ("user jan.kowalski@example.com connected", "jan.kowalski"),
    ("eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImFAYi5jIn0.c2lnbmF0dXJl", "eyJhbGciOiJSUzI1NiJ9"),
    (base64.b64encode(b"user=jan@example.com\x01auth=Bearer ya29.tokentokentoken\x01\x01").decode(), "dXNlcj1q"),
]


@pytest.mark.parametrize("text,secret", SECRETS)
def test_redact_removes_secrets(text, secret):
    assert secret not in redact(text)


def test_redact_keeps_useful_context():
    assert redact("connect https://imap.example.com:993/x") == "connect https://imap.example.com:993/[redacted]"
    assert redact("user jan@gmail.com") == "user [user]@gmail.com"
    line = "Scan finished for account 1: status=ok folders=2 fetched=38 candidates=35"
    assert redact(line) == line


def test_log_file_is_sanitized_including_tracebacks(tmp_path):
    path = setup_logging(tmp_path, debug=True)
    log = logging.getLogger("local_mail_cleaner.test")
    try:
        log.info("connecting as %s with password=%s", "jan@example.com", "Hunter2-Secret")
        try:
            raise RuntimeError("token=ya29.inside-exception https://shop.example.com/u?t=abc")
        except RuntimeError:
            log.exception("failure")
    finally:
        for handler in logging.getLogger().handlers:
            handler.flush()
        logging.getLogger().handlers.clear()
    content = path.read_text(encoding="utf-8")
    for secret in ("Hunter2-Secret", "jan@example.com", "ya29.inside", "/u?t=abc"):
        assert secret not in content
    assert "RuntimeError" in content and "[user]@example.com" in content
    assert tail_log(path, 2)


def test_imaplib_debug_is_disabled():
    import local_mail_cleaner.imap_readonly  # noqa: F401

    assert imaplib.Debug == 0


def test_diagnostic_report_is_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    base = tmp_path / "data"
    base.mkdir()
    log_path = setup_logging(base)
    logging.getLogger("x").warning("connecting as secret.person@example.org to https://imap.example.org/a?b=c")
    for handler in logging.getLogger().handlers:
        handler.flush()
    logging.getLogger().handlers.clear()
    with Storage(":memory:") as st:
        st.save_account(account(email="secret.person@example.org"))
        report = build_report(base, log_path, st, CredentialStore(MemoryBackend()))
    assert "secret.person" not in report and "?b=c" not in report
    assert str(tmp_path) not in report and "~" in report
    assert "accounts_ionos: 1" in report and "stage A" in report
