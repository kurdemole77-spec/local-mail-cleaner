"""Mocked integration tests: real imaplib + ReadOnlySession against a fake IMAP server."""

from __future__ import annotations

import imaplib
import json
import logging
import time
from datetime import timedelta

import pytest

from local_mail_cleaner.credentials import KIND_GOOGLE_CLIENT_SECRET, KIND_GOOGLE_REFRESH, KIND_PASSWORD
from local_mail_cleaner.demo import build_message, dkim_header, fake_b64
from local_mail_cleaner.grouping import aggregate
from local_mail_cleaner.imap_readonly import MailboxError
from local_mail_cleaner.logging_setup import setup_logging
from local_mail_cleaner.models import CheckStatus, UnsubMethod, Verification
from local_mail_cleaner.oauth_google import GmailTokenCache
from local_mail_cleaner.scanner import make_session_opener, scan_account, verify_subscriptions
from tests.conftest import NOW, account, dns_for, newsletter, sign, stored

PASSWORD = "Synthetic-App-Password-123!"
ALLOWED_COMMANDS = {"CAPABILITY", "LOGIN", "AUTHENTICATE", "LIST", "EXAMINE", "UID SEARCH", "UID FETCH", "LOGOUT"}


def populate(mailbox, *, extra_inbox=()):
    mailbox.passwords["user@example.net"] = PASSWORD
    mailbox.folders["INBOX"] = [
        stored(1, newsletter(1)),
        stored(2, newsletter(2)),
        stored(3, newsletter(3, sender="promo@other.example.org", list_id="<promo.other.example.org>",
                             unsub="<https://other.example.org/u>", post=None)),
        stored(4, build_message(from_header="anna@example.org", subject="Lunch", date=NOW, message_id="<p@x>")),
        stored(5, newsletter(4), when=NOW - timedelta(days=500)),  # outside the scan window
        *extra_inbox,
    ]
    mailbox.folders["Newsletters"] = [stored(10, newsletter(1))]  # same Message-ID as uid 1
    mailbox.uidvalidity.update({"INBOX": 11, "Newsletters": 12})


def scan(storage, credentials, factory, acct, **kwargs):
    storage.save_account(acct)
    if acct.provider != "gmail":
        credentials.set(acct.id, KIND_PASSWORD, PASSWORD)
    opener = make_session_opener(credentials, imap_factory=factory, **kwargs)
    return scan_account(storage, acct, opener, now=NOW), opener


def test_full_read_only_scan(fake_server, storage, credentials):
    _, mailbox, factory = fake_server
    populate(mailbox)
    flags_before = mailbox.flags_snapshot()

    result, _ = scan(storage, credentials, factory, account(folders=("INBOX", "Newsletters")))

    assert result.status == "ok", result
    assert result.folders_scanned == 2 and result.candidates == 4 and result.messages_fetched == 5
    subs = {s.key: s for s in aggregate(storage.load_message_rows(), {1: "A"})}
    assert set(subs) == {"list-id:weekly.shop.example.com", "list-id:promo.other.example.org"}
    assert subs["list-id:weekly.shop.example.com"].message_count == 2  # duplicate across folders counted once
    assert subs["list-id:weekly.shop.example.com"].method == UnsubMethod.ONE_CLICK
    assert subs["list-id:promo.other.example.org"].method == UnsubMethod.HTTPS_LINK
    # IONOS has no trusted provider evidence: manual review until verified locally
    assert all(s.verification == Verification.MANUAL_REVIEW for s in subs.values())

    # Nothing was marked as read, nothing was written.
    assert mailbox.flags_snapshot() == flags_before
    names = set(mailbox.command_names())
    assert names <= {n.split()[0] for n in ALLOWED_COMMANDS} | {"UID"}
    commands = mailbox.commands
    assert not any(c.startswith(("SELECT", "STORE", "COPY", "MOVE", "EXPUNGE", "CLOSE", "APPEND")) for c in commands)
    assert not any(c.startswith(("UID STORE", "UID COPY", "UID MOVE", "UID EXPUNGE")) for c in commands)
    fetches = [c for c in commands if c.startswith("UID FETCH")]
    assert fetches and all("BODY.PEEK[HEADER.FIELDS" in c for c in fetches)
    assert [c for c in commands if c.startswith("EXAMINE")] == ['EXAMINE "INBOX"', 'EXAMINE "Newsletters"']
    assert PASSWORD not in "\n".join(commands)


def test_server_variant_with_uid_after_literal(fake_server, storage, credentials):
    _, mailbox, factory = fake_server
    mailbox.uid_after_literal = True
    populate(mailbox)
    result, _ = scan(storage, credentials, factory, account())
    assert result.status == "ok" and result.candidates == 3


def test_missing_read_only_confirmation_stops_before_fetching(fake_server, storage, credentials):
    _, mailbox, factory = fake_server
    populate(mailbox)
    mailbox.confirm_read_only = False
    result, _ = scan(storage, credentials, factory, account())
    assert result.status == "error" and result.error_kind == MailboxError.KIND_READ_ONLY
    assert not any(c.startswith("UID") for c in mailbox.commands)


def test_missing_folder_is_skipped(fake_server, storage, credentials):
    _, mailbox, factory = fake_server
    populate(mailbox)
    result, _ = scan(storage, credentials, factory, account(folders=("Nope", "INBOX")))
    assert result.status == "ok" and result.skipped_folders == ["Nope"] and result.folders_scanned == 1


def test_wrong_password_is_reported_without_leaking(fake_server, storage, credentials, tmp_path, caplog):
    _, mailbox, factory = fake_server
    populate(mailbox)
    log_file = setup_logging(tmp_path, debug=True)
    try:
        acct = account()
        storage.save_account(acct)
        credentials.set(acct.id, KIND_PASSWORD, "Wrong-Secret-Value-987")
        with caplog.at_level(logging.DEBUG):
            result = scan_account(storage, acct, make_session_opener(credentials, imap_factory=factory), now=NOW)
    finally:
        logging.getLogger().handlers.clear()
    assert result.status == "error" and result.error_kind == MailboxError.KIND_AUTH
    text = log_file.read_text(encoding="utf-8") + caplog.text + result.error_message
    assert "Wrong-Secret-Value-987" not in text and PASSWORD not in text
    assert "user@example.net" not in log_file.read_text(encoding="utf-8")


def test_missing_credentials(fake_server, storage, credentials):
    _, mailbox, factory = fake_server
    acct = account()
    storage.save_account(acct)
    result = scan_account(storage, acct, make_session_opener(credentials, imap_factory=factory), now=NOW)
    assert result.status == "error" and result.error_kind == "auth"
    assert mailbox.commands == []  # did not even connect


def gmail_setup(mailbox, credentials, acct, token="ya29.synthetic-access-token"):
    mailbox.oauth_tokens[acct.email] = token
    credentials.set(acct.id, KIND_GOOGLE_REFRESH, "1//synthetic-refresh-token-value")
    credentials.set(acct.id, KIND_GOOGLE_CLIENT_SECRET, "GOCSPX-synthetic-client-secret")


def test_gmail_xoauth2_scan_with_trusted_provider_evidence(fake_server, storage, credentials, tmp_path):
    _, mailbox, factory = fake_server
    b = fake_b64("gmail")
    raw = newsletter(1, dkim_signatures=[dkim_header("shop.example.com", "s1",
                                                      ("from", "list-unsubscribe", "list-unsubscribe-post"), b)],
                     auth_results=[f"mx.google.com; dkim=pass header.i=@shop.example.com header.b={b[:8]}"])
    mailbox.folders["INBOX"] = [stored(1, raw)]
    acct = account(provider="gmail", email="someone@example.com", trusted=["mx.google.com"],
                   oauth_client_id="123-abc.apps.googleusercontent.com")
    storage.save_account(acct)
    gmail_setup(mailbox, credentials, acct)
    posts = []

    def http_post(url, form):
        posts.append((url, dict(form)))
        return 200, json.dumps({"access_token": "ya29.synthetic-access-token", "expires_in": 3600}).encode()

    log_file = setup_logging(tmp_path, debug=True)
    try:
        opener = make_session_opener(credentials, imap_factory=factory, oauth_http_post=http_post,
                                     token_cache=GmailTokenCache())
        result = scan_account(storage, acct, opener, now=NOW)
        result2 = scan_account(storage, acct, opener, now=NOW)  # access token is cached
    finally:
        logging.getLogger().handlers.clear()
    assert result.status == "ok" and result2.status == "ok"
    assert len(posts) == 1 and posts[0][1]["grant_type"] == "refresh_token"
    (sub,) = aggregate(storage.load_message_rows(), {acct.id: "G"})
    assert sub.verification == Verification.VERIFIED_PROVIDER
    assert any(c.startswith("AUTHENTICATE XOAUTH2") for c in mailbox.commands)
    content = log_file.read_text(encoding="utf-8")
    for secret in ("ya29.synthetic", "1//synthetic", "GOCSPX-synthetic"):
        assert secret not in content


def test_gmail_rejected_token_is_auth_error(fake_server, storage, credentials):
    _, mailbox, factory = fake_server
    mailbox.folders["INBOX"] = []
    acct = account(provider="gmail", email="someone@example.com", oauth_client_id="1.apps.googleusercontent.com")
    storage.save_account(acct)
    gmail_setup(mailbox, credentials, acct, token="ya29.the-server-expects-this")

    def http_post(url, form):
        return 200, json.dumps({"access_token": "ya29.but-we-got-this", "expires_in": 3600}).encode()

    opener = make_session_opener(credentials, imap_factory=factory, oauth_http_post=http_post)
    result = scan_account(storage, acct, opener, now=NOW)
    assert result.status == "error" and result.error_kind == "auth"
    assert "ya29" not in result.error_message


def test_gmail_revoked_refresh_token(fake_server, storage, credentials):
    _, mailbox, factory = fake_server
    acct = account(provider="gmail", email="someone@example.com", oauth_client_id="1.apps.googleusercontent.com")
    storage.save_account(acct)
    gmail_setup(mailbox, credentials, acct)
    opener = make_session_opener(credentials, imap_factory=factory,
                                 oauth_http_post=lambda url, form: (400, b'{"error": "invalid_grant"}'))
    result = scan_account(storage, acct, opener, now=NOW)
    assert result.status == "error" and "reauth" in result.error_message
    assert mailbox.commands == []


def test_local_dkim_verification_over_imap(fake_server, storage, credentials, dkim_key):
    _, mailbox, factory = fake_server
    signed = sign(newsletter(1), dkim_key, "shop.example.com")
    unsigned = newsletter(2, sender="promo@other.example.org", list_id="<promo.other.example.org>")
    populate(mailbox)
    mailbox.folders["INBOX"] = [stored(1, signed), stored(2, unsigned)]
    flags_before = mailbox.flags_snapshot()
    _, opener = scan(storage, credentials, factory, account())
    subs = aggregate(storage.load_message_rows(), {1: "A"})
    accounts = {1: storage.get_account(1)}
    results = verify_subscriptions(storage, subs, accounts, opener,
                                   dnsfunc=dns_for(dkim_key, "s1._domainkey.shop.example.com"))
    by_key = {r.subscription_key: r for r in results}
    assert by_key["list-id:weekly.shop.example.com"].status == CheckStatus.PASS
    assert by_key["list-id:promo.other.example.org"].status == CheckStatus.FAIL
    after = {s.key: s for s in aggregate(storage.load_message_rows(), {1: "A"})}
    assert after["list-id:weekly.shop.example.com"].verification == Verification.VERIFIED_LOCAL
    assert after["list-id:promo.other.example.org"].verification == Verification.MANUAL_REVIEW
    assert any("BODY.PEEK[]" in c for c in mailbox.commands)
    assert mailbox.flags_snapshot() == flags_before  # still unread

    # A later scan keeps the local result for the same message.
    scan_account(storage, accounts[1], opener, now=NOW)
    kept = {s.key: s for s in aggregate(storage.load_message_rows(), {1: "A"})}
    assert kept["list-id:weekly.shop.example.com"].verification == Verification.VERIFIED_LOCAL


def test_verification_detects_uidvalidity_change(fake_server, storage, credentials, dkim_key):
    _, mailbox, factory = fake_server
    populate(mailbox)
    _, opener = scan(storage, credentials, factory, account())
    mailbox.uidvalidity["INBOX"] = 99  # folder recreated on the server
    subs = aggregate(storage.load_message_rows(), {1: "A"})
    results = verify_subscriptions(storage, subs, {1: storage.get_account(1)}, opener,
                                   dnsfunc=lambda *a, **k: None)
    assert all(r.reasons == ["message_reference_stale"] for r in results)
    assert not any("BODY.PEEK[]" in c for c in mailbox.commands)


def test_fake_server_would_detect_a_mark_as_read(fake_server):
    """Sanity check of the test double: SELECT + BODY[] does set \\Seen."""
    server, mailbox, _ = fake_server
    populate(mailbox)
    imap = imaplib.IMAP4("127.0.0.1", server.port)
    imap.login("user@example.net", PASSWORD)
    imap.select('"INBOX"')
    imap.uid("FETCH", "1", "(BODY[])")
    imap.logout()
    time.sleep(0.05)
    assert "\\Seen" in next(m.flags for m in mailbox.folders["INBOX"] if m.uid == 1)


def test_list_folders_is_read_only(fake_server, storage, credentials):
    _, mailbox, factory = fake_server
    populate(mailbox)
    acct = account()
    storage.save_account(acct)
    credentials.set(acct.id, KIND_PASSWORD, PASSWORD)
    session = make_session_opener(credentials, imap_factory=factory)(acct)
    try:
        names = [f.name for f in session.list_folders()]
    finally:
        session.logout()
    assert names == ["INBOX", "Newsletters"]
    assert set(mailbox.command_names()) <= {"CAPABILITY", "LOGIN", "LIST", "LOGOUT"}


@pytest.mark.parametrize("cancel_first", [True])
def test_cancel_stops_scan(fake_server, storage, credentials, cancel_first):
    import threading

    _, mailbox, factory = fake_server
    populate(mailbox)
    acct = account()
    storage.save_account(acct)
    credentials.set(acct.id, KIND_PASSWORD, PASSWORD)
    event = threading.Event()
    event.set()
    result = scan_account(storage, acct, make_session_opener(credentials, imap_factory=factory),
                          cancel=event, now=NOW)
    assert result.status == "cancelled" and result.folders_scanned == 0
