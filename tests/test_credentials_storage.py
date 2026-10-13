import sqlite3
from datetime import timedelta

import pytest

from local_mail_cleaner.credentials import (
    KIND_GOOGLE_REFRESH,
    KIND_PASSWORD,
    SERVICE,
    CredentialStore,
    CredentialStoreUnavailable,
    MemoryBackend,
)
from local_mail_cleaner.headers import parse_message_headers
from local_mail_cleaner.models import CheckStatus
from local_mail_cleaner.storage import SCHEMA_VERSION, Storage
from tests.conftest import NOW, account, newsletter


def test_credential_store_round_trip():
    backend = MemoryBackend()
    store = CredentialStore(backend)
    store.set(3, KIND_PASSWORD, "s3cret")
    assert backend.data == {(SERVICE, "account-3:password"): "s3cret"}
    assert store.get(3, KIND_PASSWORD) == "s3cret" and store.has(3, KIND_PASSWORD)
    store.set(3, KIND_GOOGLE_REFRESH, "1//r")
    store.delete_all(3)
    assert backend.data == {}
    store.delete(3, KIND_PASSWORD)  # deleting a missing secret is fine
    with pytest.raises(ValueError):
        store.set(3, KIND_PASSWORD, "")
    with pytest.raises(ValueError):
        store.set(3, "something_else", "x")


def _fake_backend(module: str, **attrs):
    cls = type("Backend", (), {"__module__": module, **attrs})
    return cls()


@pytest.mark.parametrize("module", ["keyrings.alt.file", "keyring.backends.fail"])
def test_insecure_backends_are_refused(monkeypatch, module):
    keyring = pytest.importorskip("keyring")
    monkeypatch.setattr(keyring, "get_keyring", lambda: _fake_backend(module))
    store = CredentialStore()
    with pytest.raises(CredentialStoreUnavailable):
        store.set(1, KIND_PASSWORD, "x")
    assert store.backend_name().startswith("unavailable")
    assert store.has(1, KIND_PASSWORD) is False


def test_empty_chainer_is_refused(monkeypatch):
    keyring = pytest.importorskip("keyring")
    monkeypatch.setattr(keyring, "get_keyring", lambda: _fake_backend("keyring.backends.chainer", backends=[]))
    with pytest.raises(CredentialStoreUnavailable):
        CredentialStore().get(1, KIND_PASSWORD)


def test_schema_and_account_round_trip(tmp_path):
    path = tmp_path / "db.sqlite3"
    with Storage(path) as st:
        assert st.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        acct = account(folders=("INBOX", "[Gmail]/Wszystkie"), trusted=["mx.google.com"], label="Moja")
        account_id = st.save_account(acct)
        acct.scan_days = 30
        st.save_account(acct)
    with Storage(path) as st:
        loaded = st.get_account(account_id)
        assert loaded.folders == ["INBOX", "[Gmail]/Wszystkie"] and loaded.scan_days == 30
        assert loaded.trusted_authserv_ids == ["mx.google.com"] and loaded.label == "Moja"
        columns = {r[1] for r in st.conn.execute("PRAGMA table_info(accounts)")}
        assert not any("password" in c or "token" in c or "secret" in c for c in columns)


def test_newer_schema_is_rejected(tmp_path):
    path = tmp_path / "db.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(RuntimeError):
        Storage(path)


def parsed(uid, i=None, **kwargs):
    msg, _ = parse_message_headers(newsletter(uid if i is None else i, **kwargs), uid=uid, folder="INBOX",
                                   uidvalidity=1)
    return msg


def test_upsert_keeps_local_results_and_drops_vanished_messages(storage):
    account_id = storage.save_account(account())
    run1 = storage.start_scan_run(account_id)
    storage.replace_folder_messages(account_id, "INBOX", 1, [parsed(1), parsed(2)], run1)
    row1 = next(r for r in storage.load_message_rows() if r["uid"] == 1)
    storage.set_local_result(row1["id"], CheckStatus.PASS, [], "shop.example.com")

    run2 = storage.start_scan_run(account_id)
    storage.replace_folder_messages(account_id, "INBOX", 1, [parsed(1)], run2)  # uid 2 disappeared
    rows = storage.load_message_rows()
    assert [r["uid"] for r in rows] == [1]
    assert rows[0]["local_status"] == "pass" and rows[0]["verification"] == "verified_local"

    run3 = storage.start_scan_run(account_id)
    storage.replace_folder_messages(account_id, "INBOX", 2, [parsed(1)], run3)  # UIDVALIDITY changed
    rows = storage.load_message_rows()
    assert len(rows) == 1 and rows[0]["uidvalidity"] == 2 and rows[0]["local_status"] == "not_run"


def test_drop_unscanned_folders_and_cascade(storage):
    account_id = storage.save_account(account())
    run = storage.start_scan_run(account_id)
    storage.replace_folder_messages(account_id, "INBOX", 1, [parsed(1)], run)
    storage.replace_folder_messages(account_id, "Old", 1, [parsed(2)], run)
    storage.drop_unscanned_folders(account_id, ["INBOX"])
    assert {r["folder"] for r in storage.load_message_rows()} == {"INBOX"}
    storage.finish_scan_run(run, "ok", 1, 1, 1)
    assert storage.last_scan_runs()[account_id]["status"] == "ok"
    storage.delete_account(account_id)
    assert storage.load_message_rows() == [] and storage.last_scan_runs() == {}


def test_stored_targets_never_hold_full_urls(storage):
    account_id = storage.save_account(account())
    run = storage.start_scan_run(account_id)
    storage.replace_folder_messages(account_id, "INBOX", 1, [parsed(1, when=NOW - timedelta(days=1))], run)
    row = storage.load_message_rows()[0]
    assert "SECRETTOKEN123" not in row["targets_json"]
    assert row["targets"][0] == {"scheme": "https", "host": "shop.example.com", "problems": []}
