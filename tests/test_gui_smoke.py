"""Tkinter smoke tests. Skipped when Tk or a display is unavailable.

These only prove the widgets build and react on the platform where they run;
they are not a substitute for a manual check of the GUI on Windows.
"""

import os
import sys

import pytest

tk = pytest.importorskip("tkinter")

pytestmark = pytest.mark.gui


@pytest.fixture
def root():
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        pytest.skip("no display (run under xvfb-run)")
    try:
        window = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Tk unavailable: {exc}")
    window.withdraw()
    yield window
    window.destroy()


def test_main_window_with_demo_data(root, tmp_path):
    from local_mail_cleaner.app import AppContext
    from local_mail_cleaner.ui.main_window import CHECKED, MainWindow

    ctx = AppContext(tmp_path, demo=True)
    try:
        window = MainWindow(root, ctx)
        assert window.tree.get_children() == ()
        ctx.scan()
        window.refresh()
        rows = window.tree.get_children()
        assert len(rows) == 13
        window.toggle(rows[0])
        assert window.tree.set(rows[0], "sel") == CHECKED and len(window.checked_subscriptions()) == 1
        window.tree.focus(rows[0])
        window.show_details()
        assert "Nadawca:" in window.details.get("1.0", "end")
        assert "https://" not in window.details.get("1.0", "end")  # full URLs are never displayed
        window.filter_var.set("sklep")
        assert 0 < len(window.tree.get_children()) < 13
        window.filter_var.set("")
        window.sort_by("count")
        counts = [int(window.tree.set(i, "count")) for i in window.tree.get_children()]
        assert counts == sorted(counts, reverse=True)
        assert str(window.btn_unsubscribe["state"]) == "disabled"
        assert str(window.btn_quarantine["state"]) == "disabled"
    finally:
        ctx.close()


def test_account_editor_stores_password_only_in_credential_store(root, tmp_path):
    from local_mail_cleaner.app import AppContext
    from local_mail_cleaner.credentials import KIND_PASSWORD, CredentialStore, MemoryBackend
    from local_mail_cleaner.ui.accounts_dialog import AccountEditor

    backend = MemoryBackend()
    ctx = AppContext(tmp_path, credentials=CredentialStore(backend))
    saved = []
    editor = AccountEditor(root, ctx, None, on_saved=lambda: saved.append(1))
    editor.provider_var.set("IONOS")
    editor._provider_changed()
    assert editor.host_var.get() == "imap.ionos.de"
    editor.email_var.set("biuro@example.net")
    editor.password_var.set("Synthetic-Password-1")
    account = editor._persist()
    editor.close()
    assert saved and ctx.credentials.get(account.id, KIND_PASSWORD) == "Synthetic-Password-1"
    assert b"Synthetic-Password-1" not in ctx.db_path.read_bytes()
    assert [a.email for a in ctx.accounts()] == ["biuro@example.net"]
    ctx.delete_account(account.id)
    assert backend.data == {} and ctx.accounts() == []


def test_account_editor_validation(root, tmp_path):
    from local_mail_cleaner.app import AppContext
    from local_mail_cleaner.credentials import CredentialStore, MemoryBackend
    from local_mail_cleaner.ui.accounts_dialog import AccountEditor

    ctx = AppContext(tmp_path, credentials=CredentialStore(MemoryBackend()))
    editor = AccountEditor(root, ctx, None, on_saved=lambda: None)
    try:
        for field, value in (("email_var", "not-an-email"), ("host_var", "https://imap.example.com"),
                             ("port_var", "abc"), ("folders_var", " , ")):
            editor.email_var.set("ok@example.com")
            editor.host_var.set("imap.example.com")
            editor.port_var.set("993")
            editor.folders_var.set("INBOX")
            getattr(editor, field).set(value)
            with pytest.raises(ValueError):
                editor._collect()
    finally:
        editor.close()
