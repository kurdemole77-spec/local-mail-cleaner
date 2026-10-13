"""Application context shared by the GUI and the command line."""

from __future__ import annotations

import logging
import tempfile
import threading
from pathlib import Path

from local_mail_cleaner.credentials import CredentialStore, MemoryBackend
from local_mail_cleaner.demo import DemoSessionFactory, demo_accounts, demo_dns_lookup
from local_mail_cleaner.dkim_verify import DnsFunc
from local_mail_cleaner.grouping import aggregate
from local_mail_cleaner.imap_readonly import ImapFactory
from local_mail_cleaner.models import Account, Subscription
from local_mail_cleaner.oauth_google import GmailTokenCache, HttpPost
from local_mail_cleaner.paths import database_path
from local_mail_cleaner.scanner import (
    AccountScanResult,
    ProgressFn,
    SessionOpener,
    VerifyResult,
    make_session_opener,
    scan_account,
    verify_subscriptions,
)
from local_mail_cleaner.storage import Storage

log = logging.getLogger(__name__)


class AppContext:
    """Holds configuration and opens per-thread storage connections."""

    def __init__(
        self,
        base_dir: Path,
        *,
        demo: bool = False,
        credentials: CredentialStore | None = None,
        imap_factory: ImapFactory | None = None,
        oauth_http_post: HttpPost | None = None,
        dnsfunc: DnsFunc | None = None,
        open_session: SessionOpener | None = None,
    ):
        self.base_dir = base_dir
        self.demo = demo
        self.log_path: Path | None = None
        self.oauth_http_post = oauth_http_post
        self.token_cache = GmailTokenCache()
        self._tmp: tempfile.TemporaryDirectory | None = None
        if demo:
            # Demo data lives in a throw-away directory, never in the real database.
            self._tmp = tempfile.TemporaryDirectory(prefix="lmc-demo-")
            self.db_path = Path(self._tmp.name) / "demo.sqlite3"
            self.credentials = CredentialStore(MemoryBackend())
            self.open_session: SessionOpener = open_session or DemoSessionFactory()
            self.dnsfunc: DnsFunc | None = demo_dns_lookup
            with self.storage() as storage:
                for account in demo_accounts():
                    storage.save_account(account)
        else:
            self.db_path = database_path(base_dir)
            self.credentials = credentials or CredentialStore()
            self.open_session = open_session or make_session_opener(
                self.credentials, imap_factory=imap_factory, oauth_http_post=oauth_http_post,
                token_cache=self.token_cache,
            )
            self.dnsfunc = dnsfunc

    def storage(self) -> Storage:
        """Open a new connection (one per thread)."""
        return Storage(self.db_path)

    def close(self) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    # -- queries ---------------------------------------------------------------

    def accounts(self) -> list[Account]:
        with self.storage() as storage:
            return storage.list_accounts()

    def subscriptions(self) -> list[Subscription]:
        with self.storage() as storage:
            names = {a.id: a.display_name for a in storage.list_accounts()}
            return aggregate(storage.load_message_rows(), names)

    # -- read-only operations ----------------------------------------------------

    def scan(
        self,
        account_ids: list[int] | None = None,
        progress: ProgressFn | None = None,
        cancel: threading.Event | None = None,
    ) -> list[AccountScanResult]:
        results: list[AccountScanResult] = []
        with self.storage() as storage:
            for account in storage.list_accounts():
                if account_ids is not None and account.id not in account_ids:
                    continue
                if cancel is not None and cancel.is_set():
                    break
                results.append(scan_account(storage, account, self.open_session, progress=progress, cancel=cancel))
        return results

    def verify(
        self,
        subscriptions: list[Subscription],
        progress: ProgressFn | None = None,
        cancel: threading.Event | None = None,
    ) -> list[VerifyResult]:
        with self.storage() as storage:
            accounts = {a.id: a for a in storage.list_accounts()}
            return verify_subscriptions(storage, subscriptions, accounts, self.open_session,
                                        dnsfunc=self.dnsfunc, progress=progress, cancel=cancel)

    def delete_account(self, account_id: int) -> None:
        with self.storage() as storage:
            storage.delete_account(account_id)
        self.token_cache.forget(account_id)
        try:
            self.credentials.delete_all(account_id)
        except Exception as exc:  # the account row is gone either way
            log.warning("Could not remove stored secrets for account %d: %s", account_id, type(exc).__name__)
