"""Scan orchestration: read-only header scan and opt-in local DKIM verification."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from local_mail_cleaner.auth_evidence import evaluate_provider_evidence
from local_mail_cleaner.credentials import (
    KIND_GOOGLE_CLIENT_SECRET,
    KIND_GOOGLE_REFRESH,
    KIND_PASSWORD,
    CredentialStore,
    CredentialStoreUnavailable,
)
from local_mail_cleaner.dkim_verify import MAX_VERIFY_BYTES, DnsFunc, verify_message
from local_mail_cleaner.headers import FETCH_FIELDS, parse_message_headers
from local_mail_cleaner.imap_readonly import (
    FETCH_BATCH,
    ImapFactory,
    MailboxError,
    ReadOnlySession,
    find_header_section,
)
from local_mail_cleaner.models import Account, CheckStatus, ParsedMessage, Subscription
from local_mail_cleaner.oauth_google import ClientConfig, GmailTokenCache, HttpPost, OAuthError
from local_mail_cleaner.providers import AUTH_OAUTH2, get_provider
from local_mail_cleaner.storage import Storage

log = logging.getLogger(__name__)

R_UIDVALIDITY_CHANGED = "message_reference_stale"
R_MESSAGE_NOT_FOUND = "message_not_found"
R_TOO_LARGE = "message_too_large_to_verify"


@dataclass
class ScanProgress:
    account: str
    folder: str = ""
    done: int = 0
    total: int = 0
    stage: str = ""  # connecting, searching, fetching, saving, verifying, done


@dataclass
class AccountScanResult:
    account_id: int
    account: str
    status: str = "ok"  # ok, error, cancelled
    error_kind: str = ""
    error_message: str = ""
    folders_scanned: int = 0
    messages_fetched: int = 0
    candidates: int = 0
    skipped_folders: list[str] = field(default_factory=list)


class ScanCancelled(Exception):
    pass


ProgressFn = Callable[[ScanProgress], None]
SessionOpener = Callable[[Account], ReadOnlySession]


def make_session_opener(
    credentials: CredentialStore,
    *,
    imap_factory: ImapFactory | None = None,
    oauth_http_post: HttpPost | None = None,
    token_cache: GmailTokenCache | None = None,
) -> SessionOpener:
    """Return a function that opens an authenticated read-only session."""
    cache = token_cache or GmailTokenCache()

    def open_session(account: Account) -> ReadOnlySession:
        provider = get_provider(account.provider)
        try:
            if provider.auth == AUTH_OAUTH2:
                refresh = credentials.get(account.id, KIND_GOOGLE_REFRESH)
                secret = credentials.get(account.id, KIND_GOOGLE_CLIENT_SECRET)
                if not refresh or not secret or not account.oauth_client_id:
                    raise MailboxError(MailboxError.KIND_AUTH, "not signed in with Google")
            else:
                password = credentials.get(account.id, KIND_PASSWORD)
                if not password:
                    raise MailboxError(MailboxError.KIND_AUTH, "no password stored")
        except CredentialStoreUnavailable as exc:
            raise MailboxError(MailboxError.KIND_AUTH, f"credential store unavailable: {exc}") from None

        if provider.auth == AUTH_OAUTH2:
            try:
                access_token = cache.get(
                    account.id, ClientConfig(account.oauth_client_id, secret), refresh, oauth_http_post
                )
            except OAuthError as exc:
                raise MailboxError(MailboxError.KIND_AUTH, f"Google token refresh failed ({exc.kind})") from None
        session = ReadOnlySession.connect(account.host, account.port, factory=imap_factory)
        try:
            if provider.auth == AUTH_OAUTH2:
                try:
                    session.login_xoauth2(account.email, access_token)
                except MailboxError:
                    cache.forget(account.id)
                    raise
            else:
                session.login_password(account.email, password)
        except BaseException:
            session.logout()
            raise
        return session

    return open_session


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise ScanCancelled()


def scan_account(
    storage: Storage,
    account: Account,
    open_session: SessionOpener,
    *,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
    now: datetime | None = None,
) -> AccountScanResult:
    """Scan the account's folders read-only and store subscription candidates."""
    result = AccountScanResult(account.id, account.display_name)
    report = progress or (lambda p: None)
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=max(1, account.scan_days))
    run_id = storage.start_scan_run(account.id)
    scanned_folders: list[str] = []
    log.info("Scan started for account %d (%s), %d folder(s)", account.id, account.provider, len(account.folders))
    try:
        report(ScanProgress(account.display_name, stage="connecting"))
        session = open_session(account)
        try:
            for folder in account.folders:
                _check_cancel(cancel)
                try:
                    status = session.examine(folder)
                except MailboxError as exc:
                    if exc.kind != MailboxError.KIND_PROTOCOL:
                        raise
                    log.warning("Folder skipped for account %d: %s", account.id, exc)
                    result.skipped_folders.append(folder)
                    continue
                report(ScanProgress(account.display_name, folder, stage="searching"))
                uids = session.search_since(since)
                if len(uids) > account.max_messages:
                    uids = uids[-account.max_messages:]  # newest messages have the highest UIDs
                candidates: list[ParsedMessage] = []
                for start in range(0, len(uids), FETCH_BATCH):
                    _check_cancel(cancel)
                    batch = uids[start : start + FETCH_BATCH]
                    for fetched in session.fetch_headers(batch, FETCH_FIELDS):
                        result.messages_fetched += 1
                        raw = find_header_section(fetched)
                        if raw is None:
                            continue
                        parsed = _parse_candidate(raw, fetched.uid, folder, status.uidvalidity,
                                                  fetched.internaldate, account)
                        if parsed is not None:
                            candidates.append(parsed)
                    report(ScanProgress(account.display_name, folder, min(start + len(batch), len(uids)),
                                        len(uids), "fetching"))
                report(ScanProgress(account.display_name, folder, len(uids), len(uids), "saving"))
                storage.replace_folder_messages(account.id, folder, status.uidvalidity, candidates, run_id)
                scanned_folders.append(folder)
                result.folders_scanned += 1
                result.candidates += len(candidates)
        finally:
            session.logout()
        storage.drop_unscanned_folders(account.id, scanned_folders + result.skipped_folders)
    except ScanCancelled:
        result.status = "cancelled"
    except MailboxError as exc:
        result.status, result.error_kind, result.error_message = "error", exc.kind, str(exc)
        log.warning("Scan failed for account %d: %s (%s)", account.id, exc.kind, exc)
    except Exception as exc:  # unexpected: keep the app alive, keep details in the log
        result.status, result.error_kind, result.error_message = "error", "internal", type(exc).__name__
        log.exception("Unexpected error while scanning account %d", account.id)
    storage.finish_scan_run(run_id, result.status, result.folders_scanned, result.messages_fetched,
                            result.candidates, result.error_kind)
    log.info("Scan finished for account %d: status=%s folders=%d fetched=%d candidates=%d",
             account.id, result.status, result.folders_scanned, result.messages_fetched, result.candidates)
    report(ScanProgress(account.display_name, stage="done"))
    return result


def _parse_candidate(raw: bytes, uid: int, folder: str, uidvalidity: int,
                     internaldate: datetime | None, account: Account) -> ParsedMessage | None:
    try:
        parsed, headers = parse_message_headers(raw, uid=uid, folder=folder, uidvalidity=uidvalidity,
                                                internaldate=internaldate)
    except Exception:  # one hostile message must not stop the scan
        log.warning("Could not parse headers of one message in account %d", account.id)
        return None
    if not parsed.is_candidate:
        return None
    evidence = evaluate_provider_evidence(
        headers, account.trusted_authserv_ids, parsed.from_domain,
        needs_post=bool(parsed.list_unsubscribe_post_raw),
    )
    parsed.provider_status = evidence.status
    parsed.provider_reasons = evidence.reasons
    parsed.provider_signer = evidence.signer
    return parsed


@dataclass
class VerifyResult:
    subscription_key: str
    account_id: int
    status: CheckStatus
    reasons: list[str]
    error_kind: str = ""


def verify_subscriptions(
    storage: Storage,
    subscriptions: list[Subscription],
    accounts: dict[int, Account],
    open_session: SessionOpener,
    *,
    dnsfunc: DnsFunc | None = None,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
) -> list[VerifyResult]:
    """Fetch the newest message of each subscription (BODY.PEEK[]) and verify DKIM locally."""
    report = progress or (lambda p: None)
    results: list[VerifyResult] = []
    by_account: dict[int, list[Subscription]] = {}
    for sub in subscriptions:
        by_account.setdefault(sub.account_id, []).append(sub)
    for account_id, subs in by_account.items():
        account = accounts.get(account_id)
        if account is None:
            continue
        try:
            _check_cancel(cancel)
            session = open_session(account)
        except ScanCancelled:
            break
        except MailboxError as exc:
            results.extend(VerifyResult(s.key, account_id, CheckStatus.NOT_RUN, [], exc.kind) for s in subs)
            continue
        try:
            current_folder: str | None = None
            current_validity = 0
            for index, sub in enumerate(subs):
                _check_cancel(cancel)
                report(ScanProgress(account.display_name, sub.latest_ref["folder"], index, len(subs), "verifying"))
                ref = sub.latest_ref
                row = storage.get_message_row(ref["message_row_id"]) if ref.get("message_row_id") else None
                if row is None:
                    results.append(VerifyResult(sub.key, account_id, CheckStatus.NOT_RUN, [R_MESSAGE_NOT_FOUND]))
                    continue
                if ref["folder"] != current_folder:
                    current_validity = session.examine(ref["folder"]).uidvalidity
                    current_folder = ref["folder"]
                if current_validity != ref["uidvalidity"]:
                    outcome = (CheckStatus.FAIL, [R_UIDVALIDITY_CHANGED], "")
                else:
                    outcome = _verify_one(session, ref["uid"], row, dnsfunc)
                status, reasons, signer = outcome
                storage.set_local_result(row["id"], status, reasons, signer)
                results.append(VerifyResult(sub.key, account_id, status, reasons))
        except ScanCancelled:
            break
        except MailboxError as exc:
            log.warning("Verification stopped for account %d: %s", account_id, exc.kind)
            done = {r.subscription_key for r in results if r.account_id == account_id}
            results.extend(VerifyResult(s.key, account_id, CheckStatus.NOT_RUN, [], exc.kind)
                           for s in subs if s.key not in done)
        finally:
            session.logout()
    report(ScanProgress("", stage="done"))
    return results


def _verify_one(session: ReadOnlySession, uid: int, row: dict, dnsfunc: DnsFunc | None):
    size = session.fetch_size(uid)
    if size is None:
        return CheckStatus.FAIL, [R_MESSAGE_NOT_FOUND], ""
    if size > MAX_VERIFY_BYTES:
        return CheckStatus.FAIL, [R_TOO_LARGE], ""
    raw = session.fetch_full(uid)
    if raw is None:
        return CheckStatus.FAIL, [R_MESSAGE_NOT_FOUND], ""
    outcome = verify_message(raw, row["from_domain"], bool(row["list_unsubscribe_post"]), dnsfunc)
    return outcome.status, outcome.reasons, outcome.signer
