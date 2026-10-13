"""SQLite storage for accounts (no secrets), scan runs and header metadata.

Open one :class:`Storage` per thread. The database contains personal data
(sender addresses, subjects, dates, List-* header values including unsubscribe
URLs that may carry personal tokens). It stays in the local user profile.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from local_mail_cleaner.grouping import subscription_key
from local_mail_cleaner.models import (
    Account,
    CheckStatus,
    ParsedMessage,
    UnsubTarget,
)
from local_mail_cleaner.verification import classify_method, combine

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL,
    email TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 993,
    folders_json TEXT NOT NULL DEFAULT '["INBOX"]',
    scan_days INTEGER NOT NULL DEFAULT 365,
    max_messages INTEGER NOT NULL DEFAULT 5000,
    oauth_client_id TEXT NOT NULL DEFAULT '',
    trusted_authserv_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    folders_scanned INTEGER NOT NULL DEFAULT 0,
    messages_fetched INTEGER NOT NULL DEFAULT 0,
    candidates INTEGER NOT NULL DEFAULT 0,
    error_kind TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    message_id TEXT NOT NULL DEFAULT '',
    from_addr TEXT NOT NULL DEFAULT '',
    from_name TEXT NOT NULL DEFAULT '',
    from_domain TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    date_utc TEXT,
    list_id TEXT NOT NULL DEFAULT '',
    list_id_desc TEXT NOT NULL DEFAULT '',
    list_unsubscribe TEXT NOT NULL DEFAULT '',
    list_unsubscribe_post TEXT NOT NULL DEFAULT '',
    one_click_post INTEGER NOT NULL DEFAULT 0,
    targets_json TEXT NOT NULL DEFAULT '[]',
    header_problems_json TEXT NOT NULL DEFAULT '[]',
    dkim_signature_count INTEGER NOT NULL DEFAULT 0,
    provider_status TEXT NOT NULL DEFAULT 'not_run',
    provider_reasons_json TEXT NOT NULL DEFAULT '[]',
    provider_signer TEXT NOT NULL DEFAULT '',
    local_status TEXT NOT NULL DEFAULT 'not_run',
    local_reasons_json TEXT NOT NULL DEFAULT '[]',
    local_signer TEXT NOT NULL DEFAULT '',
    local_checked_at TEXT NOT NULL DEFAULT '',
    subscription_key TEXT,
    scan_run_id INTEGER,
    UNIQUE (account_id, folder, uidvalidity, uid)
);
CREATE INDEX IF NOT EXISTS idx_messages_account_key ON messages(account_id, subscription_key);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def _migrate(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError("database was created by a newer version of the application")
        if version < 1:
            with self.conn:
                self.conn.executescript(_SCHEMA)
                self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # -- accounts ------------------------------------------------------------

    @staticmethod
    def _account_from_row(row: sqlite3.Row) -> Account:
        return Account(
            id=row["id"],
            provider=row["provider"],
            email=row["email"],
            label=row["label"],
            host=row["host"],
            port=row["port"],
            folders=json.loads(row["folders_json"]),
            scan_days=row["scan_days"],
            max_messages=row["max_messages"],
            oauth_client_id=row["oauth_client_id"],
            trusted_authserv_ids=json.loads(row["trusted_authserv_json"]),
        )

    def list_accounts(self) -> list[Account]:
        rows = self.conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
        return [self._account_from_row(r) for r in rows]

    def get_account(self, account_id: int) -> Account | None:
        row = self.conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self._account_from_row(row) if row else None

    def save_account(self, account: Account) -> int:
        values = (
            account.provider, account.email, account.label, account.host, int(account.port),
            json.dumps(account.folders), int(account.scan_days), int(account.max_messages),
            account.oauth_client_id, json.dumps(account.trusted_authserv_ids),
        )
        with self.conn:
            if account.id is None:
                cur = self.conn.execute(
                    "INSERT INTO accounts (provider, email, label, host, port, folders_json, scan_days,"
                    " max_messages, oauth_client_id, trusted_authserv_json, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    values + (_now(), _now()),
                )
                account.id = int(cur.lastrowid)
            else:
                self.conn.execute(
                    "UPDATE accounts SET provider=?, email=?, label=?, host=?, port=?, folders_json=?,"
                    " scan_days=?, max_messages=?, oauth_client_id=?, trusted_authserv_json=?, updated_at=?"
                    " WHERE id=?",
                    values + (_now(), account.id),
                )
        return account.id

    def delete_account(self, account_id: int) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))

    # -- scan runs -----------------------------------------------------------

    def start_scan_run(self, account_id: int) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO scan_runs (account_id, started_at) VALUES (?, ?)", (account_id, _now())
            )
        return int(cur.lastrowid)

    def finish_scan_run(self, run_id: int, status: str, folders: int, fetched: int, candidates: int,
                        error_kind: str = "") -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE scan_runs SET finished_at=?, status=?, folders_scanned=?, messages_fetched=?,"
                " candidates=?, error_kind=? WHERE id=?",
                (_now(), status, folders, fetched, candidates, error_kind, run_id),
            )

    def last_scan_runs(self) -> dict[int, sqlite3.Row]:
        rows = self.conn.execute(
            "SELECT * FROM scan_runs WHERE id IN (SELECT MAX(id) FROM scan_runs GROUP BY account_id)"
        ).fetchall()
        return {r["account_id"]: r for r in rows}

    # -- messages ------------------------------------------------------------

    def replace_folder_messages(self, account_id: int, folder: str, uidvalidity: int,
                                messages: list[ParsedMessage], run_id: int) -> None:
        """Upsert this folder's candidates and drop rows the scan no longer saw.

        Local DKIM results of messages that are still present are kept.
        """
        with self.conn:
            for msg in messages:
                targets = [{"scheme": t.scheme, "host": t.host, "problems": list(t.problems)}
                           for t in msg.targets]
                key = subscription_key(msg.list_id, msg.from_addr, targets, bool(msg.list_unsubscribe_raw))
                self.conn.execute(
                    """INSERT INTO messages (account_id, folder, uidvalidity, uid, message_id, from_addr,
                        from_name, from_domain, subject, date_utc, list_id, list_id_desc, list_unsubscribe,
                        list_unsubscribe_post, one_click_post, targets_json, header_problems_json,
                        dkim_signature_count, provider_status, provider_reasons_json, provider_signer,
                        subscription_key, scan_run_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT (account_id, folder, uidvalidity, uid) DO UPDATE SET
                        message_id=excluded.message_id, from_addr=excluded.from_addr,
                        from_name=excluded.from_name, from_domain=excluded.from_domain,
                        subject=excluded.subject, date_utc=excluded.date_utc, list_id=excluded.list_id,
                        list_id_desc=excluded.list_id_desc, list_unsubscribe=excluded.list_unsubscribe,
                        list_unsubscribe_post=excluded.list_unsubscribe_post,
                        one_click_post=excluded.one_click_post, targets_json=excluded.targets_json,
                        header_problems_json=excluded.header_problems_json,
                        dkim_signature_count=excluded.dkim_signature_count,
                        provider_status=excluded.provider_status,
                        provider_reasons_json=excluded.provider_reasons_json,
                        provider_signer=excluded.provider_signer,
                        subscription_key=excluded.subscription_key, scan_run_id=excluded.scan_run_id""",
                    (
                        account_id, folder, uidvalidity, msg.uid, msg.message_id, msg.from_addr,
                        msg.from_name, msg.from_domain, msg.subject,
                        msg.date.isoformat() if msg.date else None, msg.list_id, msg.list_id_desc,
                        msg.list_unsubscribe_raw, msg.list_unsubscribe_post_raw, int(msg.one_click_post),
                        json.dumps(targets), json.dumps(msg.header_problems), msg.dkim_signature_count,
                        msg.provider_status.value, json.dumps(msg.provider_reasons), msg.provider_signer,
                        key, run_id,
                    ),
                )
            self.conn.execute(
                "DELETE FROM messages WHERE account_id=? AND folder=? AND (scan_run_id IS NOT ? OR uidvalidity != ?)",
                (account_id, folder, run_id, uidvalidity),
            )

    def drop_unscanned_folders(self, account_id: int, folders: list[str]) -> None:
        placeholders = ",".join("?" for _ in folders) or "''"
        with self.conn:
            self.conn.execute(
                f"DELETE FROM messages WHERE account_id=? AND folder NOT IN ({placeholders})",
                (account_id, *folders),
            )

    def set_local_result(self, message_row_id: int, status: CheckStatus, reasons: list[str], signer: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE messages SET local_status=?, local_reasons_json=?, local_signer=?, local_checked_at=?"
                " WHERE id=?",
                (status.value, json.dumps(reasons), signer, _now(), message_row_id),
            )

    def get_message_row(self, message_row_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM messages WHERE id = ?", (message_row_id,)).fetchone()
        return self._message_dict(row) if row else None

    def load_message_rows(self, account_id: int | None = None) -> list[dict]:
        if account_id is None:
            rows = self.conn.execute("SELECT * FROM messages").fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM messages WHERE account_id = ?", (account_id,)).fetchall()
        return [self._message_dict(r) for r in rows]

    @staticmethod
    def _message_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["date"] = datetime.fromisoformat(row["date_utc"]) if row["date_utc"] else None
        data["targets"] = json.loads(row["targets_json"])
        data["header_problems"] = json.loads(row["header_problems_json"])
        data["provider_reasons"] = json.loads(row["provider_reasons_json"])
        data["local_reasons"] = json.loads(row["local_reasons_json"])
        targets = [UnsubTarget(t["scheme"], "", t["host"], tuple(t["problems"])) for t in data["targets"]]
        method, has_mailto = classify_method(targets, bool(row["one_click_post"]))
        verification, reasons = combine(
            method,
            data["header_problems"],
            CheckStatus(row["provider_status"]),
            data["provider_reasons"],
            CheckStatus(row["local_status"]),
            data["local_reasons"],
        )
        data["method"] = method.value
        data["has_mailto"] = has_mailto
        data["verification"] = verification.value
        data["reasons"] = reasons
        return data

    def stats(self) -> dict[str, int]:
        accounts = self.conn.execute("SELECT provider, COUNT(*) FROM accounts GROUP BY provider").fetchall()
        messages = self.conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        return {**{f"accounts_{r[0]}": r[1] for r in accounts}, "messages": messages}

    def delete_all_scan_data(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM messages")
            self.conn.execute("DELETE FROM scan_runs")
