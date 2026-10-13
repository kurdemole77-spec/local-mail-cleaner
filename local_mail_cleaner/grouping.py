"""Grouping of messages into subscriptions.

A subscription is identified per mailbox account, never by sender address
alone:

1. ``List-ID`` when present (RFC 2919) - one list, whatever the sender;
2. otherwise sender address + unsubscribe destination host (scheme:host);
   hosts are used instead of full URLs because paths/queries usually carry
   per-message tokens.

Messages without List-ID and without List-Unsubscribe are not subscriptions.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from local_mail_cleaner.models import (
    CheckStatus,
    Subscription,
    UnsubMethod,
    Verification,
)


def subscription_key(list_id: str, from_addr: str, targets: list[dict], has_unsub_header: bool = False) -> str | None:
    if list_id:
        return f"list-id:{list_id}"
    if not targets:
        # A present but unparseable List-Unsubscribe still marks a mailing.
        return f"sender:{from_addr or '?'}|unsub:invalid" if has_unsub_header else None
    preferred = sorted(targets, key=lambda t: {"https": 0, "http": 1, "mailto": 2}.get(t["scheme"], 3))
    first = preferred[0]
    return f"sender:{from_addr or '?'}|unsub:{first['scheme']}:{first['host'] or '?'}"


def aggregate(rows: Iterable[dict], account_names: dict[int, str]) -> list[Subscription]:
    """Build subscriptions from stored message rows (see storage.load_message_rows).

    Each row must already carry ``method``, ``verification`` and ``reasons``.
    Duplicate copies of a message (same Message-ID in several folders of one
    account, e.g. Gmail labels) are counted once.
    """
    groups: dict[tuple[int, str], dict] = {}
    for row in rows:
        key = row["subscription_key"]
        if not key:
            continue
        gkey = (row["account_id"], key)
        group = groups.setdefault(gkey, {"seen": set(), "count": 0, "latest": None})
        identity = row["message_id"] or f"{row['folder']}/{row['uidvalidity']}/{row['uid']}"
        if identity in group["seen"]:
            continue
        group["seen"].add(identity)
        group["count"] += 1
        latest = group["latest"]
        if latest is None or _sort_date(row) > _sort_date(latest):
            group["latest"] = row

    subscriptions: list[Subscription] = []
    for (account_id, key), group in groups.items():
        row = group["latest"]
        subscriptions.append(
            Subscription(
                key=key,
                account_id=account_id,
                account_name=account_names.get(account_id, str(account_id)),
                sender_name=row["from_name"],
                sender_addr=row["from_addr"],
                list_id=row["list_id"],
                list_desc=row["list_id_desc"],
                message_count=group["count"],
                latest_date=row["date"],
                latest_subject=row["subject"],
                method=UnsubMethod(row["method"]),
                has_mailto=bool(row["has_mailto"]),
                verification=Verification(row["verification"]),
                reasons=list(row["reasons"]),
                targets=list(row["targets"]),
                latest_ref={
                    "account_id": account_id,
                    "folder": row["folder"],
                    "uidvalidity": row["uidvalidity"],
                    "uid": row["uid"],
                    "message_row_id": row.get("id"),
                },
                local_status=CheckStatus(row.get("local_status") or CheckStatus.NOT_RUN.value),
                local_checked_at=row.get("local_checked_at") or "",
            )
        )
    subscriptions.sort(key=lambda s: (s.account_name.lower(), -s.message_count, s.sender_addr))
    return subscriptions


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _sort_date(row: dict) -> tuple[datetime, int]:
    return (row["date"] or _EPOCH, row["uid"])
