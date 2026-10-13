"""CSV export of the subscription table (no unsubscribe URLs)."""

from __future__ import annotations

import csv
from pathlib import Path

from local_mail_cleaner import strings_pl as S
from local_mail_cleaner.models import Subscription

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> str:
    """Neutralise spreadsheet formula injection from untrusted header text."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def export_csv(path: str | Path, subscriptions: list[Subscription]) -> int:
    header = [
        S.COLUMNS["mailbox"], S.COLUMNS["sender"], "Adres nadawcy", S.COLUMNS["list"],
        S.COLUMNS["count"], S.COLUMNS["latest"], S.COLUMNS["method"], S.COLUMNS["verification"],
        "Powody", "Serwery wypisania",
    ]
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(header)
        for sub in subscriptions:
            writer.writerow([csv_safe(v) for v in (
                sub.account_name,
                sub.sender_name,
                sub.sender_addr,
                sub.list_id,
                sub.message_count,
                sub.latest_date.strftime("%Y-%m-%d") if sub.latest_date else "",
                S.METHODS.get(sub.method.value, sub.method.value),
                S.VERIFICATION.get(sub.verification.value, sub.verification.value),
                "; ".join(S.reason_text(r) for r in sub.reasons),
                ", ".join(f"{t['scheme']}:{t['host']}" for t in sub.targets),
            )])
    return len(subscriptions)
