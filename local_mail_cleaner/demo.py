"""Synthetic demo mailbox and an in-memory read-only session.

Everything here is invented: only reserved example domains (RFC 2606) and
fake signatures are used. Demo mode never touches the network, the OS
credential store or any real mailbox.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

from local_mail_cleaner.imap_readonly import (
    FetchedMessage,
    FolderInfo,
    FolderStatus,
    ReadOnlyViolation,
    check_fetch_items,
)
from local_mail_cleaner.models import Account

DEMO_USER_GMAIL = "uzytkownik@example.com"
DEMO_USER_IONOS = "biuro@example.net"


def fake_b64(seed: str, length: int = 88) -> str:
    """Deterministic base64 text that looks like a signature but is not one."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return base64.b64encode(out).decode("ascii")[:length]


def dkim_header(d: str, s: str, signed: Sequence[str], b: str, a: str = "rsa-sha256", extra: str = "") -> str:
    return (
        f"v=1; a={a}; c=relaxed/relaxed; d={d}; s={s};{extra}\r\n"
        f"\th={':'.join(signed)};\r\n\tbh={fake_b64('bh' + b, 44)};\r\n\tb={b}"
    )


def build_message(
    *,
    from_header: str,
    subject: str,
    date: datetime,
    message_id: str,
    to: str = DEMO_USER_GMAIL,
    list_id: str | None = None,
    list_unsubscribe: str | Sequence[str] | None = None,
    list_unsubscribe_post: str | None = None,
    dkim_signatures: Sequence[str] = (),
    auth_results: Sequence[str] = (),
    extra_headers: Sequence[tuple[str, str]] = (),
    body: str = "To jest syntetyczna wiadomosc testowa.\r\n",
) -> bytes:
    """Assemble an RFC 5322 message (CRLF line endings). Order: top to bottom."""
    lines: list[str] = []
    for value in auth_results:
        lines.append(f"Authentication-Results: {value}")
    for value in dkim_signatures:
        lines.append(f"DKIM-Signature: {value}")
    lines += [
        f"From: {from_header}",
        f"To: {to}",
        f"Subject: {subject}",
        f"Date: {format_datetime(date)}",
        f"Message-ID: {message_id}",
    ]
    if list_id:
        lines.append(f"List-ID: {list_id}")
    if list_unsubscribe is not None:
        values = [list_unsubscribe] if isinstance(list_unsubscribe, str) else list(list_unsubscribe)
        lines += [f"List-Unsubscribe: {v}" for v in values]
    if list_unsubscribe_post is not None:
        lines.append(f"List-Unsubscribe-Post: {list_unsubscribe_post}")
    lines += [f"{k}: {v}" for k, v in extra_headers]
    lines += ["MIME-Version: 1.0", 'Content-Type: text/plain; charset="utf-8"']
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")


@dataclass
class StoredMessage:
    uid: int
    raw: bytes = field(repr=False)
    internaldate: datetime
    flags: set[str] = field(default_factory=set)


def extract_header_fields(raw: bytes, fields: Iterable[str]) -> bytes:
    """Return the requested header fields (all occurrences, original order)."""
    wanted = {f.lower() for f in fields}
    head = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)[0]
    out: list[bytes] = []
    keep = False
    for line in re.split(rb"\r?\n", head):
        if line[:1] in (b" ", b"\t"):
            if keep:
                out.append(line)
            continue
        name = line.split(b":", 1)[0].strip().lower().decode("ascii", "replace")
        keep = name in wanted
        if keep:
            out.append(line)
    return b"\r\n".join(out) + b"\r\n\r\n"


class DemoSession:
    """In-memory stand-in for :class:`ReadOnlySession` (same read-only API)."""

    def __init__(self, folders: dict[str, list[StoredMessage]], uidvalidity: int = 1):
        self.folders = folders
        self.uidvalidity = uidvalidity
        self.selected: str | None = None
        self.commands: list[str] = []

    def __enter__(self) -> "DemoSession":
        return self

    def __exit__(self, *exc_info) -> None:
        self.logout()

    def logout(self) -> None:
        self.commands.append("LOGOUT")

    def list_folders(self) -> list[FolderInfo]:
        self.commands.append("LIST")
        return [FolderInfo(name, ("\\HasNoChildren",)) for name in self.folders]

    def examine(self, folder: str) -> FolderStatus:
        from local_mail_cleaner.imap_readonly import MailboxError

        self.commands.append(f"EXAMINE {folder}")
        if folder not in self.folders:
            raise MailboxError(MailboxError.KIND_PROTOCOL, "no such folder")
        self.selected = folder
        return FolderStatus(folder, self.uidvalidity, len(self.folders[folder]))

    def _messages(self) -> list[StoredMessage]:
        if self.selected is None:
            raise ReadOnlyViolation("no folder opened with EXAMINE")
        return self.folders[self.selected]

    def search_since(self, since: datetime) -> list[int]:
        self.commands.append("UID SEARCH SINCE")
        return sorted(m.uid for m in self._messages() if m.internaldate.date() >= since.date())

    def fetch_headers(self, uids: list[int], fields: Iterable[str]) -> list[FetchedMessage]:
        fields = list(fields)
        spec = "(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (" + " ".join(fields) + ")])"
        check_fetch_items(spec)
        self.commands.append("UID FETCH " + spec)
        key = "BODY[HEADER.FIELDS (" + " ".join(f.upper() for f in fields) + ")]"
        wanted = set(uids)
        return [
            FetchedMessage(m.uid, m.internaldate, len(m.raw), {key: extract_header_fields(m.raw, fields)})
            for m in self._messages() if m.uid in wanted
        ]

    def fetch_size(self, uid: int) -> int | None:
        check_fetch_items("(UID RFC822.SIZE)")
        self.commands.append("UID FETCH (UID RFC822.SIZE)")
        return next((len(m.raw) for m in self._messages() if m.uid == uid), None)

    def fetch_full(self, uid: int) -> bytes | None:
        check_fetch_items("(UID BODY.PEEK[])")
        self.commands.append("UID FETCH (UID BODY.PEEK[])")
        return next((m.raw for m in self._messages() if m.uid == uid), None)


# --------------------------------------------------------------------------
# Demo data set
# --------------------------------------------------------------------------

GMAIL_AR = "mx.google.com"


def _gmail_ar(result: str, domain: str, b: str, selector: str = "s2026") -> str:
    return (
        f"{GMAIL_AR};\r\n       dkim={result} header.i=@{domain} header.s={selector} header.b={b[:8]};\r\n"
        f"       spf=pass (google.com: domain of bounce@{domain} designates 192.0.2.10 as permitted sender)"
        f" smtp.mailfrom=bounce@{domain};\r\n       dmarc=pass (p=REJECT) header.from={domain}"
    )


SIGNED_ALL = ("from", "to", "subject", "date", "message-id", "list-id", "list-unsubscribe", "list-unsubscribe-post")
SIGNED_NO_POST = ("from", "to", "subject", "date", "message-id", "list-id", "list-unsubscribe")
SIGNED_NO_LIST = ("from", "to", "subject", "date", "message-id")


def _series(now: datetime, count: int, every_days: int, start_days_ago: int = 3) -> list[datetime]:
    return [now - timedelta(days=start_days_ago + i * every_days, hours=i % 5) for i in range(count)]


def demo_mailboxes(now: datetime | None = None) -> dict[str, dict[str, list[StoredMessage]]]:
    """Return {account_key: {folder: [messages]}} with synthetic newsletters."""
    now = now or datetime.now(timezone.utc)
    gmail: dict[str, list[StoredMessage]] = {"INBOX": [], "[Gmail]/Wszystkie": []}
    ionos: dict[str, list[StoredMessage]] = {"INBOX": [], "Newslettery": []}
    counters = {"gmail": 100, "ionos": 500}

    def add(box: dict, folder: str, account: str, raw: bytes, when: datetime) -> None:
        counters[account] += 1
        box[folder].append(StoredMessage(counters[account], raw, when))

    # A. One-click, Gmail-verified; copies also in the "All mail" label (counted once).
    for i, when in enumerate(_series(now, 8, 7)):
        b = fake_b64(f"promo{i}")
        raw = build_message(
            from_header='"Sklep Przyklad" <promocje@sklep.example.com>',
            subject=f"Promocje tygodnia nr {40 - i}", date=when,
            message_id=f"<promo-{i}@sklep.example.com>",
            list_id='"Promocje Sklepu" <promocje.sklep.example.com>',
            list_unsubscribe=f"<https://sklep.example.com/u/one-click?t={fake_b64('t'+str(i), 24)}>,\r\n"
                             " <mailto:wypisz@sklep.example.com?subject=unsubscribe>",
            list_unsubscribe_post="List-Unsubscribe=One-Click",
            dkim_signatures=[dkim_header("sklep.example.com", "s2026", SIGNED_ALL, b)],
            auth_results=[_gmail_ar("pass", "sklep.example.com", b)],
        )
        add(gmail, "INBOX", "gmail", raw, when)
        if i < 4:
            add(gmail, "[Gmail]/Wszystkie", "gmail", raw, when)

    # B. Same sender address, different List-ID: a separate subscription.
    for i, when in enumerate(_series(now, 4, 14, 5)):
        b = fake_b64(f"nowosci{i}")
        add(gmail, "INBOX", "gmail", build_message(
            from_header='"Sklep Przyklad" <promocje@sklep.example.com>',
            subject=f"Nowosci w sklepie ({i + 1})", date=when,
            message_id=f"<nowosci-{i}@sklep.example.com>",
            list_id="<nowosci.sklep.example.com>",
            list_unsubscribe=f"<https://sklep.example.com/preferencje?u={fake_b64('n'+str(i), 16)}>",
            dkim_signatures=[dkim_header("sklep.example.com", "s2026", SIGNED_NO_POST, b)],
            auth_results=[_gmail_ar("pass", "sklep.example.com", b)],
        ), when)

    # C. One-click offered, but List-Unsubscribe-Post is not signed.
    for i, when in enumerate(_series(now, 5, 10, 2)):
        b = fake_b64(f"kuchnia{i}")
        add(gmail, "INBOX", "gmail", build_message(
            from_header='"Blog Kulinarny" <newsletter@kuchnia.example.org>',
            subject=f"Przepis tygodnia: zupa nr {i + 1}", date=when,
            message_id=f"<kuchnia-{i}@kuchnia.example.org>",
            list_unsubscribe=f"<https://lists.kuchnia.example.org/unsub/{fake_b64('k'+str(i), 20)}>",
            list_unsubscribe_post="List-Unsubscribe=One-Click",
            dkim_signatures=[dkim_header("kuchnia.example.org", "k1", SIGNED_NO_POST, b)],
            auth_results=[_gmail_ar("pass", "kuchnia.example.org", b, "k1")],
        ), when)

    # D. mailto only, no DKIM signature.
    for i, when in enumerate(_series(now, 3, 30, 9)):
        add(gmail, "INBOX", "gmail", build_message(
            from_header='"Klub Ksiazki" <klub@ksiazki.example.org>',
            subject=f"Ksiazka miesiaca ({i + 1})", date=when,
            message_id=f"<ksiazki-{i}@ksiazki.example.org>",
            list_id="Klub Ksiazki <klub.ksiazki.example.org>",
            list_unsubscribe="<mailto:wypisz@ksiazki.example.org?subject=wypisz>",
            auth_results=[f"{GMAIL_AR}; dkim=none; spf=pass smtp.mailfrom=ksiazki.example.org"],
        ), when)

    # E. Forged "pass" below the provider's real (failing) result.
    for i, when in enumerate(_series(now, 2, 20, 4)):
        b = fake_b64(f"bank{i}")
        add(gmail, "INBOX", "gmail", build_message(
            from_header='"Bank Przykladowy" <powiadomienia@bank.example.net>',
            subject="Wazne: potwierdz swoje dane", date=when,
            message_id=f"<bank-{i}@bank.example.net>",
            list_unsubscribe="<https://bank.example.net/wypisz?id=1>",
            list_unsubscribe_post="List-Unsubscribe=One-Click",
            dkim_signatures=[dkim_header("bank.example.net", "x", SIGNED_ALL, b)],
            auth_results=[_gmail_ar("fail", "bank.example.net", b, "x"), _gmail_ar("pass", "bank.example.net", b, "x")],
        ), when)

    # F. Duplicate List-Unsubscribe headers (header injection attempt).
    for i, when in enumerate(_series(now, 3, 6, 1)):
        b = fake_b64(f"gazeta{i}")
        add(gmail, "INBOX", "gmail", build_message(
            from_header='"Gazeta Codzienna" <wydanie@gazeta.example.com>',
            subject=f"Wydanie poranne {i + 1}", date=when,
            message_id=f"<gazeta-{i}@gazeta.example.com>",
            list_id="<poranna.gazeta.example.com>",
            list_unsubscribe=["<https://inny-serwer.example.net/x>", "<https://gazeta.example.com/wypisz>"],
            list_unsubscribe_post="List-Unsubscribe=One-Click",
            dkim_signatures=[dkim_header("gazeta.example.com", "g", SIGNED_ALL, b)],
            auth_results=[_gmail_ar("pass", "gazeta.example.com", b, "g")],
        ), when)

    # G. Only unsafe destinations (loopback / private network).
    for i, when in enumerate(_series(now, 2, 15, 8)):
        add(gmail, "INBOX", "gmail", build_message(
            from_header='"Okazje 24" <okazje@okazje.example.com>',
            subject="Ostatnia szansa!", date=when, message_id=f"<okazje-{i}@okazje.example.com>",
            list_unsubscribe="<https://127.0.0.1/unsub>, <http://192.168.0.10/u>",
        ), when)

    # H. Personal mail without list headers: not a subscription.
    for i, when in enumerate(_series(now, 3, 11, 1)):
        add(gmail, "INBOX", "gmail", build_message(
            from_header='"Anna" <anna@example.org>', subject="Spotkanie w piatek?", date=when,
            message_id=f"<anna-{i}@example.org>",
        ), when)

    # I. Valid-looking provider pass, but the signer is a third party.
    for i, when in enumerate(_series(now, 4, 12, 6)):
        b = fake_b64(f"podroze{i}")
        add(gmail, "INBOX", "gmail", build_message(
            from_header='"Biuro Podrozy" <oferty@podroze.example.org>',
            subject=f"Last minute: oferta {i + 1}", date=when,
            message_id=f"<podroze-{i}@podroze.example.org>",
            list_id="<oferty.podroze.example.org>",
            list_unsubscribe="<https://esp-mailer.example.net/u/abc>",
            list_unsubscribe_post="List-Unsubscribe=One-Click",
            dkim_signatures=[dkim_header("esp-mailer.example.net", "esp", SIGNED_ALL, b)],
            auth_results=[_gmail_ar("pass", "esp-mailer.example.net", b, "esp")],
        ), when)

    # K. IONOS: signature present, but no trusted provider evidence.
    for i, when in enumerate(_series(now, 6, 9, 2)):
        b = fake_b64(f"tech{i}")
        add(ionos, "Newslettery", "ionos", build_message(
            from_header='"Portal Technologiczny" <redakcja@portal.example.com>', to=DEMO_USER_IONOS,
            subject=f"Tydzien w technologii #{120 - i}", date=when,
            message_id=f"<tech-{i}@portal.example.com>",
            list_id="Portal Tech <tech.portal.example.com>",
            list_unsubscribe=f"<https://portal.example.com/newsletter/wypisz?k={fake_b64('p'+str(i), 20)}>",
            list_unsubscribe_post="List-Unsubscribe=One-Click",
            dkim_signatures=[dkim_header("portal.example.com", "p1", SIGNED_ALL, b)],
        ), when)

    # L. Unencrypted http link.
    for i, when in enumerate(_series(now, 2, 40, 20)):
        add(ionos, "INBOX", "ionos", build_message(
            from_header="Stara Lista <lista@old.example.org>", to=DEMO_USER_IONOS,
            subject=f"Biuletyn {i + 1}", date=when, message_id=f"<old-{i}@old.example.org>",
            list_unsubscribe="<http://lists.old.example.org/unsub?u=7>",
        ), when)

    # M. Same sender, no List-ID, two different unsubscribe hosts: two groups.
    for i, when in enumerate(_series(now, 4, 8, 3)):
        host = "a.sport.example.com" if i % 2 == 0 else "b.sport.example.com"
        add(ionos, "INBOX", "ionos", build_message(
            from_header='"Sklep Sportowy" <info@sport.example.com>', to=DEMO_USER_IONOS,
            subject=f"Sport: oferta {i + 1}", date=when, message_id=f"<sport-{i}@sport.example.com>",
            list_unsubscribe=f"<https://{host}/wypisz>",
        ), when)

    # N. Malformed List-Unsubscribe (no angle brackets).
    for i, when in enumerate(_series(now, 2, 25, 10)):
        add(ionos, "INBOX", "ionos", build_message(
            from_header="Lokalna Gazetka <gazetka@gazetka.example.org>", to=DEMO_USER_IONOS,
            subject=f"Gazetka nr {i + 1}", date=when, message_id=f"<gazetka-{i}@gazetka.example.org>",
            list_unsubscribe="https://gazetka.example.org/unsub",
        ), when)

    return {"gmail": gmail, "ionos": ionos}


def demo_accounts() -> list[Account]:
    return [
        Account(provider="gmail", email=DEMO_USER_GMAIL, host="imap.gmail.com", label="Demo Gmail",
                folders=["INBOX", "[Gmail]/Wszystkie"], trusted_authserv_ids=["mx.google.com"]),
        Account(provider="ionos", email=DEMO_USER_IONOS, host="imap.ionos.de", label="Demo IONOS",
                folders=["INBOX", "Newslettery"], trusted_authserv_ids=[]),
    ]


def demo_dns_lookup(name: bytes, timeout: float = 5) -> bytes | None:
    """Demo DNS: no example domain publishes DKIM keys, so verification fails closed."""
    return None


class DemoSessionFactory:
    """Opens :class:`DemoSession` objects for the demo accounts."""

    def __init__(self, now: datetime | None = None):
        self.boxes = demo_mailboxes(now)
        self.sessions: list[DemoSession] = []

    def __call__(self, account: Account) -> DemoSession:
        session = DemoSession(self.boxes[account.provider])
        self.sessions.append(session)
        return session
