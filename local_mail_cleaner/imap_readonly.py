"""Read-only IMAP access.

Safety properties (stage A):

* folders are opened with ``EXAMINE`` (``select(readonly=True)``), never
  ``SELECT``; the server must confirm ``[READ-ONLY]`` or we stop (fail closed);
* message data is fetched only with ``BODY.PEEK[...]`` and metadata items,
  which do not set the ``\\Seen`` flag; every FETCH item list is validated
  against a whitelist before it is sent;
* only ``UID SEARCH`` and ``UID FETCH`` UID-commands are allowed; there is no
  code path that issues STORE, COPY, MOVE, EXPUNGE, APPEND, CREATE, DELETE,
  RENAME or CLOSE;
* TLS with certificate and host name verification is always used for real
  servers; imaplib protocol debugging (which would print credentials) is off.
"""

from __future__ import annotations

import base64
import imaplib
import logging
import re
import socket
import ssl
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime

from local_mail_cleaner.headers import imap_date, parse_internaldate

log = logging.getLogger(__name__)

imaplib.Debug = 0  # never print protocol traffic (it contains credentials)

DEFAULT_TIMEOUT = 30
FETCH_BATCH = 100


class ReadOnlyViolation(RuntimeError):
    """Raised when an operation would (or might) modify the mailbox."""


class MailboxError(RuntimeError):
    """User-facing mailbox error. ``kind`` is one of the KIND_* constants."""

    KIND_CONNECTION = "connection"
    KIND_TLS = "tls"
    KIND_AUTH = "auth"
    KIND_PROTOCOL = "protocol"
    KIND_READ_ONLY = "read_only"

    def __init__(self, kind: str, message: str = ""):
        super().__init__(message or kind)
        self.kind = kind


@dataclass(frozen=True)
class FolderInfo:
    name: str  # decoded (Unicode) name
    flags: tuple[str, ...] = ()

    @property
    def selectable(self) -> bool:
        return "\\noselect" not in {f.lower() for f in self.flags} and "\\nonexistent" not in {
            f.lower() for f in self.flags
        }


@dataclass(frozen=True)
class FolderStatus:
    name: str
    uidvalidity: int
    exists: int


@dataclass
class FetchedMessage:
    uid: int
    internaldate: datetime | None = None
    size: int | None = None
    sections: dict[str, bytes] = field(default_factory=dict, repr=False)


# --------------------------------------------------------------------------
# Modified UTF-7 (RFC 3501 section 5.1.3) for mailbox names
# --------------------------------------------------------------------------

def decode_mailbox_name(raw: bytes | str) -> str:
    text = raw.decode("ascii", errors="replace") if isinstance(raw, bytes) else raw

    def repl(match: re.Match) -> str:
        chunk = match.group(1)
        if not chunk:
            return "&"
        b64 = chunk.replace(",", "/")
        b64 += "=" * (-len(b64) % 4)
        try:
            return base64.b64decode(b64).decode("utf-16-be")
        except (ValueError, UnicodeDecodeError):
            return match.group(0)

    return re.sub(r"&([A-Za-z0-9+,]*)-", repl, text)


def encode_mailbox_name(name: str) -> str:
    out: list[str] = []
    buffer: list[str] = []

    def flush() -> None:
        if buffer:
            encoded = base64.b64encode("".join(buffer).encode("utf-16-be")).decode("ascii")
            out.append("&" + encoded.rstrip("=").replace("/", ",") + "-")
            buffer.clear()

    for ch in name:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buffer.append(ch)
    flush()
    return "".join(out)


def quote_mailbox(name: str) -> str:
    """Return the mailbox name as a quoted IMAP string (modified UTF-7)."""
    if re.search(r"[\x00-\x1f\x7f]", name):  # check before encoding hides control characters
        raise ValueError("invalid mailbox name")
    encoded = encode_mailbox_name(name)
    return '"' + encoded.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------------------
# FETCH item whitelist
# --------------------------------------------------------------------------

_ALLOWED_FETCH_ITEM = re.compile(
    r"^(UID|INTERNALDATE|RFC822\.SIZE|FLAGS"
    r"|BODY\.PEEK\[(HEADER|HEADER\.FIELDS \([A-Z0-9 -]+\))?\])$"
)


def split_fetch_items(spec: str) -> list[str]:
    spec = spec.strip()
    if spec.startswith("(") and spec.endswith(")"):
        spec = spec[1:-1]
    items: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in spec:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == " " and depth == 0:
            if current:
                items.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        items.append("".join(current))
    if depth != 0:
        raise ReadOnlyViolation("unbalanced FETCH item list")
    return items


def check_fetch_items(spec: str) -> None:
    """Raise :class:`ReadOnlyViolation` unless every item is known not to set \\Seen."""
    items = split_fetch_items(spec.upper())
    if not items:
        raise ReadOnlyViolation("empty FETCH item list")
    for item in items:
        if not _ALLOWED_FETCH_ITEM.match(item):
            raise ReadOnlyViolation(f"FETCH item not allowed in read-only mode: {item[:40]}")


def uid_set(uids: Iterable[int]) -> str:
    """Compress UIDs into an IMAP sequence set (``1:3,7``)."""
    ordered = sorted(set(int(u) for u in uids))
    if not ordered:
        raise ValueError("empty UID set")
    ranges: list[str] = []
    start = prev = ordered[0]
    for uid in ordered[1:]:
        if uid == prev + 1:
            prev = uid
            continue
        ranges.append(f"{start}:{prev}" if start != prev else str(start))
        start = prev = uid
    ranges.append(f"{start}:{prev}" if start != prev else str(start))
    return ",".join(ranges)


# --------------------------------------------------------------------------
# FETCH response parsing
# --------------------------------------------------------------------------

_MSG_START = re.compile(rb"^\s*\d+ \(")
_SECTION_BEFORE_LITERAL = re.compile(rb"(BODY\[[^\]]*\](?:<\d+>)?)\s*\{\d+\}\s*$", re.IGNORECASE)


def parse_fetch_response(data: list) -> list[FetchedMessage]:
    """Parse imaplib FETCH data (mix of tuples and bytes) into messages.

    Handles servers that put UID/INTERNALDATE after the literal, and ignores
    responses without a UID (e.g. unsolicited flag updates).
    """
    groups: list[dict] = []
    current: dict | None = None
    for item in data:
        if item is None:
            continue
        if isinstance(item, tuple):
            prefix = item[0] if isinstance(item[0], bytes) else bytes(item[0])
            literal = item[1] if len(item) > 1 and isinstance(item[1], bytes) else b""
            if _MSG_START.match(prefix) or current is None:
                current = {"meta": b"", "sections": {}}
                groups.append(current)
            section = _SECTION_BEFORE_LITERAL.search(prefix)
            if section:
                key = section.group(1).upper().decode("ascii", errors="replace")
                key = re.sub(r"<\d+>$", "", key)
                current["sections"][key] = literal
                prefix = prefix[: section.start()]
            current["meta"] += b" " + prefix
        elif isinstance(item, bytes):
            if _MSG_START.match(item) or current is None:
                current = {"meta": b"", "sections": {}}
                groups.append(current)
            current["meta"] += b" " + item
    messages: list[FetchedMessage] = []
    for group in groups:
        meta = group["meta"]
        uid_match = re.search(rb"\bUID (\d+)", meta)
        if not uid_match:
            continue
        msg = FetchedMessage(uid=int(uid_match.group(1)), sections=group["sections"])
        date_match = re.search(rb'INTERNALDATE "([^"]+)"', meta)
        if date_match:
            msg.internaldate = parse_internaldate(date_match.group(1).decode("ascii", "replace"))
        size_match = re.search(rb"RFC822\.SIZE (\d+)", meta)
        if size_match:
            msg.size = int(size_match.group(1))
        messages.append(msg)
    return messages


def find_header_section(msg: FetchedMessage) -> bytes | None:
    for key, value in msg.sections.items():
        if key.startswith("BODY[HEADER"):
            return value
    return None


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------

ImapFactory = Callable[[str, int, int], imaplib.IMAP4]

_LIST_LINE = re.compile(rb'^\((?P<flags>[^)]*)\) (?P<delim>"(?:[^"\\]|\\.)*"|NIL) ?(?P<name>.*)$', re.IGNORECASE)


def _default_factory(host: str, port: int, timeout: int) -> imaplib.IMAP4:
    context = ssl.create_default_context()  # verifies certificates and host names
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=timeout)


def _server_text(exc: BaseException) -> str:
    text = str(exc.args[0] if exc.args else exc)
    if text.startswith(("b'", 'b"')):
        text = text[2:-1]
    return text[:200]


class ReadOnlySession:
    """A read-only IMAP session. Construct with :meth:`connect`."""

    def __init__(self, imap: imaplib.IMAP4):
        self._imap = imap
        self._imap.debug = 0
        self._selected: FolderStatus | None = None

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def connect(
        cls,
        host: str,
        port: int,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        factory: ImapFactory | None = None,
    ) -> "ReadOnlySession":
        log.info("Connecting to IMAP server %s:%d (TLS)", host, port)
        try:
            imap = (factory or _default_factory)(host, port, timeout)
        except ssl.SSLError as exc:
            raise MailboxError(MailboxError.KIND_TLS, f"TLS error: {type(exc).__name__}") from None
        except (OSError, socket.timeout, imaplib.IMAP4.error) as exc:
            raise MailboxError(MailboxError.KIND_CONNECTION, f"{type(exc).__name__}: {exc}") from None
        return cls(imap)

    def __enter__(self) -> "ReadOnlySession":
        return self

    def __exit__(self, *exc_info) -> None:
        self.logout()

    def logout(self) -> None:
        # LOGOUT only. CLOSE is never sent (after SELECT it would expunge).
        try:
            self._imap.logout()
        except Exception:  # connection may already be gone
            pass

    # -- authentication ----------------------------------------------------

    def login_password(self, user: str, password: str) -> None:
        if re.search(r'[\s"\\\x00-\x1f]', user):
            raise MailboxError(MailboxError.KIND_AUTH, "invalid user name")
        try:
            self._imap.login(user, password)
        except imaplib.IMAP4.error as exc:
            raise MailboxError(MailboxError.KIND_AUTH, _server_text(exc)) from None
        except (OSError, socket.timeout) as exc:
            raise MailboxError(MailboxError.KIND_CONNECTION, type(exc).__name__) from None

    def login_xoauth2(self, user: str, access_token: str) -> None:
        sent = {"done": False}

        def respond(_challenge: bytes) -> bytes:
            if sent["done"]:
                return b""  # server sent an error challenge; finish with NO
            sent["done"] = True
            return f"user={user}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")

        try:
            self._imap.authenticate("XOAUTH2", respond)
        except imaplib.IMAP4.error as exc:
            raise MailboxError(MailboxError.KIND_AUTH, _server_text(exc)) from None
        except (OSError, socket.timeout) as exc:
            raise MailboxError(MailboxError.KIND_CONNECTION, type(exc).__name__) from None

    # -- read-only operations ----------------------------------------------

    def list_folders(self) -> list[FolderInfo]:
        typ, data = self._call(self._imap.list, '""', "*")
        if typ != "OK":
            raise MailboxError(MailboxError.KIND_PROTOCOL, "LIST failed")
        folders: list[FolderInfo] = []
        for item in data or []:
            if item is None:
                continue
            literal_name = None
            if isinstance(item, tuple):
                item, literal_name = item[0], item[1]
            match = _LIST_LINE.match(item.strip())
            if not match:
                continue
            raw_name = literal_name if literal_name is not None else match.group("name").strip()
            if raw_name.startswith(b'"') and raw_name.endswith(b'"'):
                raw_name = re.sub(rb'\\(.)', rb"\1", raw_name[1:-1])
            flags = tuple(f.decode("ascii", "replace") for f in match.group("flags").split())
            folders.append(FolderInfo(decode_mailbox_name(raw_name), flags))
        return folders

    def examine(self, folder: str) -> FolderStatus:
        """Open ``folder`` read-only (EXAMINE) and verify the server agrees."""
        typ, data = self._call(self._imap.select, quote_mailbox(folder), True)
        if typ != "OK":
            raise MailboxError(MailboxError.KIND_PROTOCOL, f"cannot open folder (server answered {typ})")
        responses = self._imap.untagged_responses
        if "READ-ONLY" not in responses:
            # The server did not confirm read-only access: stop (fail closed).
            self._selected = None
            raise MailboxError(MailboxError.KIND_READ_ONLY, "server did not confirm read-only access")
        try:
            uidvalidity = int(responses.get("UIDVALIDITY", [b"0"])[-1])
            exists = int((data or [b"0"])[-1] or 0)
        except (TypeError, ValueError):
            raise MailboxError(MailboxError.KIND_PROTOCOL, "invalid EXAMINE response") from None
        self._selected = FolderStatus(folder, uidvalidity, exists)
        return self._selected

    def search_since(self, since: datetime) -> list[int]:
        self._require_selected()
        typ, data = self._uid("SEARCH", "SINCE", imap_date(since))
        if typ != "OK":
            raise MailboxError(MailboxError.KIND_PROTOCOL, "SEARCH failed")
        uids: list[int] = []
        for chunk in data or []:
            if isinstance(chunk, bytes):
                uids.extend(int(x) for x in chunk.split() if x.isdigit())
        return sorted(set(uids))

    def fetch_headers(self, uids: list[int], fields: Iterable[str]) -> list[FetchedMessage]:
        """Fetch selected header fields with BODY.PEEK (does not mark as read)."""
        self._require_selected()
        fields = [f.upper() for f in fields]
        if not all(re.fullmatch(r"[A-Z0-9-]+", f) for f in fields):
            raise ValueError("invalid header field name")
        spec = "(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (" + " ".join(fields) + ")])"
        wanted = set(uids)
        results: list[FetchedMessage] = []
        for start in range(0, len(uids), FETCH_BATCH):
            batch = uids[start : start + FETCH_BATCH]
            typ, data = self._uid("FETCH", uid_set(batch), spec)
            if typ != "OK":
                raise MailboxError(MailboxError.KIND_PROTOCOL, "FETCH failed")
            results.extend(m for m in parse_fetch_response(data) if m.uid in wanted)
        return results

    def fetch_size(self, uid: int) -> int | None:
        self._require_selected()
        typ, data = self._uid("FETCH", str(int(uid)), "(UID RFC822.SIZE)")
        if typ != "OK":
            raise MailboxError(MailboxError.KIND_PROTOCOL, "FETCH failed")
        for msg in parse_fetch_response(data):
            if msg.uid == uid:
                return msg.size
        return None

    def fetch_full(self, uid: int) -> bytes | None:
        """Fetch the complete raw message with BODY.PEEK[] (does not mark as read)."""
        self._require_selected()
        typ, data = self._uid("FETCH", str(int(uid)), "(UID BODY.PEEK[])")
        if typ != "OK":
            raise MailboxError(MailboxError.KIND_PROTOCOL, "FETCH failed")
        for msg in parse_fetch_response(data):
            if msg.uid == uid:
                return msg.sections.get("BODY[]")
        return None

    # -- guards --------------------------------------------------------------

    def _require_selected(self) -> None:
        if self._selected is None:
            raise ReadOnlyViolation("no folder opened with EXAMINE")

    def _uid(self, command: str, *args: str):
        command = command.upper()
        if command not in ("SEARCH", "FETCH"):
            raise ReadOnlyViolation(f"UID {command} is not allowed in read-only mode")
        if command == "FETCH":
            check_fetch_items(args[-1])
        return self._call(self._imap.uid, command, *args)

    def _call(self, func, *args):
        try:
            return func(*args)
        except imaplib.IMAP4.readonly as exc:  # subclass of abort: must come first
            raise MailboxError(MailboxError.KIND_READ_ONLY, _server_text(exc)) from None
        except imaplib.IMAP4.abort as exc:
            raise MailboxError(MailboxError.KIND_CONNECTION, _server_text(exc)) from None
        except imaplib.IMAP4.error as exc:
            raise MailboxError(MailboxError.KIND_PROTOCOL, _server_text(exc)) from None
        except (OSError, socket.timeout) as exc:
            raise MailboxError(MailboxError.KIND_CONNECTION, type(exc).__name__) from None
