"""Parsing of fetched header blocks. All input here is untrusted."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses, parsedate_to_datetime

from local_mail_cleaner.models import ParsedMessage, UnsubTarget
from local_mail_cleaner.text import clean_display, decode_rfc2047
from local_mail_cleaner.url_safety import check_mailto, check_web_url

#: Header fields requested with BODY.PEEK[HEADER.FIELDS (...)].
FETCH_FIELDS = (
    "FROM",
    "SUBJECT",
    "DATE",
    "MESSAGE-ID",
    "LIST-ID",
    "LIST-UNSUBSCRIBE",
    "LIST-UNSUBSCRIBE-POST",
    "DKIM-SIGNATURE",
    "AUTHENTICATION-RESULTS",
)

MAX_HEADER_BLOCK = 512 * 1024
MAX_HEADERS = 500
MAX_LIST_UNSUBSCRIBE_LEN = 4096
MAX_URIS = 8
ONE_CLICK_VALUE = "List-Unsubscribe=One-Click"

# Header problem codes (translated in the UI).
H_TOO_LARGE = "headers_too_large"
H_DUP_LIST_UNSUB = "duplicate_list_unsubscribe"
H_DUP_LIST_UNSUB_POST = "duplicate_list_unsubscribe_post"
H_DUP_FROM = "duplicate_from"
H_DUP_LIST_ID = "duplicate_list_id"
H_MALFORMED_LIST_UNSUB = "malformed_list_unsubscribe"
H_LIST_UNSUB_TOO_LONG = "list_unsubscribe_too_long"
H_TOO_MANY_URIS = "too_many_uris"
H_MALFORMED_LIST_ID = "malformed_list_id"
H_MULTIPLE_FROM = "multiple_from_addresses"
H_INVALID_FROM = "invalid_from"
H_INVALID_POST = "invalid_list_unsubscribe_post"

#: Duplicates of these headers enable header-injection attacks against DKIM
#: (an unsigned copy placed above the signed one), so they force manual review.
SECURITY_DUPLICATES = {H_DUP_LIST_UNSUB, H_DUP_LIST_UNSUB_POST, H_DUP_FROM}

_HEADER_LINE = re.compile(r"^([!-9;-~]+):(.*)$")
_LIST_ID_ATOM = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)+$")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def parse_header_block(raw: bytes) -> list[tuple[str, str]]:
    """Split a raw header block into ordered (lower-case name, unfolded value) pairs."""
    text = raw[:MAX_HEADER_BLOCK].decode("utf-8", errors="replace")
    headers: list[tuple[str, str]] = []
    for line in re.split(r"\r?\n", text):
        if not line:
            break
        if line[0] in " \t":
            if headers:
                name, value = headers[-1]
                headers[-1] = (name, value + line)
            continue
        match = _HEADER_LINE.match(line)
        if not match:
            continue
        if len(headers) >= MAX_HEADERS:
            break
        headers.append((match.group(1).lower(), match.group(2).strip()))
    return headers


def header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key == name]


def parse_list_unsubscribe(value: str) -> tuple[list[UnsubTarget], list[str]]:
    """Parse an RFC 2369 List-Unsubscribe value into statically checked targets."""
    if len(value) > MAX_LIST_UNSUBSCRIBE_LEN:
        return [], [H_LIST_UNSUB_TOO_LONG]
    uris = re.findall(r"<([^<>]*)>", value)
    if not uris:
        return [], [H_MALFORMED_LIST_UNSUB] if value.strip() else []
    problems: list[str] = []
    if len(uris) > MAX_URIS:
        problems.append(H_TOO_MANY_URIS)
        uris = uris[:MAX_URIS]
    targets: list[UnsubTarget] = []
    for uri in uris:
        # RFC 2369: whitespace inside the angle brackets is to be ignored.
        uri = re.sub(r"\s+", "", uri)
        if not uri:
            continue
        lowered = uri.lower()
        if lowered.startswith("mailto:"):
            _, domain, uri_problems = check_mailto(uri)
            targets.append(UnsubTarget("mailto", uri, domain, tuple(uri_problems)))
        elif lowered.startswith(("https:", "http:")):
            scheme, host, uri_problems = check_web_url(uri)
            targets.append(UnsubTarget(scheme or "invalid", uri, host, tuple(uri_problems)))
        else:
            scheme = lowered.split(":", 1)[0][:20] if ":" in lowered else "invalid"
            targets.append(UnsubTarget(scheme, uri, "", ("unsupported_scheme",)))
    return targets, problems


def parse_list_id(value: str) -> tuple[str, str, list[str]]:
    """Return (normalised list identifier, description, problems) per RFC 2919."""
    value = value[:1000]
    match = re.search(r"<([^<>]+)>\s*$", value)
    if match:
        list_id = match.group(1).strip().lower()
        description = decode_rfc2047(value[: match.start()].strip().strip('"'), 120)
    else:
        list_id = value.strip().lower()
        description = ""
    if not _LIST_ID_ATOM.match(list_id) or len(list_id) > 255:
        return "", description, [H_MALFORMED_LIST_ID]
    return list_id, description, []


def parse_from(value: str) -> tuple[str, str, str, list[str]]:
    """Return (address, display name, domain, problems) for a From value."""
    problems: list[str] = []
    try:
        pairs = [p for p in getaddresses([value[:2000]]) if p[1]]
    except Exception:  # malformed input must never crash the scan
        pairs = []
    if not pairs:
        return "", "", "", [H_INVALID_FROM]
    if len(pairs) > 1:
        problems.append(H_MULTIPLE_FROM)
    name, addr = pairs[0]
    addr = clean_display(addr, 320).lower()
    if addr.count("@") != 1 or " " in addr:
        return "", decode_rfc2047(name, 120), "", problems + [H_INVALID_FROM]
    domain = addr.rsplit("@", 1)[1].rstrip(".")
    if "." not in domain:
        problems.append(H_INVALID_FROM)
    return addr, decode_rfc2047(name, 120), domain, problems


def parse_internaldate(value: str) -> datetime | None:
    """Parse an IMAP INTERNALDATE such as ``13-Oct-2026 10:00:00 +0200``."""
    match = re.match(
        r'^"?\s?(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})"?$',
        value.strip(),
    )
    if not match:
        return None
    day, mon, year, hh, mm, ss, sign, oh, om = match.groups()
    try:
        month = _MONTHS.index(mon.capitalize()) + 1
        offset = timedelta(hours=int(oh), minutes=int(om))
        tz = timezone(offset if sign == "+" else -offset)
        return datetime(int(year), month, int(day), int(hh), int(mm), int(ss), tzinfo=tz).astimezone(
            timezone.utc
        )
    except ValueError:
        return None


def parse_date(value: str | None, fallback: datetime | None = None) -> datetime | None:
    """Parse a Date header to UTC; use ``fallback`` when missing or implausible."""
    parsed = None
    if value:
        try:
            parsed = parsedate_to_datetime(value[:200])
        except (TypeError, ValueError, IndexError, OverflowError):
            parsed = None
    if parsed is not None:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = parsed.astimezone(timezone.utc)
        if parsed > datetime.now(timezone.utc) + timedelta(days=2) or parsed.year < 1990:
            parsed = None
    return parsed or fallback


def imap_date(day: datetime) -> str:
    """Format a date for IMAP SEARCH SINCE. Locale-independent on purpose."""
    return f"{day.day:02d}-{_MONTHS[day.month - 1]}-{day.year:04d}"


def parse_message_headers(
    raw: bytes,
    *,
    uid: int,
    folder: str,
    uidvalidity: int,
    internaldate: datetime | None = None,
) -> tuple[ParsedMessage, list[tuple[str, str]]]:
    """Build a :class:`ParsedMessage` from a raw header block.

    Returns the message and the ordered header list (needed for the
    authentication evidence check). Provider evidence is filled in elsewhere.
    """
    msg = ParsedMessage(uid=uid, folder=folder, uidvalidity=uidvalidity)
    if len(raw) > MAX_HEADER_BLOCK:
        msg.header_problems.append(H_TOO_LARGE)
    headers = parse_header_block(raw)

    def single(name: str, dup_code: str | None = None) -> str:
        values = header_values(headers, name)
        if len(values) > 1 and dup_code:
            msg.header_problems.append(dup_code)
        return values[0] if values else ""

    from_value = single("from", H_DUP_FROM)
    if from_value:
        msg.from_addr, msg.from_name, msg.from_domain, problems = parse_from(from_value)
        msg.header_problems.extend(problems)
    msg.subject = decode_rfc2047(single("subject"), 200)
    msg.date = parse_date(single("date"), internaldate)
    msg.message_id = clean_display(single("message-id"), 300)

    list_id_value = single("list-id", H_DUP_LIST_ID)
    if list_id_value:
        msg.list_id, msg.list_id_desc, problems = parse_list_id(list_id_value)
        msg.header_problems.extend(problems)

    unsub_value = single("list-unsubscribe", H_DUP_LIST_UNSUB)
    if unsub_value:
        msg.list_unsubscribe_raw = unsub_value[: MAX_LIST_UNSUBSCRIBE_LEN + 1]
        msg.targets, problems = parse_list_unsubscribe(unsub_value)
        msg.header_problems.extend(problems)

    post_value = single("list-unsubscribe-post", H_DUP_LIST_UNSUB_POST)
    if post_value:
        msg.list_unsubscribe_post_raw = clean_display(post_value, 100)
        msg.one_click_post = post_value.strip() == ONE_CLICK_VALUE
        if not msg.one_click_post:
            msg.header_problems.append(H_INVALID_POST)

    msg.dkim_signature_count = len(header_values(headers, "dkim-signature"))
    return msg, headers
