"""Static (offline) safety checks for unsubscribe destinations.

Stage A only classifies destinations; it never contacts them. The checks here
need no network access. DNS validation and connection pinning against DNS
rebinding belong to the stage B request code and must be added there.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

MAX_URL_LENGTH = 2048

# Problem codes (translated in the UI).
P_NOT_HTTPS = "not_https"
P_INSECURE_HTTP = "insecure_http"
P_TOO_LONG = "too_long"
P_INVALID_CHARS = "invalid_chars"
P_USERINFO = "userinfo"
P_PORT = "nonstandard_port"
P_NO_HOST = "no_host"
P_INVALID_HOST = "invalid_host"
P_IP_LITERAL = "ip_literal"
P_FORBIDDEN_ADDRESS = "forbidden_address"
P_LOCAL_NAME = "local_hostname"
P_MAILTO_INVALID = "mailto_invalid"
P_MAILTO_MULTIPLE = "mailto_multiple_recipients"

_LOCAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".home.arpa",
    ".test",
    ".invalid",
    ".example",
    ".onion",
)
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_ADDR = re.compile(r"^[^@\s<>()\[\],;:\"]+@([^@\s<>()\[\],;:\"]+)$")


def is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for loopback, private, link-local, reserved, multicast and similar."""
    if isinstance(ip, ipaddress.IPv6Address):
        for embedded in (ip.ipv4_mapped, ip.sixtofour):
            if embedded is not None and is_forbidden_ip(embedded):
                return True
        if ip.teredo is not None:
            return True
    return (
        not ip.is_global
        or ip.is_multicast
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    )


def check_hostname(host: str) -> tuple[str, list[str]]:
    """Normalise a host name and return (ascii_host, problems)."""
    problems: list[str] = []
    host = host.strip().rstrip(".").lower()
    if not host:
        return "", [P_NO_HOST]
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        ip = None
    if ip is not None:
        problems.append(P_IP_LITERAL)
        if is_forbidden_ip(ip):
            problems.append(P_FORBIDDEN_ADDRESS)
        return candidate, problems
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return host, [P_INVALID_HOST]
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or not all(_HOST_LABEL.match(label) for label in labels):
        return ascii_host, [P_INVALID_HOST]
    tld = labels[-1]
    # Numeric or hex "TLDs" are alternative IPv4 spellings (127.1, 0x7f.1, 2130706433).
    if tld.isdigit() or re.fullmatch(r"0x[0-9a-f]*", tld):
        return ascii_host, [P_IP_LITERAL, P_FORBIDDEN_ADDRESS]
    if len(labels) < 2 or ascii_host == "localhost" or ascii_host.endswith(_LOCAL_SUFFIXES):
        problems.append(P_LOCAL_NAME)
    return ascii_host, problems


def check_web_url(url: str) -> tuple[str, str, list[str]]:
    """Statically check an http(s) unsubscribe URL.

    Returns (scheme, host, problems). An empty problem list means the URL passed
    the offline checks; it does not mean the destination is safe to contact.
    """
    problems: list[str] = []
    if len(url) > MAX_URL_LENGTH:
        problems.append(P_TOO_LONG)
    if re.search(r"[\x00-\x20\x7f\\]", url):
        return "", "", problems + [P_INVALID_CHARS]
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "", "", problems + [P_INVALID_HOST]
    scheme = parts.scheme.lower()
    if scheme == "http":
        problems.append(P_INSECURE_HTTP)
    elif scheme != "https":
        problems.append(P_NOT_HTTPS)
    if "@" in parts.netloc:
        problems.append(P_USERINFO)
    if port not in (None, 443):
        problems.append(P_PORT)
    host, host_problems = check_hostname(parts.hostname or "")
    problems.extend(host_problems)
    return scheme, host, problems


def check_mailto(uri: str) -> tuple[str, str, list[str]]:
    """Statically check a mailto: URI. Returns (address, domain, problems)."""
    if len(uri) > MAX_URL_LENGTH:
        return "", "", [P_TOO_LONG]
    if re.search(r"[\x00-\x20\x7f]", uri):
        return "", "", [P_INVALID_CHARS]
    body = uri[len("mailto:"):]
    address_part = unquote(body.split("?", 1)[0])
    if "," in address_part:
        return "", "", [P_MAILTO_MULTIPLE]
    match = _ADDR.match(address_part)
    if not match:
        return "", "", [P_MAILTO_INVALID]
    domain, problems = check_hostname(match.group(1))
    return address_part.lower(), domain, problems
