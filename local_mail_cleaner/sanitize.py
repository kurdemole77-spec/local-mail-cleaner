"""Redaction of secrets and personal data in diagnostic output.

This is a safety net: code must not pass secrets to the logger in the first
place. Everything that is written to a log file or diagnostic report goes
through :func:`redact` as well.
"""

from __future__ import annotations

import re

_RULES: list[tuple[re.Pattern, object]] = [
    # IMAP LOGIN / AUTHENTICATE arguments.
    (re.compile(r"(?i)\b(LOGIN)\s+\S+\s+\S+"), r"\1 [redacted]"),
    (re.compile(r"(?i)\b(AUTHENTICATE\s+\w+)\s+\S+"), r"\1 [redacted]"),
    # HTTP authorization headers and bearer tokens.
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(\S+\s+)?\S+"), r"\1[redacted]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer [redacted]"),
    # XOAUTH2 initial client response (raw form).
    (re.compile(r"auth=Bearer[^\x01\s]*"), "auth=[redacted]"),
    # Google token formats.
    (re.compile(r"\bya29\.[A-Za-z0-9_\-]+"), "[redacted-token]"),
    (re.compile(r"\b1//[A-Za-z0-9_\-]{10,}"), "[redacted-token]"),
    (re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]+"), "[redacted-secret]"),
    # JSON Web Tokens.
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"), "[redacted-jwt]"),
    # key=value / "key": "value" secrets.
    (
        re.compile(
            r"(?i)([\"']?\b(?:password|passwd|pwd|pass|secret|client_secret|token|access_token|"
            r"refresh_token|id_token|code|code_verifier|api_key|apikey|app_password)\b[\"']?\s*[:=]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&}]+)"
        ),
        r"\1[redacted]",
    ),
    # URLs: keep scheme and host only.
    (re.compile(r"(?i)\b(https?)://([^/\s?#<>\"']+)[^\s<>\"']*"), lambda m: f"{m.group(1)}://{_host_only(m.group(2))}/[redacted]"),
    (re.compile(r"(?i)\bmailto:[^\s<>\"']+"), "mailto:[redacted]"),
    # E-mail addresses: keep the domain (useful to tell providers apart).
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)"), r"[user]@\1"),
    # Long opaque blobs (base64 / hex tokens, XOAUTH2 strings, signatures).
    (re.compile(r"[A-Za-z0-9+_\-]{32,}={0,2}"), lambda m: _blob(m.group(0))),
]


def _blob(token: str) -> str:
    # Long identifiers made of words (no digits) are kept readable.
    if len(token) >= 60 or any(ch.isdigit() for ch in token):
        return "[redacted-blob]"
    return token


def _host_only(netloc: str) -> str:
    return netloc.rsplit("@", 1)[-1]


def redact(text: str) -> str:
    """Return ``text`` with credentials, tokens, URLs and addresses masked."""
    if not text:
        return text
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text
