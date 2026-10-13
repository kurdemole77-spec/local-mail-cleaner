"""Helpers for turning untrusted header text into safe display strings."""

from __future__ import annotations

import re
from email.header import decode_header, make_header

# C0/C1 controls, zero-width characters and bidirectional overrides. Bidi
# overrides can make a sender name render differently from its real content.
_UNSAFE_CHARS = re.compile(
    "[\x00-\x1f\x7f-\x9f​-‏  ‪-‮⁠-⁤⁦-⁩﻿]"
)
_WS = re.compile(r"\s+")


def unfold(value: str) -> str:
    """Remove RFC 5322 header folding (CRLF followed by whitespace)."""
    return re.sub(r"\r?\n(?=[ \t])", "", value)


def clean_display(value: str | None, max_len: int = 200) -> str:
    """Return a single-line, control-character-free, length-limited string."""
    if not value:
        return ""
    text = _UNSAFE_CHARS.sub(" ", value)
    text = _WS.sub(" ", text).strip()
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def decode_rfc2047(value: str | None, max_len: int = 500) -> str:
    """Decode RFC 2047 encoded words; fall back to the raw text on any error."""
    if not value:
        return ""
    raw = unfold(value)[:4000]
    try:
        decoded = str(make_header(decode_header(raw)))
    except (LookupError, UnicodeError, ValueError, TypeError, AssertionError):
        decoded = raw
    return clean_display(decoded, max_len)
