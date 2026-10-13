"""Local DKIM verification of a full message (opt-in, read-only fetch).

Uses dkimpy for the cryptography and our own DNS lookup (absolute names, no
search domains, timeouts, ambiguous answers rejected). A cryptographically
valid signature must additionally pass :func:`auth_evidence.signature_problems`
(coverage of the unsubscribe headers, sender alignment, algorithm policy).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from local_mail_cleaner.auth_evidence import (
    R_NO_SIGNATURE,
    DkimSignature,
    signature_problems,
)
from local_mail_cleaner.models import CheckStatus

log = logging.getLogger(__name__)

R_DKIM_INVALID = "dkim_signature_invalid"
R_DKIM_ERROR = "dkim_verification_error"
R_DKIM_UNAVAILABLE = "dkim_library_unavailable"
R_MESSAGE_TOO_LARGE = "message_too_large_to_verify"

MAX_VERIFY_BYTES = 10 * 1024 * 1024
DNS_TIMEOUT = 5.0

DnsFunc = Callable[..., "bytes | None"]


@dataclass
class LocalDkimResult:
    status: CheckStatus
    reasons: list[str] = field(default_factory=list)
    signer: str = ""


def make_dns_txt_lookup(timeout: float = DNS_TIMEOUT) -> DnsFunc:
    """Return a dkimpy-compatible ``dnsfunc(name, timeout=...)`` using dnspython."""
    import dkim
    import dns.exception
    import dns.name
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = timeout

    def lookup(name: bytes, timeout: float = timeout) -> bytes | None:
        text = name.decode("ascii", errors="strict") if isinstance(name, bytes) else name
        if not text.endswith("."):
            text += "."
        try:
            answer = resolver.resolve(
                dns.name.from_text(text), "TXT", search=False, raise_on_no_answer=False,
                lifetime=min(timeout, DNS_TIMEOUT),
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoResolverConfiguration) as exc:
            raise dkim.DnsTimeoutError(type(exc).__name__) from None
        records = {b"".join(r.strings) for r in answer.rrset} if answer.rrset else set()
        if len(records) != 1:
            return None  # none, or ambiguous: fail closed
        return records.pop()

    return lookup


def _quiet_logger() -> logging.Logger:
    quiet = logging.getLogger("local_mail_cleaner.dkimpy")
    quiet.propagate = False
    quiet.addHandler(logging.NullHandler())
    return quiet


def verify_message(
    raw: bytes,
    from_domain: str,
    needs_post: bool,
    dnsfunc: DnsFunc | None = None,
) -> LocalDkimResult:
    """Verify every DKIM signature; pass if one valid signature meets policy."""
    if len(raw) > MAX_VERIFY_BYTES:
        return LocalDkimResult(CheckStatus.FAIL, [R_MESSAGE_TOO_LARGE])
    try:
        import dkim
        from dkim.util import InvalidTagValueList, parse_tag_value
    except ImportError:
        return LocalDkimResult(CheckStatus.FAIL, [R_DKIM_UNAVAILABLE])
    if dnsfunc is None:
        dnsfunc = make_dns_txt_lookup()

    try:
        verifier = dkim.DKIM(raw, logger=_quiet_logger(), minkey=1024, timeout=int(DNS_TIMEOUT))
    except Exception:  # malformed message
        return LocalDkimResult(CheckStatus.FAIL, [R_DKIM_ERROR])
    sig_values = [v for k, v in verifier.headers if k.lower() == b"dkim-signature"]
    if not sig_values:
        return LocalDkimResult(CheckStatus.FAIL, [R_NO_SIGNATURE])

    reasons: list[str] = []
    for idx, value in enumerate(sig_values):
        try:
            tags = parse_tag_value(value)
            sig = DkimSignature(
                domain=tags[b"d"].decode("ascii").lower().rstrip("."),
                selector=tags[b"s"].decode("ascii"),
                algorithm=tags[b"a"].decode("ascii").lower(),
                signed_headers=[
                    h.strip().lower() for h in tags[b"h"].decode("ascii").split(":") if h.strip()
                ],
                b_value="",
                has_length_tag=b"l" in tags,
            )
        except (InvalidTagValueList, KeyError, UnicodeDecodeError):
            reasons.append(R_DKIM_ERROR)
            continue
        policy = signature_problems(sig, from_domain, needs_post)
        if policy:
            # Do not spend a DNS lookup on a signature that cannot qualify.
            reasons.extend(policy)
            continue
        try:
            valid = verifier.verify(idx=idx, dnsfunc=dnsfunc)
        except dkim.DKIMException as exc:
            log.info("DKIM signature %d for %s rejected: %s", idx, sig.domain, type(exc).__name__)
            reasons.append(R_DKIM_INVALID)
            continue
        except Exception as exc:  # defensive: dkimpy on hostile input
            log.warning("DKIM verification error for %s: %s", sig.domain, type(exc).__name__)
            reasons.append(R_DKIM_ERROR)
            continue
        if not valid:
            reasons.append(R_DKIM_INVALID)
            continue
        return LocalDkimResult(CheckStatus.PASS, [], sig.domain)
    return LocalDkimResult(CheckStatus.FAIL, list(dict.fromkeys(reasons)) or [R_DKIM_INVALID])
