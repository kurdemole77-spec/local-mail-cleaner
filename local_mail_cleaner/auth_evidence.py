"""Authentication evidence for List-Unsubscribe headers.

Two sources of evidence are supported:

* trusted provider evidence: the topmost ``Authentication-Results`` header,
  only when its authserv-id is on the account's trusted list (by default only
  Gmail's ``mx.google.com``), combined with the ``h=`` tag of the matching
  ``DKIM-Signature`` to prove the unsubscribe headers were covered;
* local DKIM verification (see :mod:`local_mail_cleaner.dkim_verify`).

The mere presence of a ``DKIM-Signature`` header is never treated as proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from local_mail_cleaner.models import CheckStatus

# Reason codes (translated in the UI).
R_NO_SIGNATURE = "no_dkim_signature"
R_SIGNATURE_UNVERIFIED = "dkim_signature_unverified"
R_PROVIDER_NOT_TRUSTED = "provider_evidence_not_trusted"
R_NO_PROVIDER_RESULTS = "no_trusted_authentication_results"
R_TOP_RESULTS_UNTRUSTED = "top_authentication_results_not_trusted"
R_PROVIDER_DKIM_NOT_PASS = "provider_dkim_not_pass"
R_NO_MATCHING_SIGNATURE = "no_matching_signature"
R_AMBIGUOUS_SIGNATURE = "ambiguous_signature_match"
R_NOT_COVERED = "unsubscribe_headers_not_signed"
R_POST_NOT_COVERED = "unsubscribe_post_header_not_signed"
R_NOT_ALIGNED = "signer_not_aligned_with_sender"
R_WEAK_ALGORITHM = "weak_signature_algorithm"
R_LENGTH_TAG = "signature_uses_body_length_limit"
R_NO_FROM_DOMAIN = "sender_domain_unknown"

# Multi-label public suffixes that must never count as an aligned signer.
_PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.pl", "net.pl", "org.pl",
    "info.pl", "biz.pl", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "com.br",
    "co.nz", "co.za", "com.cn", "com.tr", "com.mx", "co.in", "com.de", "co.de",
}


@dataclass
class DkimSignature:
    domain: str
    selector: str
    algorithm: str
    signed_headers: list[str]
    b_value: str = field(repr=False)
    identity: str = ""
    has_length_tag: bool = False


@dataclass
class AuthResult:
    method: str
    result: str
    props: dict[str, str]


@dataclass
class AuthResultsHeader:
    authserv_id: str
    results: list[AuthResult]


@dataclass
class EvidenceResult:
    status: CheckStatus
    reasons: list[str]
    signer: str = ""


def parse_tag_list(value: str) -> dict[str, str] | None:
    """Parse a DKIM tag=value list. Returns None when malformed."""
    tags: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            return None
        key, _, val = part.partition("=")
        key = key.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in tags:
            return None
        tags[key] = re.sub(r"\s+", "", val)
    return tags


def parse_dkim_signature(value: str) -> DkimSignature | None:
    tags = parse_tag_list(value)
    if not tags or not all(k in tags for k in ("d", "s", "h", "b", "a")):
        return None
    return DkimSignature(
        domain=tags["d"].lower().rstrip("."),
        selector=tags["s"],
        algorithm=tags["a"].lower(),
        signed_headers=[h.strip().lower() for h in tags["h"].split(":") if h.strip()],
        b_value=tags["b"],
        identity=tags.get("i", ""),
        has_length_tag="l" in tags,
    )


def _strip_comments(value: str) -> str:
    """Remove RFC 5322 comments (nested parentheses) outside quoted strings."""
    out: list[str] = []
    depth = 0
    in_quote = False
    escaped = False
    for ch in value:
        if escaped:
            if depth == 0:
                out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            if depth == 0:
                out.append(ch)
            continue
        if in_quote:
            out.append(ch)
            if ch == '"':
                in_quote = False
            continue
        if ch == "(":
            depth += 1
            continue
        if ch == ")" and depth:
            depth -= 1
            continue
        if depth == 0:
            if ch == '"':
                in_quote = True
            out.append(ch)
    return "".join(out)


def _split_outside_quotes(value: str, sep: str | None) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    for ch in value:
        if ch == '"':
            in_quote = not in_quote
        is_sep = (ch.isspace() if sep is None else ch == sep) and not in_quote
        if is_sep:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def parse_authentication_results(value: str) -> AuthResultsHeader | None:
    """Parse an RFC 8601 Authentication-Results value (tolerant, fail-closed)."""
    cleaned = _strip_comments(value[:8000])
    segments = _split_outside_quotes(cleaned, ";")
    if not segments:
        return None
    head = segments[0].split()
    if not head or "=" in head[0]:
        return None
    authserv_id = head[0].lower().rstrip(".")
    results: list[AuthResult] = []
    for segment in segments[1:]:
        tokens = _split_outside_quotes(segment, None)
        if not tokens or tokens[0].lower() == "none":
            continue
        method, sep, result = tokens[0].partition("=")
        if not sep:
            continue
        props: dict[str, str] = {}
        for token in tokens[1:]:
            key, sep, val = token.partition("=")
            if sep:
                props[key.lower()] = val.strip('"')
        results.append(AuthResult(method.split("/")[0].lower(), result.lower(), props))
    return AuthResultsHeader(authserv_id, results)


def domains_aligned(signer: str, from_domain: str) -> bool:
    """Relaxed alignment: equal domains, or one is a sub-domain of the other.

    Sibling sub-domains (mail.example.com vs news.example.com) are not treated
    as aligned because there is no public suffix list here; they fall back to
    manual review, which is the fail-closed direction.
    """
    signer = signer.lower().rstrip(".")
    from_domain = from_domain.lower().rstrip(".")
    if not signer or not from_domain or "." not in signer or signer in _PUBLIC_SUFFIXES:
        return False
    return (
        signer == from_domain
        or from_domain.endswith("." + signer)
        or signer.endswith("." + from_domain)
    )


def signature_problems(sig: DkimSignature, from_domain: str, needs_post: bool) -> list[str]:
    """Policy checks a cryptographically valid signature must also satisfy."""
    problems: list[str] = []
    if sig.algorithm not in ("rsa-sha256", "ed25519-sha256"):
        problems.append(R_WEAK_ALGORITHM)
    if sig.has_length_tag:
        problems.append(R_LENGTH_TAG)
    if "list-unsubscribe" not in sig.signed_headers:
        problems.append(R_NOT_COVERED)
    if needs_post and "list-unsubscribe-post" not in sig.signed_headers:
        problems.append(R_POST_NOT_COVERED)
    if not from_domain:
        problems.append(R_NO_FROM_DOMAIN)
    elif not domains_aligned(sig.domain, from_domain):
        problems.append(R_NOT_ALIGNED)
    return problems


def evaluate_provider_evidence(
    headers: list[tuple[str, str]],
    trusted_authserv_ids: list[str],
    from_domain: str,
    needs_post: bool,
) -> EvidenceResult:
    """Decide whether trusted provider evidence authenticates the unsubscribe headers."""
    signatures = [
        s for s in (parse_dkim_signature(v) for k, v in headers if k == "dkim-signature") if s
    ]
    has_raw_signature = any(k == "dkim-signature" for k, _ in headers)
    trusted = {t.strip().lower().rstrip(".") for t in trusted_authserv_ids if t.strip()}

    def fail(*reasons: str) -> EvidenceResult:
        base = [R_SIGNATURE_UNVERIFIED] if has_raw_signature else [R_NO_SIGNATURE]
        return EvidenceResult(CheckStatus.FAIL, base + [r for r in reasons if r not in base])

    if not trusted:
        return fail(R_PROVIDER_NOT_TRUSTED)
    ar_values = [v for k, v in headers if k == "authentication-results"]
    if not ar_values:
        return fail(R_NO_PROVIDER_RESULTS)
    # Only the topmost header is the receiving provider's own; lower ones may
    # have been supplied by the sender and are ignored.
    top = parse_authentication_results(ar_values[0])
    if top is None or top.authserv_id not in trusted:
        return fail(R_TOP_RESULTS_UNTRUSTED)
    passes = [r for r in top.results if r.method == "dkim" and r.result == "pass"]
    if not passes:
        return fail(R_PROVIDER_DKIM_NOT_PASS)

    collected: list[str] = []
    for res in passes:
        domain = res.props.get("header.d", "").lower().rstrip(".")
        identity = res.props.get("header.i", "")
        if not domain and "@" in identity:
            domain = identity.rsplit("@", 1)[1].lower().rstrip(".")
        b_prefix = res.props.get("header.b", "")
        if not domain:
            collected.append(R_NO_MATCHING_SIGNATURE)
            continue
        matches = [
            s for s in signatures
            if (s.domain == domain or domain.endswith("." + s.domain))
            and (not b_prefix or s.b_value.startswith(b_prefix))
        ]
        if not matches:
            collected.append(R_NO_MATCHING_SIGNATURE)
            continue
        # When several signatures match (no header.b, or a copied b= value in
        # a forged duplicate), we cannot tell which one the provider verified,
        # so every candidate has to qualify.
        problems = sorted({p for s in matches for p in signature_problems(s, from_domain, needs_post)})
        if not problems:
            return EvidenceResult(CheckStatus.PASS, [], matches[0].domain)
        if len(matches) > 1:
            collected.append(R_AMBIGUOUS_SIGNATURE)
        collected.extend(problems)
    return fail(*dict.fromkeys(collected))
