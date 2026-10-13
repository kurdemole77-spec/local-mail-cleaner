"""Combine header facts and evidence into an unsubscribe method and a status."""

from __future__ import annotations

from local_mail_cleaner.headers import SECURITY_DUPLICATES
from local_mail_cleaner.models import CheckStatus, UnsubMethod, UnsubTarget, Verification

R_DUPLICATE_HEADERS = "duplicate_security_headers"
R_UNSAFE_TARGETS = "unsafe_unsubscribe_targets"
R_LOCAL_CONFLICT = "local_check_failed_provider_passed"


def classify_method(targets: list[UnsubTarget], one_click_post: bool) -> tuple[UnsubMethod, bool]:
    """Return (primary method, has a usable mailto alternative)."""
    safe_https = [t for t in targets if t.scheme == "https" and t.statically_safe]
    safe_mailto = [t for t in targets if t.scheme == "mailto" and t.statically_safe]
    http_only = [
        t for t in targets
        if t.scheme == "http" and set(t.problems) <= {"insecure_http"}
    ]
    if safe_https and one_click_post:
        primary = UnsubMethod.ONE_CLICK
    elif safe_https:
        primary = UnsubMethod.HTTPS_LINK
    elif safe_mailto:
        primary = UnsubMethod.MAILTO
    elif http_only:
        primary = UnsubMethod.HTTP_LINK
    elif targets:
        primary = UnsubMethod.UNSAFE
    else:
        primary = UnsubMethod.NONE
    return primary, bool(safe_mailto) and primary != UnsubMethod.MAILTO


def combine(
    method: UnsubMethod,
    header_problems: list[str],
    provider_status: CheckStatus,
    provider_reasons: list[str],
    local_status: CheckStatus = CheckStatus.NOT_RUN,
    local_reasons: list[str] | None = None,
) -> tuple[Verification, list[str]]:
    """Fail-closed combination of all evidence for one message."""
    if method == UnsubMethod.NONE:
        return Verification.NOT_APPLICABLE, []
    reasons: list[str] = []
    if SECURITY_DUPLICATES.intersection(header_problems):
        reasons.append(R_DUPLICATE_HEADERS)
    if method == UnsubMethod.UNSAFE:
        reasons.append(R_UNSAFE_TARGETS)
    if local_status == CheckStatus.FAIL:
        reasons.extend(local_reasons or [])
        if provider_status == CheckStatus.PASS:
            reasons.append(R_LOCAL_CONFLICT)
    elif local_status == CheckStatus.NOT_RUN and provider_status != CheckStatus.PASS:
        reasons.extend(provider_reasons)
    if reasons:
        return Verification.MANUAL_REVIEW, list(dict.fromkeys(reasons))
    if local_status == CheckStatus.PASS:
        return Verification.VERIFIED_LOCAL, []
    return Verification.VERIFIED_PROVIDER, []
