"""Plain data structures shared across the application."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class UnsubMethod(str, Enum):
    """How a subscription could be ended, judged from its List-* headers."""

    ONE_CLICK = "one_click"  # RFC 8058 candidate: HTTPS URI + List-Unsubscribe-Post
    HTTPS_LINK = "https_link"  # ordinary link: manual browser action
    MAILTO = "mailto"  # e-mail request: separate preview and confirmation (stage B)
    HTTP_LINK = "http_link"  # unencrypted link: manual only
    UNSAFE = "unsafe"  # every destination failed the static safety checks
    NONE = "none"  # no usable List-Unsubscribe header


class Verification(str, Enum):
    """Whether the unsubscribe headers are authenticated."""

    VERIFIED_LOCAL = "verified_local"  # local DKIM verification passed
    VERIFIED_PROVIDER = "verified_provider"  # trusted provider evidence passed
    MANUAL_REVIEW = "manual_review"  # could not be verified: fail closed
    NOT_APPLICABLE = "not_applicable"  # nothing to verify (no unsubscribe header)


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_RUN = "not_run"


@dataclass(frozen=True)
class UnsubTarget:
    """One URI from List-Unsubscribe. ``uri`` is sensitive: never log it."""

    scheme: str
    uri: str = field(repr=False)
    host: str
    problems: tuple[str, ...] = ()

    @property
    def statically_safe(self) -> bool:
        return not self.problems


@dataclass
class ParsedMessage:
    """Header-derived facts about one message. Contains untrusted data."""

    uid: int
    folder: str
    uidvalidity: int
    message_id: str = ""
    from_addr: str = ""
    from_name: str = ""
    from_domain: str = ""
    subject: str = ""
    date: datetime | None = None
    list_id: str = ""
    list_id_desc: str = ""
    list_unsubscribe_raw: str = field(default="", repr=False)
    list_unsubscribe_post_raw: str = ""
    targets: list[UnsubTarget] = field(default_factory=list)
    one_click_post: bool = False
    header_problems: list[str] = field(default_factory=list)
    dkim_signature_count: int = 0
    provider_status: CheckStatus = CheckStatus.NOT_RUN
    provider_reasons: list[str] = field(default_factory=list)
    provider_signer: str = ""

    @property
    def is_candidate(self) -> bool:
        return bool(self.list_id or self.list_unsubscribe_raw)


@dataclass
class Account:
    """Mailbox account settings. Secrets live in the OS credential store only."""

    provider: str
    email: str
    host: str
    port: int = 993
    label: str = ""
    folders: list[str] = field(default_factory=lambda: ["INBOX"])
    scan_days: int = 365
    max_messages: int = 5000
    oauth_client_id: str = ""
    trusted_authserv_ids: list[str] = field(default_factory=list)
    id: int | None = None

    @property
    def display_name(self) -> str:
        return self.label or self.email


@dataclass
class Subscription:
    """Messages of one mailbox grouped under one subscription identity."""

    key: str
    account_id: int
    account_name: str
    sender_name: str
    sender_addr: str
    list_id: str
    list_desc: str
    message_count: int
    latest_date: datetime | None
    latest_subject: str
    method: UnsubMethod
    has_mailto: bool
    verification: Verification
    reasons: list[str]
    targets: list[dict]
    latest_ref: dict  # account_id, folder, uidvalidity, uid of the newest message
    local_status: CheckStatus = CheckStatus.NOT_RUN
    local_checked_at: str = ""
