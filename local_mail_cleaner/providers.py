"""Mailbox provider presets.

Host names and authentication methods follow the providers' public
documentation at the time of writing; they have NOT been exercised against the
real services from this code base. Users can edit host and port per account.
"""

from __future__ import annotations

from dataclasses import dataclass

AUTH_OAUTH2 = "oauth2"
AUTH_PASSWORD = "password"


@dataclass(frozen=True)
class ProviderPreset:
    key: str
    label: str
    host: str
    port: int
    auth: str
    host_choices: tuple[str, ...] = ()
    #: authserv-ids whose topmost Authentication-Results header is trusted.
    #: Only Gmail is trusted by default; see README "Verification".
    trusted_authserv_ids: tuple[str, ...] = ()


PROVIDERS: dict[str, ProviderPreset] = {
    "gmail": ProviderPreset(
        key="gmail",
        label="Gmail",
        host="imap.gmail.com",
        port=993,
        auth=AUTH_OAUTH2,
        trusted_authserv_ids=("mx.google.com",),
    ),
    "yahoo": ProviderPreset(
        key="yahoo",
        label="Yahoo Mail",
        host="imap.mail.yahoo.com",
        port=993,
        auth=AUTH_PASSWORD,  # Yahoo app password
    ),
    "ionos": ProviderPreset(
        key="ionos",
        label="IONOS",
        host="imap.ionos.de",
        port=993,
        auth=AUTH_PASSWORD,  # mailbox password
        host_choices=(
            "imap.ionos.de",
            "imap.ionos.co.uk",
            "imap.ionos.com",
            "imap.ionos.es",
            "imap.ionos.fr",
            "imap.ionos.it",
        ),
    ),
}


def get_provider(key: str) -> ProviderPreset:
    try:
        return PROVIDERS[key]
    except KeyError:
        raise ValueError(f"unknown provider: {key!r}") from None
