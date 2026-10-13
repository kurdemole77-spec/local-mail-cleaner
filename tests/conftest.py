"""Shared fixtures. Everything is synthetic: example domains, throw-away keys."""

from __future__ import annotations

import base64
import imaplib
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("LMC_DATA_DIR", tempfile.mkdtemp(prefix="lmc-test-data-"))  # never the real profile

from local_mail_cleaner.credentials import CredentialStore, MemoryBackend  # noqa: E402
from local_mail_cleaner.demo import StoredMessage, build_message  # noqa: E402
from local_mail_cleaner.models import Account  # noqa: E402
from local_mail_cleaner.storage import Storage  # noqa: E402
from tests.fake_imap_server import FakeImapServer, FakeMailbox  # noqa: E402

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)

SIGNED_LIST_HEADERS = ["from", "to", "subject", "date", "message-id", "list-id",
                       "list-unsubscribe", "list-unsubscribe-post"]


@pytest.fixture
def now() -> datetime:
    return NOW


@pytest.fixture
def storage():
    st = Storage(":memory:")
    yield st
    st.close()


@pytest.fixture
def credentials() -> CredentialStore:
    return CredentialStore(MemoryBackend())


@pytest.fixture(scope="session")
def dkim_key():
    """A throw-away RSA key generated per test session (never stored)."""
    crypto = pytest.importorskip("cryptography")
    del crypto
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    der = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"pem": pem, "record": b"v=DKIM1; k=rsa; p=" + base64.b64encode(der)}


def sign(raw: bytes, key: dict, domain: str, selector: str = "s1", headers=None) -> bytes:
    """Prepend a real DKIM-Signature made with the session test key."""
    import dkim

    signature = dkim.sign(raw, selector.encode(), domain.encode(), key["pem"],
                          include_headers=[h.encode() for h in (headers or SIGNED_LIST_HEADERS)])
    return signature + raw


def dns_for(key: dict, *names: str):
    """Mock DNS returning the test public key for ``selector._domainkey.domain`` names."""
    records = {(n if n.endswith(".") else n + ".").encode(): key["record"] for n in names}

    def lookup(name: bytes, timeout: float = 5):
        return records.get(name if name.endswith(b".") else name + b".")

    return lookup


def newsletter(i: int = 0, *, sender="news@shop.example.com", list_id="<weekly.shop.example.com>",
               unsub="<https://shop.example.com/u/one-click?t=SECRETTOKEN123>, <mailto:unsub@shop.example.com>",
               post="List-Unsubscribe=One-Click", when: datetime | None = None, **kwargs) -> bytes:
    return build_message(
        from_header=f'"Shop" <{sender}>', subject=f"Weekly {i}",
        date=when or NOW - timedelta(days=i + 1), message_id=f"<n{i}.{sender}>",
        list_id=list_id, list_unsubscribe=unsub, list_unsubscribe_post=post, **kwargs,
    )


def stored(uid: int, raw: bytes, when: datetime | None = None, flags=None) -> StoredMessage:
    return StoredMessage(uid, raw, when or NOW - timedelta(days=1), set(flags or ()))


@pytest.fixture
def fake_server():
    """Start a fake IMAP server; yields (server, mailbox, imap_factory)."""
    mailbox = FakeMailbox()
    server = FakeImapServer(mailbox).start()

    def factory(host: str, port: int, timeout: int):
        return imaplib.IMAP4("127.0.0.1", server.port, timeout=timeout)

    yield server, mailbox, factory
    server.stop()


def account(provider="ionos", email="user@example.net", folders=("INBOX",), trusted=(), **kwargs) -> Account:
    return Account(provider=provider, email=email, host="imap.example.net", folders=list(folders),
                   trusted_authserv_ids=list(trusted), **kwargs)
