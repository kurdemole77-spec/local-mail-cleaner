"""Local DKIM verification with real signatures made by a throw-away test key."""

import types

import pytest

from local_mail_cleaner import auth_evidence as A
from local_mail_cleaner import dkim_verify as D
from local_mail_cleaner.headers import parse_message_headers
from local_mail_cleaner.models import CheckStatus, Verification
from local_mail_cleaner.verification import R_DUPLICATE_HEADERS, classify_method, combine
from tests.conftest import dns_for, newsletter, sign

pytest.importorskip("dkim")

DOMAIN = "shop.example.com"


@pytest.fixture
def dns(dkim_key):
    return dns_for(dkim_key, f"s1._domainkey.{DOMAIN}")


def test_valid_signature_covering_headers_passes(dkim_key, dns):
    raw = sign(newsletter(), dkim_key, DOMAIN)
    result = D.verify_message(raw, DOMAIN, needs_post=True, dnsfunc=dns)
    assert result.status == CheckStatus.PASS and result.signer == DOMAIN


def test_tampered_unsubscribe_header_fails(dkim_key, dns):
    raw = sign(newsletter(), dkim_key, DOMAIN)
    tampered = raw.replace(b"https://shop.example.com/u/one-click", b"https://evil.example.net/u/one-click")
    result = D.verify_message(tampered, DOMAIN, needs_post=True, dnsfunc=dns)
    assert result.status == CheckStatus.FAIL and D.R_DKIM_INVALID in result.reasons


def test_tampered_body_fails(dkim_key, dns):
    raw = sign(newsletter(), dkim_key, DOMAIN) + b"appended\r\n"
    assert D.verify_message(raw, DOMAIN, True, dns).status == CheckStatus.FAIL


def test_signature_not_covering_unsubscribe_headers(dkim_key, dns):
    raw = sign(newsletter(), dkim_key, DOMAIN, headers=["from", "subject", "date"])
    result = D.verify_message(raw, DOMAIN, needs_post=True, dnsfunc=dns)
    assert result.status == CheckStatus.FAIL and A.R_NOT_COVERED in result.reasons


def test_signature_not_covering_post_header(dkim_key, dns):
    raw = sign(newsletter(), dkim_key, DOMAIN, headers=["from", "subject", "list-unsubscribe"])
    assert A.R_POST_NOT_COVERED in D.verify_message(raw, DOMAIN, True, dns).reasons
    assert D.verify_message(raw, DOMAIN, False, dns).status == CheckStatus.PASS


def test_signer_must_align_with_sender(dkim_key):
    raw = sign(newsletter(), dkim_key, "esp.example.net")
    result = D.verify_message(raw, DOMAIN, True, dns_for(dkim_key, "s1._domainkey.esp.example.net"))
    assert result.status == CheckStatus.FAIL and A.R_NOT_ALIGNED in result.reasons


def test_missing_dns_key_and_dns_errors_fail_closed(dkim_key):
    import dkim

    raw = sign(newsletter(), dkim_key, DOMAIN)
    assert D.verify_message(raw, DOMAIN, True, lambda name, timeout=5: None).status == CheckStatus.FAIL

    def timeout(name, timeout=5):
        raise dkim.DnsTimeoutError("timeout")

    assert D.verify_message(raw, DOMAIN, True, timeout).status == CheckStatus.FAIL

    def broken(name, timeout=5):
        raise RuntimeError("resolver exploded")

    assert D.verify_message(raw, DOMAIN, True, broken).status == CheckStatus.FAIL


def test_no_signature_and_oversized_message():
    assert D.verify_message(newsletter(), DOMAIN, True, lambda *a, **k: None).reasons == [A.R_NO_SIGNATURE]
    big = b"X" * (D.MAX_VERIFY_BYTES + 1)
    assert D.verify_message(big, DOMAIN, True, lambda *a, **k: None).reasons == [D.R_MESSAGE_TOO_LARGE]


def test_injected_unsigned_duplicate_list_unsubscribe_is_caught(dkim_key, dns):
    """DKIM still verifies (it signs the bottom-most copy) but the duplicate forces manual review."""
    raw = sign(newsletter(), dkim_key, DOMAIN)
    injected = b"List-Unsubscribe: <https://evil.example.net/steal>\r\n" + raw
    local = D.verify_message(injected, DOMAIN, True, dns)
    msg, _ = parse_message_headers(injected, uid=1, folder="INBOX", uidvalidity=1)
    method, _ = classify_method(msg.targets, msg.one_click_post)
    verification, reasons = combine(method, msg.header_problems, CheckStatus.NOT_RUN, [], local.status, local.reasons)
    assert verification == Verification.MANUAL_REVIEW and R_DUPLICATE_HEADERS in reasons


def test_dns_lookup_wrapper(monkeypatch):
    import dkim
    import dns.exception
    import dns.resolver

    calls = {}

    def fake_resolve(self, qname, rdtype, search=False, raise_on_no_answer=False, lifetime=None):
        calls["qname"] = str(qname)
        calls["search"] = search
        mode = calls["mode"]
        if mode == "nx":
            raise dns.resolver.NXDOMAIN()
        if mode == "timeout":
            raise dns.exception.Timeout()
        records = [types.SimpleNamespace(strings=[b"v=DKIM1; ", b"p=AAA"])]
        if mode == "two":
            records.append(types.SimpleNamespace(strings=[b"v=DKIM1; p=BBB"]))
        return types.SimpleNamespace(rrset=records)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    lookup = D.make_dns_txt_lookup()
    calls["mode"] = "one"
    assert lookup(b"s1._domainkey.shop.example.com.") == b"v=DKIM1; p=AAA"
    assert calls["qname"] == "s1._domainkey.shop.example.com." and calls["search"] is False
    calls["mode"] = "two"
    assert lookup(b"s1._domainkey.shop.example.com") is None  # ambiguous -> fail closed
    calls["mode"] = "nx"
    assert lookup(b"x.example.com.") is None
    calls["mode"] = "timeout"
    with pytest.raises(dkim.DnsTimeoutError):
        lookup(b"x.example.com.")
