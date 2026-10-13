import pytest

from local_mail_cleaner import auth_evidence as A
from local_mail_cleaner.demo import dkim_header, fake_b64
from local_mail_cleaner.models import CheckStatus

ALL = ("from", "subject", "date", "list-id", "list-unsubscribe", "list-unsubscribe-post")
NO_POST = ("from", "subject", "date", "list-unsubscribe")
NO_LIST = ("from", "subject", "date")
GMAIL = ["mx.google.com"]


def ar(result="pass", domain="shop.example.com", b="", authserv="mx.google.com", key="header.i"):
    value = f"@{domain}" if key == "header.i" else domain
    bpart = f" header.b={b[:8]}" if b else ""
    return (f"{authserv};\r\n dkim={result} ({result} result) {key}={value} header.s=s1{bpart};\r\n"
            f" spf=pass smtp.mailfrom=bounce@{domain}; dmarc=pass header.from={domain}")


def headers(*, ar_values=(), sigs=()):
    return [("authentication-results", v) for v in ar_values] + [("dkim-signature", s) for s in sigs]


def evaluate(hdrs, trusted=GMAIL, from_domain="shop.example.com", needs_post=True):
    return A.evaluate_provider_evidence(hdrs, trusted, from_domain, needs_post)


def test_tag_list_parsing():
    assert A.parse_tag_list("v=1; a=rsa-sha256;\r\n\th=From : Subject;b=ab cd") == {
        "v": "1", "a": "rsa-sha256", "h": "From:Subject", "b": "abcd"}
    assert A.parse_tag_list("v=1; v=2") is None
    assert A.parse_tag_list("v=1; broken") is None
    sig = A.parse_dkim_signature(dkim_header("Shop.Example.com.", "s1", ALL, "QUJD", extra=" l=100;"))
    assert sig.domain == "shop.example.com" and sig.has_length_tag and "list-unsubscribe-post" in sig.signed_headers
    assert A.parse_dkim_signature("v=1; d=x.example.com") is None


def test_authentication_results_parsing():
    parsed = A.parse_authentication_results(
        'mx.google.com 1; dkim=pass (good (nested) comment) header.i=@shop.example.com header.b="AbCd;123";'
        " spf=softfail smtp.mailfrom=x@y.example; arc=none")
    assert parsed.authserv_id == "mx.google.com"
    assert [(r.method, r.result) for r in parsed.results] == [("dkim", "pass"), ("spf", "softfail"), ("arc", "none")]
    assert parsed.results[0].props["header.b"] == "AbCd;123"
    assert A.parse_authentication_results("mx.google.com; none").results == []
    assert A.parse_authentication_results("dkim=pass") is None


def test_trusted_gmail_evidence_passes():
    b = fake_b64("ok")
    result = evaluate(headers(ar_values=[ar(b=b)], sigs=[dkim_header("shop.example.com", "s1", ALL, b)]))
    assert result.status == CheckStatus.PASS and result.signer == "shop.example.com"


def test_header_d_property_is_supported():
    b = fake_b64("d")
    result = evaluate(headers(ar_values=[ar(b=b, key="header.d")], sigs=[dkim_header("shop.example.com", "s1", ALL, b)]))
    assert result.status == CheckStatus.PASS


def test_presence_of_signature_alone_is_not_proof():
    b = fake_b64("x")
    result = evaluate(headers(sigs=[dkim_header("shop.example.com", "s1", ALL, b)]))
    assert result.status == CheckStatus.FAIL
    assert A.R_SIGNATURE_UNVERIFIED in result.reasons and A.R_NO_PROVIDER_RESULTS in result.reasons


def test_untrusted_provider_never_passes():
    b = fake_b64("u")
    result = evaluate(headers(ar_values=[ar(b=b)], sigs=[dkim_header("shop.example.com", "s1", ALL, b)]), trusted=[])
    assert result.status == CheckStatus.FAIL and A.R_PROVIDER_NOT_TRUSTED in result.reasons


def test_only_topmost_authentication_results_counts():
    b = fake_b64("forged")
    sig = dkim_header("shop.example.com", "s1", ALL, b)
    forged_below = evaluate(headers(ar_values=[ar("fail", b=b), ar("pass", b=b)], sigs=[sig]))
    assert forged_below.status == CheckStatus.FAIL and A.R_PROVIDER_DKIM_NOT_PASS in forged_below.reasons
    foreign_top = evaluate(headers(ar_values=[ar(b=b, authserv="mx.attacker.example"), ar(b=b)], sigs=[sig]))
    assert foreign_top.status == CheckStatus.FAIL and A.R_TOP_RESULTS_UNTRUSTED in foreign_top.reasons


@pytest.mark.parametrize("signed,needs_post,reason", [
    (NO_LIST, False, A.R_NOT_COVERED),
    (NO_POST, True, A.R_POST_NOT_COVERED),
])
def test_coverage_of_unsubscribe_headers_is_required(signed, needs_post, reason):
    b = fake_b64("cov")
    result = evaluate(headers(ar_values=[ar(b=b)], sigs=[dkim_header("shop.example.com", "s1", signed, b)]),
                      needs_post=needs_post)
    assert result.status == CheckStatus.FAIL and reason in result.reasons


def test_post_coverage_not_needed_without_post_header():
    b = fake_b64("np")
    result = evaluate(headers(ar_values=[ar(b=b)], sigs=[dkim_header("shop.example.com", "s1", NO_POST, b)]),
                      needs_post=False)
    assert result.status == CheckStatus.PASS


def test_unaligned_signer_needs_manual_review():
    b = fake_b64("esp")
    result = evaluate(headers(ar_values=[ar(domain="esp.example.net", b=b)],
                              sigs=[dkim_header("esp.example.net", "s1", ALL, b)]))
    assert result.status == CheckStatus.FAIL and A.R_NOT_ALIGNED in result.reasons


def test_weak_algorithm_and_length_tag_are_rejected():
    b = fake_b64("weak")
    weak = evaluate(headers(ar_values=[ar(b=b)], sigs=[dkim_header("shop.example.com", "s1", ALL, b, a="rsa-sha1")]))
    assert A.R_WEAK_ALGORITHM in weak.reasons
    length = evaluate(headers(ar_values=[ar(b=b)], sigs=[dkim_header("shop.example.com", "s1", ALL, b, extra=" l=10;")]))
    assert A.R_LENGTH_TAG in length.reasons


def test_header_b_must_match_signature():
    b = fake_b64("one")
    result = evaluate(headers(ar_values=[ar(b=fake_b64("other"))], sigs=[dkim_header("shop.example.com", "s1", ALL, b)]))
    assert result.status == CheckStatus.FAIL and A.R_NO_MATCHING_SIGNATURE in result.reasons


def test_forged_duplicate_signature_with_copied_b_value_is_rejected():
    """Attacker copies a real signature's b= into a forged one that claims coverage."""
    b = fake_b64("real")
    real = dkim_header("shop.example.com", "s1", NO_LIST, b)  # does not cover List-Unsubscribe
    forged = dkim_header("shop.example.com", "s1", ALL, b)  # same b= prefix, claims coverage
    result = evaluate(headers(ar_values=[ar(b=b)], sigs=[forged, real]))
    assert result.status == CheckStatus.FAIL
    assert A.R_AMBIGUOUS_SIGNATURE in result.reasons and A.R_NOT_COVERED in result.reasons


def test_without_header_b_all_candidate_signatures_must_qualify():
    good = dkim_header("shop.example.com", "s1", ALL, fake_b64("g"))
    bad = dkim_header("shop.example.com", "s2", NO_LIST, fake_b64("b"))
    assert evaluate(headers(ar_values=[ar()], sigs=[good])).status == CheckStatus.PASS
    assert evaluate(headers(ar_values=[ar()], sigs=[good, bad])).status == CheckStatus.FAIL


@pytest.mark.parametrize("signer,from_domain,aligned", [
    ("example.com", "example.com", True),
    ("example.com", "news.example.com", True),
    ("mail.example.com", "example.com", True),
    ("mail.example.com", "news.example.com", False),
    ("example.net", "example.com", False),
    ("co.uk", "shop.co.uk", False),
    ("com", "example.com", False),
    ("", "example.com", False),
])
def test_domain_alignment(signer, from_domain, aligned):
    assert A.domains_aligned(signer, from_domain) is aligned
