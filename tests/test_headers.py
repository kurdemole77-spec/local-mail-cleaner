from datetime import datetime, timedelta, timezone

from local_mail_cleaner import headers as H
from local_mail_cleaner.demo import build_message
from tests.conftest import NOW, newsletter


def test_parse_header_block_unfolds_and_keeps_order_and_duplicates():
    raw = (b"From: a@example.com\r\nList-Unsubscribe: <https://a.example.com/x>,\r\n <mailto:u@a.example.com>\r\n"
           b"X-Bad line without colon\r\nList-Unsubscribe: <https://b.example.com/y>\r\n\r\nbody: not a header\r\n")
    parsed = H.parse_header_block(raw)
    assert [name for name, _ in parsed] == ["from", "list-unsubscribe", "list-unsubscribe"]
    assert parsed[1][1] == "<https://a.example.com/x>, <mailto:u@a.example.com>"


def test_list_unsubscribe_multiple_uris_and_inner_whitespace():
    targets, problems = H.parse_list_unsubscribe(
        "<mailto:unsub@shop.example.com?subject=unsubscribe>,\t< https://shop.example.com/u/\r\n x >")
    assert problems == []
    assert [t.scheme for t in targets] == ["mailto", "https"]
    assert targets[1].uri == "https://shop.example.com/u/x"
    assert targets[0].host == "shop.example.com" and targets[1].host == "shop.example.com"
    assert all(t.statically_safe for t in targets)


def test_list_unsubscribe_malformed_without_brackets():
    targets, problems = H.parse_list_unsubscribe("https://shop.example.com/unsub")
    assert targets == [] and problems == [H.H_MALFORMED_LIST_UNSUB]


def test_list_unsubscribe_limits_and_unsupported_scheme():
    many = ", ".join(f"<https://h{i}.example.com/>" for i in range(12))
    targets, problems = H.parse_list_unsubscribe(many)
    assert len(targets) == H.MAX_URIS and H.H_TOO_MANY_URIS in problems
    assert H.parse_list_unsubscribe("<https://x.example.com/" + "a" * 5000 + ">") == ([], [H.H_LIST_UNSUB_TOO_LONG])
    targets, _ = H.parse_list_unsubscribe("<javascript:alert(1)>, <ftp://x.example.com/>")
    assert [t.problems for t in targets] == [("unsupported_scheme",), ("unsupported_scheme",)]


def test_list_id_variants():
    assert H.parse_list_id("Weekly News <Weekly.News.Example.COM>") == ("weekly.news.example.com", "Weekly News", [])
    assert H.parse_list_id("<list.example.org>")[0] == "list.example.org"
    assert H.parse_list_id("bare.list.example.org")[0] == "bare.list.example.org"
    assert H.parse_list_id('"=?utf-8?q?Lista_Pi=C4=85tkowa?=" <p.example.pl>')[1] == "Lista Piątkowa"
    assert H.parse_list_id("not a list id")[2] == [H.H_MALFORMED_LIST_ID]
    assert H.parse_list_id("<nodot>")[2] == [H.H_MALFORMED_LIST_ID]


def test_parse_from_variants():
    assert H.parse_from('=?utf-8?b?WmHFvMOzxYLEhyBHxJnFm2zEhQ==?= <News@Shop.Example.com>') == (
        "news@shop.example.com", "Zażółć Gęślą", "shop.example.com", [])
    addr, _, _, problems = H.parse_from("a@example.com, b@example.org")
    assert addr == "a@example.com" and H.H_MULTIPLE_FROM in problems
    assert H.parse_from("not an address")[3] == [H.H_INVALID_FROM]


def test_display_text_strips_controls_and_bidi_overrides():
    raw = build_message(from_header='"Bank‮LAPYAP" <x@example.com>', subject="Hi\x07 there\r\n\tfolded",
                        date=NOW, message_id="<1@example.com>", list_id="<l.example.com>")
    msg, _ = H.parse_message_headers(raw, uid=1, folder="INBOX", uidvalidity=1)
    assert "‮" not in msg.from_name and msg.from_name == "Bank LAPYAP"
    assert msg.subject == "Hi there folded"


def test_dates():
    fallback = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert H.parse_date("Tue, 13 Oct 2026 10:00:00 +0200") == datetime(2026, 10, 13, 8, 0, tzinfo=timezone.utc)
    assert H.parse_date("13 Oct 2026 10:00:00", fallback).tzinfo is not None  # naive -> UTC
    assert H.parse_date("garbage", fallback) == fallback
    future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    assert H.parse_date(future, fallback) == fallback
    assert H.parse_internaldate('"13-Oct-2026 10:00:00 +0200"') == datetime(2026, 10, 13, 8, 0, tzinfo=timezone.utc)
    assert H.parse_internaldate("nonsense") is None


def test_imap_date_is_locale_independent():
    assert H.imap_date(datetime(2026, 10, 3)) == "03-Oct-2026"
    assert H.imap_date(datetime(2025, 5, 31)) == "31-May-2025"


def test_parse_message_headers_full_newsletter():
    msg, headers = H.parse_message_headers(newsletter(), uid=7, folder="INBOX", uidvalidity=3)
    assert msg.is_candidate and msg.uid == 7 and msg.uidvalidity == 3
    assert msg.list_id == "weekly.shop.example.com"
    assert msg.one_click_post and msg.header_problems == []
    assert [t.scheme for t in msg.targets] == ["https", "mailto"]
    assert msg.from_domain == "shop.example.com"
    assert ("list-id", "<weekly.shop.example.com>") in headers


def test_duplicates_and_invalid_post_are_flagged():
    raw = build_message(
        from_header="a@example.com", subject="s", date=NOW, message_id="<d@example.com>",
        list_unsubscribe=["<https://evil.example.net/x>", "<https://good.example.com/y>"],
        list_unsubscribe_post="List-Unsubscribe=one-click-please",
        extra_headers=[("From", "b@example.org")],
    )
    msg, _ = H.parse_message_headers(raw, uid=1, folder="INBOX", uidvalidity=1)
    assert {H.H_DUP_LIST_UNSUB, H.H_DUP_FROM, H.H_INVALID_POST} <= set(msg.header_problems)
    assert not msg.one_click_post


def test_non_newsletter_is_not_candidate():
    raw = build_message(from_header="anna@example.org", subject="Lunch?", date=NOW, message_id="<p@example.org>")
    msg, _ = H.parse_message_headers(raw, uid=1, folder="INBOX", uidvalidity=1)
    assert not msg.is_candidate


def test_hostile_binary_headers_do_not_crash():
    raw = b"From: \xff\xfe<x@example.com>\r\nList-ID: <\x00\x01>\r\nList-Unsubscribe: <\xc3\x28>\r\n\r\n"
    msg, _ = H.parse_message_headers(raw, uid=1, folder="INBOX", uidvalidity=1)
    assert msg.is_candidate
    assert all(t.problems for t in msg.targets)
