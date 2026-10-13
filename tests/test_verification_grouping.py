from datetime import datetime, timedelta, timezone

from local_mail_cleaner.grouping import aggregate, subscription_key
from local_mail_cleaner.headers import H_DUP_LIST_UNSUB, H_INVALID_POST
from local_mail_cleaner.models import CheckStatus, UnsubMethod, UnsubTarget, Verification
from local_mail_cleaner.verification import (
    R_DUPLICATE_HEADERS,
    R_LOCAL_CONFLICT,
    R_UNSAFE_TARGETS,
    classify_method,
    combine,
)

HTTPS = UnsubTarget("https", "https://a.example.com/u", "a.example.com")
HTTP = UnsubTarget("http", "http://a.example.com/u", "a.example.com", ("insecure_http",))
MAILTO = UnsubTarget("mailto", "mailto:u@a.example.com", "a.example.com")
BAD = UnsubTarget("https", "https://127.0.0.1/", "127.0.0.1", ("ip_literal", "forbidden_address"))


def test_classify_method():
    assert classify_method([HTTPS, MAILTO], True) == (UnsubMethod.ONE_CLICK, True)
    assert classify_method([HTTPS], False) == (UnsubMethod.HTTPS_LINK, False)
    assert classify_method([MAILTO], True) == (UnsubMethod.MAILTO, False)
    assert classify_method([HTTP], True) == (UnsubMethod.HTTP_LINK, False)
    assert classify_method([BAD], True) == (UnsubMethod.UNSAFE, False)
    assert classify_method([BAD, MAILTO], True) == (UnsubMethod.MAILTO, False)
    assert classify_method([], False) == (UnsubMethod.NONE, False)


def test_combine_is_fail_closed():
    one_click = UnsubMethod.ONE_CLICK
    assert combine(UnsubMethod.NONE, [], CheckStatus.PASS, []) == (Verification.NOT_APPLICABLE, [])
    assert combine(one_click, [], CheckStatus.PASS, []) == (Verification.VERIFIED_PROVIDER, [])
    assert combine(one_click, [], CheckStatus.FAIL, ["x"]) == (Verification.MANUAL_REVIEW, ["x"])
    assert combine(one_click, [], CheckStatus.FAIL, ["x"], CheckStatus.PASS, []) == (Verification.VERIFIED_LOCAL, [])
    status, reasons = combine(one_click, [], CheckStatus.PASS, [], CheckStatus.FAIL, ["dkim_signature_invalid"])
    assert status == Verification.MANUAL_REVIEW and R_LOCAL_CONFLICT in reasons
    status, reasons = combine(one_click, [H_DUP_LIST_UNSUB], CheckStatus.PASS, [], CheckStatus.PASS, [])
    assert status == Verification.MANUAL_REVIEW and reasons == [R_DUPLICATE_HEADERS]
    assert combine(UnsubMethod.UNSAFE, [], CheckStatus.PASS, [])[1] == [R_UNSAFE_TARGETS]
    # informational header problems alone do not block verification
    assert combine(one_click, [H_INVALID_POST], CheckStatus.PASS, [])[0] == Verification.VERIFIED_PROVIDER


def test_subscription_key_rules():
    https = [{"scheme": "https", "host": "a.example.com", "problems": []}]
    mailto = [{"scheme": "mailto", "host": "lists.example.com", "problems": []}]
    assert subscription_key("weekly.example.com", "x@example.com", https) == "list-id:weekly.example.com"
    assert subscription_key("", "x@example.com", mailto + https) == "sender:x@example.com|unsub:https:a.example.com"
    assert subscription_key("", "x@example.com", []) is None
    assert subscription_key("", "x@example.com", [], has_unsub_header=True) == "sender:x@example.com|unsub:invalid"


def row(uid, key, *, account=1, folder="INBOX", message_id=None, days_ago=1, method="one_click",
        verification="verified_provider", sender="news@example.com"):
    return {
        "id": uid, "account_id": account, "folder": folder, "uidvalidity": 1, "uid": uid,
        "message_id": message_id if message_id is not None else f"<{uid}@example.com>",
        "subscription_key": key, "from_name": "News", "from_addr": sender, "list_id": "", "list_id_desc": "",
        "subject": f"s{uid}", "date": datetime(2026, 10, 1, tzinfo=timezone.utc) - timedelta(days=days_ago),
        "method": method, "has_mailto": False, "verification": verification, "reasons": [], "targets": [],
        "local_status": "not_run", "local_checked_at": "",
    }


def test_aggregate_counts_dedupes_and_uses_latest_message():
    rows = [
        row(1, "list-id:a", days_ago=5, method="https_link", verification="manual_review"),
        row(2, "list-id:a", days_ago=1),
        row(3, "list-id:a", folder="[Gmail]/All Mail", message_id="<2@example.com>"),  # same message, other label
        row(4, "list-id:b", sender="news@example.com"),  # same sender, different list
        row(5, "list-id:a", account=2),  # same list in another mailbox
        row(6, None),  # not a subscription
    ]
    subs = {(s.account_id, s.key): s for s in aggregate(rows, {1: "A", 2: "B"})}
    assert set(subs) == {(1, "list-id:a"), (1, "list-id:b"), (2, "list-id:a")}
    first = subs[(1, "list-id:a")]
    assert first.message_count == 2
    assert first.method == UnsubMethod.ONE_CLICK and first.verification == Verification.VERIFIED_PROVIDER
    assert first.latest_ref["uid"] == 2


def test_aggregate_handles_missing_dates():
    rows = [row(1, "k"), row(2, "k")]
    rows[0]["date"] = None
    subs = aggregate(rows, {1: "A"})
    assert subs[0].message_count == 2 and subs[0].latest_ref["uid"] == 2
