"""Gmail OAuth flow with a fake browser and a mocked token endpoint (no network)."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.parse
import urllib.request

import pytest

from local_mail_cleaner import oauth_google as O

CLIENT = O.ClientConfig("123-abc.apps.googleusercontent.com", "GOCSPX-synthetic")


def id_token(email="someone@example.com", aud=CLIENT.client_id, verified=True, iss="https://accounts.google.com"):
    payload = {"iss": iss, "aud": aud, "email": email, "email_verified": verified, "exp": time.time() + 3600}
    encode = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{encode({'alg': 'RS256'})}.{encode(payload)}.signature"


def token_endpoint(record: list, **overrides):
    def post(url, form):
        record.append((url, dict(form)))
        body = {"access_token": "ya29.synthetic", "expires_in": 3599, "refresh_token": "1//synthetic-refresh",
                "scope": "https://mail.google.com/ openid https://www.googleapis.com/auth/userinfo.email",
                "token_type": "Bearer", "id_token": id_token()}
        body.update(overrides)
        return 200, json.dumps({k: v for k, v in body.items() if v is not None}).encode()
    return post


def fake_browser(*, tamper_state=False, error=None, extra_requests=()):
    """Simulates the user's browser being redirected back to the loopback listener."""
    seen = {}

    def open_browser(url):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        seen.update({k: v[0] for k, v in query.items()})
        redirect = query["redirect_uri"][0]

        def visit():
            time.sleep(0.05)
            for path in extra_requests:
                try:
                    urllib.request.urlopen(redirect.rstrip("/") + path, timeout=5).read()
                except Exception:
                    pass
            if tamper_state:
                params = {"code": "attacker-code", "state": "forged"}
                try:
                    urllib.request.urlopen(redirect + "?" + urllib.parse.urlencode(params), timeout=5).read()
                except Exception:
                    pass
            params = {"state": query["state"][0]}
            params.update({"error": error} if error else {"code": "4/synthetic-code"})
            urllib.request.urlopen(redirect + "?" + urllib.parse.urlencode(params), timeout=5).read()

        threading.Thread(target=visit, daemon=True).start()
        return True

    return open_browser, seen


def test_load_client_config(tmp_path):
    good = tmp_path / "client.json"
    good.write_text(json.dumps({"installed": {"client_id": CLIENT.client_id, "client_secret": "GOCSPX-x",
                                              "redirect_uris": ["http://localhost"]}}))
    assert O.load_client_config(good).client_id == CLIENT.client_id
    web = tmp_path / "web.json"
    web.write_text(json.dumps({"web": {"client_id": CLIENT.client_id, "client_secret": "x"}}))
    nosecret = tmp_path / "nosecret.json"
    nosecret.write_text(json.dumps({"installed": {"client_id": CLIENT.client_id}}))
    huge = tmp_path / "huge.json"
    huge.write_text(" " * (O.MAX_CLIENT_FILE_BYTES + 1))
    for path in (web, nosecret, huge, tmp_path / "missing.json"):
        with pytest.raises(O.OAuthError) as info:
            O.load_client_config(path)
        assert info.value.kind == "config"


def test_pkce_and_auth_url():
    verifier, challenge = O.make_pkce()
    assert 43 <= len(verifier) <= 128
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected
    url = O.build_auth_url(CLIENT.client_id, "http://127.0.0.1:5000/", "st", challenge, "someone@example.com")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert url.startswith(O.AUTH_ENDPOINT)
    assert query["code_challenge_method"] == ["S256"] and query["access_type"] == ["offline"]
    assert "https://mail.google.com/" in query["scope"][0].split()
    assert query["redirect_uri"] == ["http://127.0.0.1:5000/"]


def test_interactive_flow_end_to_end(capsys):
    record: list = []
    browser, seen = fake_browser(extra_requests=["/favicon.ico"])
    tokens = O.authorize_interactive(CLIENT, "someone@example.com", open_browser=browser, timeout=10,
                                     http_post=token_endpoint(record))
    assert tokens.refresh_token == "1//synthetic-refresh" and tokens.email == "someone@example.com"
    assert seen["redirect_uri"].startswith("http://127.0.0.1:")
    (url, form), = record
    assert url == O.TOKEN_ENDPOINT and form["grant_type"] == "authorization_code"
    assert form["code"] == "4/synthetic-code" and form["redirect_uri"] == seen["redirect_uri"]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=")
    assert challenge.decode() == seen["code_challenge"]
    out = capsys.readouterr()
    assert "synthetic-code" not in out.out + out.err  # the request line is never logged


def test_idle_connection_does_not_block_sign_in():
    import socket

    record: list = []
    browser, seen = fake_browser()

    def open_browser(url):
        port = int(urllib.parse.urlsplit(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["redirect_uri"][0]).port)
        idle = socket.create_connection(("127.0.0.1", port))  # speculative connection, never sends
        seen["idle"] = idle
        return browser(url)

    tokens = O.authorize_interactive(CLIENT, "", open_browser=open_browser, timeout=20,
                                     http_post=token_endpoint(record))
    seen["idle"].close()
    assert tokens.access_token == "ya29.synthetic"


def test_forged_state_is_ignored():
    record: list = []
    browser, _ = fake_browser(tamper_state=True)
    tokens = O.authorize_interactive(CLIENT, "", open_browser=browser, timeout=10, http_post=token_endpoint(record))
    assert record[0][1]["code"] == "4/synthetic-code"  # the forged code was never exchanged
    assert tokens.access_token == "ya29.synthetic"


def test_denied_consent():
    browser, _ = fake_browser(error="access_denied")
    with pytest.raises(O.OAuthError) as info:
        O.authorize_interactive(CLIENT, "", open_browser=browser, timeout=10, http_post=token_endpoint([]))
    assert info.value.kind == "denied"


def test_account_mismatch():
    browser, _ = fake_browser()
    with pytest.raises(O.OAuthError) as info:
        O.authorize_interactive(CLIENT, "other@example.com", open_browser=browser, timeout=10,
                                http_post=token_endpoint([]))
    assert info.value.kind == "account_mismatch"


def test_cancel_and_timeout():
    event = threading.Event()
    event.set()
    with pytest.raises(O.OAuthError) as info:
        O.authorize_interactive(CLIENT, "", open_browser=lambda url: None, cancel_event=event, timeout=10)
    assert info.value.kind == "cancelled"
    with pytest.raises(O.OAuthError) as info:
        O.authorize_interactive(CLIENT, "", open_browser=lambda url: None, timeout=0.3)
    assert info.value.kind == "timeout"


@pytest.mark.parametrize("overrides,kind", [
    ({"scope": "openid email"}, "token"),
    ({"refresh_token": None}, "token"),
    ({"access_token": None}, "token"),
])
def test_bad_token_responses(overrides, kind):
    with pytest.raises(O.OAuthError) as info:
        O.exchange_code(CLIENT, "code", "verifier", "http://127.0.0.1:1/", token_endpoint([], **overrides))
    assert info.value.kind == kind


def test_refresh_and_revoked_grant():
    token = O.refresh_access_token(CLIENT, "1//r", token_endpoint([]))
    assert token.access_token == "ya29.synthetic" and token.expires_at > time.time()
    with pytest.raises(O.OAuthError) as info:
        O.refresh_access_token(CLIENT, "1//r", lambda url, form: (400, b'{"error":"invalid_grant"}'))
    assert info.value.kind == "reauth"
    with pytest.raises(O.OAuthError) as info:
        O.refresh_access_token(CLIENT, "1//r", lambda url, form: (500, b"<html>"))
    assert info.value.kind == "token"


def test_id_token_checks():
    assert O._decode_id_token_email(id_token(), CLIENT.client_id) == "someone@example.com"
    assert O._decode_id_token_email(id_token(aud="other"), CLIENT.client_id) == ""
    assert O._decode_id_token_email(id_token(verified=False), CLIENT.client_id) == ""
    assert O._decode_id_token_email(id_token(iss="https://evil.example"), CLIENT.client_id) == ""
    assert O._decode_id_token_email("garbage", CLIENT.client_id) == ""


def test_http_post_only_talks_to_google_and_never_redirects():
    with pytest.raises(O.OAuthError):
        O.default_http_post("https://evil.example.net/token", {})
    assert O._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://x.example") is None


def test_token_cache():
    calls = []
    cache = O.GmailTokenCache()

    def post(url, form):
        calls.append(1)
        return 200, json.dumps({"access_token": f"ya29.t{len(calls)}", "expires_in": 3600}).encode()

    assert cache.get(1, CLIENT, "1//r", post) == "ya29.t1"
    assert cache.get(1, CLIENT, "1//r", post) == "ya29.t1"
    cache.forget(1)
    assert cache.get(1, CLIENT, "1//r", post) == "ya29.t2"
