"""Gmail OAuth 2.0 for installed (desktop) applications.

* Authorization code flow with PKCE (S256) and a random ``state``.
* The redirect listener binds to 127.0.0.1 on a random port, only while the
  user signs in, and answers a single matching request. No public interface.
* Tokens are exchanged with Google's fixed token endpoint over verified TLS,
  without following redirects, with a timeout and a response-size limit.
* The refresh token is stored by the caller in the OS credential store; access
  tokens stay in memory. Nothing token-related is logged.

The user supplies their own OAuth client (``client_secret_*.json`` of type
"Desktop app") created in their Google Cloud project; see the setup guide.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import logging
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GMAIL_SCOPE = "https://mail.google.com/"  # the only scope Gmail accepts for IMAP
SCOPES = (GMAIL_SCOPE, "openid", "email")
HTTP_TIMEOUT = 20
MAX_RESPONSE_BYTES = 64 * 1024
MAX_CLIENT_FILE_BYTES = 64 * 1024
LOGIN_TIMEOUT = 300


class OAuthError(RuntimeError):
    """``kind``: config, cancelled, timeout, denied, token, network, reauth, account_mismatch."""

    def __init__(self, kind: str, message: str = ""):
        super().__init__(message or kind)
        self.kind = kind


@dataclass(frozen=True)
class ClientConfig:
    client_id: str
    client_secret: str = field(repr=False)


@dataclass
class TokenSet:
    access_token: str = field(repr=False)
    expires_at: float
    refresh_token: str = field(default="", repr=False)
    email: str = ""
    scope: str = ""


HttpPost = Callable[[str, dict], "tuple[int, bytes]"]


def load_client_config(path: str | Path) -> ClientConfig:
    """Read a Google "Desktop app" OAuth client JSON file."""
    path = Path(path)
    try:
        if path.stat().st_size > MAX_CLIENT_FILE_BYTES:
            raise OAuthError("config", "client file too large")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OAuthError("config", f"cannot read client file: {type(exc).__name__}") from None
    if not isinstance(data, dict) or "installed" not in data:
        raise OAuthError("config", "not a Desktop app OAuth client (missing 'installed')")
    installed = data["installed"]
    client_id = str(installed.get("client_id", "")).strip()
    client_secret = str(installed.get("client_secret", "")).strip()
    if not client_id.endswith(".apps.googleusercontent.com") or not client_secret:
        raise OAuthError("config", "client_id or client_secret missing or invalid")
    return ClientConfig(client_id, client_secret)


def make_pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge.rstrip(b"=").decode("ascii")


def build_auth_url(client_id: str, redirect_uri: str, state: str, challenge: str, login_hint: str = "") -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    if login_hint:
        params["login_hint"] = login_hint
    return AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # never follow redirects


def default_http_post(url: str, form: dict) -> tuple[int, bytes]:
    """POST a form to Google's token endpoint. Returns (status, body)."""
    if url != TOKEN_ENDPOINT:
        raise OAuthError("network", "unexpected token endpoint")
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())
    data = urllib.parse.urlencode(form).encode("ascii")
    request = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, response.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_RESPONSE_BYTES) if exc.fp else b""
        return exc.code, body
    except (urllib.error.URLError, OSError) as exc:
        raise OAuthError("network", f"token request failed: {type(exc).__name__}") from None


def _decode_id_token_email(id_token: str, client_id: str) -> str:
    """Extract the e-mail from an ID token received directly from the token endpoint.

    The token came straight from Google over verified TLS, which OpenID Connect
    accepts in place of signature validation; we still check iss/aud/expiry.
    """
    try:
        payload_b64 = id_token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    except (IndexError, ValueError):
        return ""
    if payload.get("iss") not in ("https://accounts.google.com", "accounts.google.com"):
        return ""
    if payload.get("aud") != client_id or float(payload.get("exp", 0)) < time.time() - 300:
        return ""
    if not payload.get("email_verified", False):
        return ""
    return str(payload.get("email", "")).lower()


def _token_request(form: dict, http_post: HttpPost | None) -> dict:
    status, body = (http_post or default_http_post)(TOKEN_ENDPOINT, form)
    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except (UnicodeDecodeError, ValueError):
        payload = {}
    if status != 200:
        error = str(payload.get("error", "")) if isinstance(payload, dict) else ""
        if error == "invalid_grant":
            raise OAuthError("reauth", "Google rejected the stored sign-in; sign in again")
        raise OAuthError("token", f"token endpoint returned HTTP {status} {error[:40]}")
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise OAuthError("token", "token response without access_token")
    return payload


def exchange_code(
    client: ClientConfig, code: str, verifier: str, redirect_uri: str, http_post: HttpPost | None = None
) -> TokenSet:
    payload = _token_request(
        {
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": verifier,
        },
        http_post,
    )
    scope = str(payload.get("scope", ""))
    if GMAIL_SCOPE not in scope.split():
        raise OAuthError("token", "Gmail IMAP scope was not granted")
    if not payload.get("refresh_token"):
        raise OAuthError("token", "no refresh token returned")
    return TokenSet(
        access_token=str(payload["access_token"]),
        expires_at=time.time() + float(payload.get("expires_in", 3600)),
        refresh_token=str(payload["refresh_token"]),
        email=_decode_id_token_email(str(payload.get("id_token", "")), client.client_id),
        scope=scope,
    )


def refresh_access_token(client: ClientConfig, refresh_token: str, http_post: HttpPost | None = None) -> TokenSet:
    payload = _token_request(
        {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        http_post,
    )
    return TokenSet(
        access_token=str(payload["access_token"]),
        expires_at=time.time() + float(payload.get("expires_in", 3600)),
        scope=str(payload.get("scope", "")),
    )


_DONE_PAGE = (
    "<!doctype html><html lang='pl'><head><meta charset='utf-8'><title>Local Mail Cleaner</title></head>"
    "<body style='font-family:sans-serif'><h2>{title}</h2><p>{text}</p></body></html>"
)


class _CallbackServer(http.server.HTTPServer):
    allow_reuse_address = False

    def __init__(self, expected_state: str):
        super().__init__(("127.0.0.1", 0), _CallbackHandler)
        self.expected_state = expected_state
        self.result: dict | None = None


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    server: _CallbackServer
    # Browsers may open speculative connections that never send a request;
    # without a socket timeout one of those would block the sign-in loop.
    timeout = 5

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass  # the request line contains the authorization code: never log it

    def _reply(self, status: int, title: str, text: str) -> None:
        body = _DONE_PAGE.format(title=title, text=text).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/" or self.server.result is not None:
            self._reply(404, "Nie znaleziono", "")
            return
        query = urllib.parse.parse_qs(parsed.query, max_num_fields=10)
        state = query.get("state", [""])[0]
        if not hmac.compare_digest(state.encode(), self.server.expected_state.encode()):
            self._reply(400, "Nieprawidlowe zadanie", "Parametr state nie pasuje. Zamknij to okno.")
            return
        error = query.get("error", [""])[0]
        code = query.get("code", [""])[0]
        self.server.result = {"code": code, "error": error}
        if error or not code:
            self._reply(200, "Logowanie przerwane", "Mozesz zamknac to okno.")
        else:
            self._reply(200, "Zalogowano", "Mozesz zamknac to okno i wrocic do Local Mail Cleaner.")


def authorize_interactive(
    client: ClientConfig,
    login_hint: str = "",
    *,
    open_browser: Callable[[str], object] = webbrowser.open,
    timeout: float = LOGIN_TIMEOUT,
    cancel_event: threading.Event | None = None,
    http_post: HttpPost | None = None,
) -> TokenSet:
    """Run the browser sign-in and return tokens (including the refresh token)."""
    state = secrets.token_urlsafe(32)
    verifier, challenge = make_pkce()
    server = _CallbackServer(state)
    try:
        port = server.server_address[1]
        redirect_uri = f"http://127.0.0.1:{port}/"
        log.info("Waiting for Google sign-in on the loopback interface (port %d)", port)
        open_browser(build_auth_url(client.client_id, redirect_uri, state, challenge, login_hint))
        server.timeout = 0.5
        deadline = time.monotonic() + timeout
        while server.result is None:
            if cancel_event is not None and cancel_event.is_set():
                raise OAuthError("cancelled", "sign-in cancelled")
            if time.monotonic() > deadline:
                raise OAuthError("timeout", "sign-in timed out")
            server.handle_request()
    finally:
        server.server_close()
    result = server.result
    if result["error"] or not result["code"]:
        raise OAuthError("denied", "sign-in was not completed")
    tokens = exchange_code(client, result["code"], verifier, redirect_uri, http_post)
    if login_hint and tokens.email and tokens.email != login_hint.lower():
        raise OAuthError("account_mismatch", "signed in with a different Google account")
    return tokens


class GmailTokenCache:
    """In-memory access-token cache keyed by account id."""

    def __init__(self):
        self._tokens: dict[int, TokenSet] = {}
        self._lock = threading.Lock()

    def get(self, account_id: int, client: ClientConfig, refresh_token: str, http_post: HttpPost | None = None) -> str:
        with self._lock:
            cached = self._tokens.get(account_id)
            if cached and cached.expires_at - 120 > time.time():
                return cached.access_token
        token = refresh_access_token(client, refresh_token, http_post)
        with self._lock:
            self._tokens[account_id] = token
        return token.access_token

    def forget(self, account_id: int) -> None:
        with self._lock:
            self._tokens.pop(account_id, None)
