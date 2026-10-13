"""Static guards for stage A. Later stages must update these deliberately.

They scan the application source for code paths that could change a mailbox,
send e-mail or contact the network outside the approved places.
"""

import re
from pathlib import Path

import local_mail_cleaner
from local_mail_cleaner import auth_evidence, dkim_verify, headers, scanner, url_safety, verification
from local_mail_cleaner import strings_pl as S
from local_mail_cleaner.models import UnsubMethod, Verification

PACKAGE = Path(local_mail_cleaner.__file__).parent
SOURCES = {p.relative_to(PACKAGE).as_posix(): p.read_text(encoding="utf-8") for p in PACKAGE.rglob("*.py")}


def test_stage_flags():
    assert local_mail_cleaner.STAGE == "A"
    assert local_mail_cleaner.UNSUBSCRIBE_ENABLED is False
    assert local_mail_cleaner.QUARANTINE_ENABLED is False


def test_no_mailbox_mutation_or_mail_sending_code():
    forbidden = [
        (r"\bsmtplib\b", "sending e-mail"),
        (r"_imap\.(store|copy|move|expunge|append|create|delete|rename|close|subscribe|setacl)\(", "IMAP write"),
        (r"\.uid\(\s*['\"](STORE|COPY|MOVE|EXPUNGE)", "IMAP UID write"),
        (r"['\"]\s*(UID\s+)?(STORE|COPY|MOVE|EXPUNGE|APPEND)\s", "raw IMAP write command"),
        (r"\(\s*(UID\s+)?[A-Z0-9. ]*\bBODY\[", "non-PEEK body fetch in a FETCH item list"),
        (r"\bRFC822(\.TEXT)?\b(?!\.SIZE|\.HEADER)", "RFC822 fetch sets \\Seen"),
    ]
    hits = []
    for name, text in SOURCES.items():
        for line_no, line in enumerate(text.splitlines(), 1):
            code = line.split("#", 1)[0]
            if name == "imap_readonly.py" and ("_ALLOWED_FETCH_ITEM" in line or "r\"" in code or "rb\"" in code):
                continue
            for pattern, why in forbidden:
                if re.search(pattern, code):
                    hits.append(f"{name}:{line_no}: {why}: {line.strip()}")
    assert not hits, "\n".join(hits)


def test_folders_are_only_opened_read_only():
    for name, text in SOURCES.items():
        for line in text.splitlines():
            if "_imap.select" in line:
                assert "True" in line, f"{name}: select without readonly=True: {line.strip()}"


def test_network_access_only_in_approved_modules():
    approved_http = {"oauth_google.py"}
    for name, text in SOURCES.items():
        imports_http = re.search(
            r"^\s*(import|from)\s+(requests|httpx|urllib3|aiohttp|http\.client|urllib\.request)\b", text, re.M)
        if imports_http or re.search(r"\b(urlopen|build_opener)\(", text):
            assert name in approved_http, f"HTTP client code in {name}"
        if "http.server" in text or "HTTPServer" in text:
            assert name == "oauth_google.py", f"server code in {name}"
    oauth = SOURCES["oauth_google.py"]
    assert '("127.0.0.1", 0)' in oauth and "0.0.0.0" not in oauth


def test_tls_is_verified_for_imap():
    text = SOURCES["imap_readonly.py"]
    assert "ssl.create_default_context()" in text
    assert "CERT_NONE" not in "".join(SOURCES.values()) and "check_hostname = False" not in "".join(SOURCES.values())


def _codes(module, prefixes):
    return {v for k, v in vars(module).items() if k.startswith(prefixes) and isinstance(v, str) and k.isupper()}


def test_every_reason_code_has_a_polish_text():
    codes = set()
    codes |= _codes(auth_evidence, ("R_",))
    codes |= _codes(dkim_verify, ("R_",))
    codes |= _codes(verification, ("R_",))
    codes |= _codes(scanner, ("R_",))
    codes |= _codes(headers, ("H_",))
    codes |= _codes(url_safety, ("P_",))
    codes.add("unsupported_scheme")
    missing = sorted(c for c in codes if c not in S.REASONS)
    assert not missing, missing
    assert set(S.METHODS) == {m.value for m in UnsubMethod}
    assert set(S.VERIFICATION) == {v.value for v in Verification}


def test_logging_never_receives_raw_unsubscribe_values():
    # The raw List-Unsubscribe value is only stored, never passed to a logger.
    for name, text in SOURCES.items():
        for line in text.splitlines():
            if re.search(r"\blog\.\w+\(", line):
                args = line.split("(", 1)[1]
                assert not re.search(r"\b(uri|uris|list_unsubscribe(_raw)?)\b", args), (name, line)


def test_session_api_has_no_write_methods():
    from local_mail_cleaner.imap_readonly import ReadOnlySession

    public = {n for n in vars(ReadOnlySession) if not n.startswith("_")}
    assert public == {"connect", "logout", "login_password", "login_xoauth2", "list_folders", "examine",
                      "search_since", "fetch_headers", "fetch_size", "fetch_full"}
