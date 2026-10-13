import ipaddress

import pytest

from local_mail_cleaner import url_safety as U


@pytest.mark.parametrize("url", [
    "https://news.example.com/u?t=1",
    "https://news.example.com:443/u",
    "https://xn--bcher-kva.example.com/u",
    "https://bücher.example.com/u",
])
def test_safe_https_urls(url):
    scheme, host, problems = U.check_web_url(url)
    assert scheme == "https" and host and problems == []


@pytest.mark.parametrize("url,expected", [
    ("http://news.example.com/u", U.P_INSECURE_HTTP),
    ("https://127.0.0.1/u", U.P_FORBIDDEN_ADDRESS),
    ("https://10.1.2.3/u", U.P_FORBIDDEN_ADDRESS),
    ("https://192.168.0.10/u", U.P_FORBIDDEN_ADDRESS),
    ("https://169.254.169.254/latest/meta-data", U.P_FORBIDDEN_ADDRESS),
    ("https://[::1]/u", U.P_FORBIDDEN_ADDRESS),
    ("https://[fe80::1]/u", U.P_FORBIDDEN_ADDRESS),
    ("https://[::ffff:127.0.0.1]/u", U.P_FORBIDDEN_ADDRESS),
    ("https://8.8.8.8/u", U.P_IP_LITERAL),
    ("https://2130706433/u", U.P_IP_LITERAL),
    ("https://127.1/u", U.P_IP_LITERAL),
    ("https://0x7f.1/u", U.P_IP_LITERAL),
    ("https://localhost/u", U.P_LOCAL_NAME),
    ("https://printer.local/u", U.P_LOCAL_NAME),
    ("https://intranet/u", U.P_LOCAL_NAME),
    ("https://user:pw@news.example.com/u", U.P_USERINFO),
    ("https://news.example.com:8443/u", U.P_PORT),
    ("https://news.example.com/u\\..\\x", U.P_INVALID_CHARS),
    ("https://news.example.com/u\x00", U.P_INVALID_CHARS),
    ("https://news.example.com/" + "a" * 3000, U.P_TOO_LONG),
    ("https://bad_host!.example.com/", U.P_INVALID_HOST),
    ("https://news.example.com:99999/", U.P_INVALID_HOST),
])
def test_unsafe_urls(url, expected):
    _, _, problems = U.check_web_url(url)
    assert expected in problems


@pytest.mark.parametrize("address,forbidden", [
    ("8.8.8.8", False), ("2001:4860:4860::8888", False),
    ("127.0.0.1", True), ("10.0.0.1", True), ("100.64.0.1", True), ("169.254.1.1", True),
    ("192.0.2.1", True), ("224.0.0.1", True), ("0.0.0.0", True), ("255.255.255.255", True),
    ("::1", True), ("fc00::1", True), ("::ffff:10.0.0.1", True), ("2002:0a00:0001::1", True),
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", True),
])
def test_is_forbidden_ip(address, forbidden):
    assert U.is_forbidden_ip(ipaddress.ip_address(address)) is forbidden


def test_mailto_checks():
    assert U.check_mailto("mailto:Unsub@List.Example.com?subject=x") == ("unsub@list.example.com", "list.example.com", [])
    assert U.check_mailto("mailto:a@example.com,b@example.com")[2] == [U.P_MAILTO_MULTIPLE]
    assert U.check_mailto("mailto:not-an-address")[2] == [U.P_MAILTO_INVALID]
    assert U.P_LOCAL_NAME in U.check_mailto("mailto:root@localhost")[2]
    assert U.P_FORBIDDEN_ADDRESS in U.check_mailto("mailto:x@127.0.0.1")[2]
