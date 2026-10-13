import csv
import threading

from local_mail_cleaner import cli
from local_mail_cleaner import strings_pl as S
from local_mail_cleaner.app import AppContext
from local_mail_cleaner.export import csv_safe, export_csv
from local_mail_cleaner.models import UnsubMethod, Verification


def demo_subscriptions(tmp_path):
    ctx = AppContext(tmp_path, demo=True)
    try:
        results = ctx.scan()
        return ctx, results, {(s.account_name, s.key): s for s in ctx.subscriptions()}
    finally:
        ctx.close()


def test_demo_scan_scenarios(tmp_path):
    ctx, results, subs = demo_subscriptions(tmp_path)
    assert [r.status for r in results] == ["ok", "ok"]
    promo = subs[("Demo Gmail", "list-id:promocje.sklep.example.com")]
    assert promo.message_count == 8  # copies in "[Gmail]/Wszystkie" counted once
    assert promo.method == UnsubMethod.ONE_CLICK and promo.has_mailto
    assert promo.verification == Verification.VERIFIED_PROVIDER
    # same sender address, different List-ID -> separate subscription
    assert subs[("Demo Gmail", "list-id:nowosci.sklep.example.com")].method == UnsubMethod.HTTPS_LINK
    assert subs[("Demo Gmail", "list-id:poranna.gazeta.example.com")].reasons == ["duplicate_security_headers"]
    bank = next(s for s in subs.values() if s.sender_addr == "powiadomienia@bank.example.net")
    assert bank.verification == Verification.MANUAL_REVIEW and "provider_dkim_not_pass" in bank.reasons
    okazje = next(s for s in subs.values() if s.sender_addr == "okazje@okazje.example.com")
    assert okazje.method == UnsubMethod.UNSAFE
    sport = [s for s in subs.values() if s.sender_addr == "info@sport.example.com"]
    assert len(sport) == 2  # same sender, different unsubscribe hosts, no List-ID
    portal = subs[("Demo IONOS", "list-id:tech.portal.example.com")]
    assert "provider_evidence_not_trusted" in portal.reasons
    assert not any(s.sender_addr == "anna@example.org" for s in subs.values())
    assert len(subs) == 13
    assert not ctx.db_path.exists()  # demo database is temporary


def test_demo_sessions_are_read_only(tmp_path):
    ctx = AppContext(tmp_path, demo=True)
    try:
        ctx.scan()
        ctx.verify(ctx.subscriptions()[:3])
        commands = [c for session in ctx.open_session.sessions for c in session.commands]
    finally:
        ctx.close()
    assert commands and all(c.split()[0] in {"EXAMINE", "UID", "LOGOUT"} for c in commands)
    assert all("PEEK" in c or "RFC822.SIZE" in c for c in commands if c.startswith("UID FETCH"))


def test_demo_verification_fails_closed_without_dns_keys(tmp_path):
    ctx = AppContext(tmp_path, demo=True)
    try:
        ctx.scan()
        target = [s for s in ctx.subscriptions() if s.key == "list-id:promocje.sklep.example.com"]
        (result,) = ctx.verify(target)
        after = next(s for s in ctx.subscriptions() if s.key == "list-id:promocje.sklep.example.com")
    finally:
        ctx.close()
    assert result.status.value == "fail"
    assert after.verification == Verification.MANUAL_REVIEW  # conflict with provider pass -> manual


def test_cancelled_demo_scan(tmp_path):
    ctx = AppContext(tmp_path, demo=True)
    event = threading.Event()
    event.set()
    try:
        assert ctx.scan(cancel=event) == []
    finally:
        ctx.close()


def test_csv_export_is_safe(tmp_path):
    ctx = AppContext(tmp_path, demo=True)
    try:
        ctx.scan()
        subs = ctx.subscriptions()
    finally:
        ctx.close()
    subs[0].sender_name = "=HYPERLINK(\"https://evil.example\")"
    path = tmp_path / "out.csv"
    assert export_csv(path, subs) == len(subs)
    content = path.read_text(encoding="utf-8-sig")
    assert "one-click?t=" not in content and "/u/" not in content
    rows = list(csv.reader(content.splitlines(), delimiter=";"))
    assert rows[0][0] == S.COLUMNS["mailbox"]
    assert rows[1][1].startswith("'=")
    assert csv_safe("+1") == "'+1" and csv_safe("ok") == "ok" and csv_safe(None) == ""


def test_cli_scan_demo_and_check(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("LMC_DATA_DIR", str(tmp_path))
    assert cli.main(["scan-demo"]) == 0
    out = capsys.readouterr().out
    assert "13 subskrypcji" in out and S.METHODS["one_click"] in out
    assert cli.main(["scan-demo", "--verify"]) == 0
    assert cli.main(["diagnostics"]) == 0
    assert "diagnostic report" in capsys.readouterr().out
    code = cli.main(["check"])
    out = capsys.readouterr().out
    assert "[OK] dkimpy" in out and "[OK] keyring" in out
    assert code in (0, 1)  # 1 only when Tkinter is missing in this interpreter
