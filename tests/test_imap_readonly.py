import pytest

from local_mail_cleaner import imap_readonly as I


@pytest.mark.parametrize("name", ["INBOX", "[Gmail]/Ważne", "Kosz & Spam", "Pocztа ☃/Ünïcödé", "&"])
def test_mailbox_name_round_trip(name):
    encoded = I.encode_mailbox_name(name)
    assert encoded.isascii()
    assert I.decode_mailbox_name(encoded) == name


def test_known_modified_utf7_values():
    assert I.decode_mailbox_name(b"[Gmail]/Wa&AXw-ne") == "[Gmail]/Ważne"
    assert I.encode_mailbox_name("A&B") == "A&-B"
    assert I.quote_mailbox('Bulk "Mail"\\x') == '"Bulk \\"Mail\\"\\\\x"'
    with pytest.raises(ValueError):
        I.quote_mailbox("bad\r\nname")


@pytest.mark.parametrize("spec", [
    "(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM LIST-ID)])",
    "(UID BODY.PEEK[])",
    "(UID RFC822.SIZE)",
    "(UID FLAGS BODY.PEEK[HEADER])",
])
def test_allowed_fetch_items(spec):
    I.check_fetch_items(spec)


@pytest.mark.parametrize("spec", [
    "(BODY[])", "(UID BODY[HEADER])", "(RFC822)", "(RFC822.TEXT)", "(BODY[TEXT])",
    "(BINARY[1])", "(UID BODY.PEEK[TEXT])", "()", "(UID BODY.PEEK[HEADER.FIELDS (FROM)]",
])
def test_rejected_fetch_items(spec):
    with pytest.raises(I.ReadOnlyViolation):
        I.check_fetch_items(spec)


def test_uid_set_compression():
    assert I.uid_set([5, 1, 2, 3, 7, 8, 8]) == "1:3,5,7:8"
    with pytest.raises(ValueError):
        I.uid_set([])


def test_parse_fetch_response_uid_before_and_after_literal():
    data = [
        (b'1 (UID 101 INTERNALDATE "13-Oct-2026 10:00:00 +0000" BODY[HEADER.FIELDS (FROM)] {22}',
         b"From: a@example.com\r\n\r\n"),
        b")",
        (b'2 (INTERNALDATE "12-Oct-2026 10:00:00 +0000" BODY[HEADER.FIELDS (FROM)] {22}',
         b"From: b@example.com\r\n\r\n"),
        b" UID 102)",
        b"3 (FLAGS (\\Seen))",  # unsolicited update without UID: ignored
        b"4 (UID 104 RFC822.SIZE 2048)",
    ]
    messages = {m.uid: m for m in I.parse_fetch_response(data)}
    assert set(messages) == {101, 102, 104}
    assert I.find_header_section(messages[102]) == b"From: b@example.com\r\n\r\n"
    assert messages[101].internaldate.day == 13 and messages[104].size == 2048


def test_literal_content_is_never_parsed_as_metadata():
    data = [(b"1 (BODY[] {30}", b"Subject: UID 999 RFC822.SIZE 1\r\n"), b" UID 5)"]
    (message,) = I.parse_fetch_response(data)
    assert message.uid == 5 and message.size is None and message.sections["BODY[]"].startswith(b"Subject")


class RecordingImap:
    """Stand-in for imaplib.IMAP4 that records calls."""

    def __init__(self):
        self.calls = []
        self.untagged_responses = {}
        self.debug = 5

    def uid(self, *args):
        self.calls.append(("uid",) + args)
        return "OK", [b""]

    def logout(self):
        self.calls.append(("logout",))


def test_session_guards_reject_write_commands_and_require_examine():
    imap = RecordingImap()
    session = I.ReadOnlySession(imap)
    assert imap.debug == 0  # protocol debugging (prints credentials) forced off
    with pytest.raises(I.ReadOnlyViolation):
        session.fetch_headers([1], ["FROM"])  # no EXAMINE yet
    session._selected = I.FolderStatus("INBOX", 1, 1)
    for command in ("STORE", "COPY", "MOVE", "EXPUNGE"):
        with pytest.raises(I.ReadOnlyViolation):
            session._uid(command, "1", "+FLAGS (\\Seen)")
    with pytest.raises(I.ReadOnlyViolation):
        session._uid("FETCH", "1", "(BODY[])")
    assert not any(call[1] in ("STORE", "COPY", "MOVE", "EXPUNGE") for call in imap.calls if len(call) > 1)
    with pytest.raises(ValueError):
        session.fetch_headers([1], ["FROM)] BODY[TEXT"])


def test_session_exposes_no_mutating_operations():
    for name in ("store", "copy", "move", "expunge", "append", "create", "delete", "rename", "close", "select"):
        assert not hasattr(I.ReadOnlySession, name)


def test_examine_fails_closed_without_read_only_confirmation():
    class Imap(RecordingImap):
        def select(self, mailbox, readonly=False):
            self.calls.append(("select", mailbox, readonly))
            self.untagged_responses = {"UIDVALIDITY": [b"7"]}  # no READ-ONLY code
            return "OK", [b"3"]

    imap = Imap()
    session = I.ReadOnlySession(imap)
    with pytest.raises(I.MailboxError) as info:
        session.examine("INBOX")
    assert info.value.kind == I.MailboxError.KIND_READ_ONLY
    assert imap.calls == [("select", '"INBOX"', True)]
    with pytest.raises(I.ReadOnlyViolation):
        session.search_since(__import__("datetime").datetime(2026, 1, 1))
