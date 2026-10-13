"""A minimal in-process IMAP4rev1 server for mocked integration tests.

Plain TCP on 127.0.0.1 only (tests use ``imaplib.IMAP4``, not TLS). It records
every command and models the ``\\Seen`` flag like a real server: a non-PEEK
BODY[]/RFC822 fetch in a mailbox opened with SELECT marks the message read;
EXAMINE (read-only) never changes flags. Write commands are implemented just
enough to be detectable, so tests can prove the client never sends them.
"""

from __future__ import annotations

import base64
import re
import socketserver
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

from local_mail_cleaner.demo import StoredMessage, extract_header_fields
from local_mail_cleaner.imap_readonly import split_fetch_items

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
WRITE_COMMANDS = {"STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "CREATE", "DELETE", "RENAME", "CLOSE",
                  "SUBSCRIBE", "UNSUBSCRIBE", "SETACL", "SELECT"}


def internaldate(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return f"{dt.day:02d}-{MONTHS[dt.month - 1]}-{dt.year} {dt:%H:%M:%S} +0000"


@dataclass
class FakeMailbox:
    folders: dict[str, list[StoredMessage]] = field(default_factory=dict)
    uidvalidity: dict[str, int] = field(default_factory=dict)
    passwords: dict[str, str] = field(default_factory=dict)
    oauth_tokens: dict[str, str] = field(default_factory=dict)
    confirm_read_only: bool = True
    uid_after_literal: bool = False
    commands: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, text: str) -> None:
        with self.lock:
            self.commands.append(text)

    def command_names(self) -> list[str]:
        return [c.split(" ", 1)[0] for c in self.commands]

    def flags_snapshot(self) -> dict[tuple[str, int], frozenset]:
        return {(f, m.uid): frozenset(m.flags) for f, msgs in self.folders.items() for m in msgs}


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == " ":
            i += 1
            continue
        if ch == '"':
            j, buf = i + 1, []
            while text[j] != '"':
                if text[j] == "\\":
                    j += 1
                buf.append(text[j])
                j += 1
            tokens.append("".join(buf))
            i = j + 1
            continue
        j, depth = i, 0
        while j < len(text) and (text[j] != " " or depth > 0):
            if text[j] in "[(":
                depth += 1
            elif text[j] in "])":
                depth -= 1
            j += 1
        tokens.append(text[i:j])
        i = j
    return tokens


def parse_set(spec: str, uids: list[int]) -> set[int]:
    result: set[int] = set()
    top = max(uids) if uids else 0
    for part in spec.split(","):
        if ":" in part:
            a, b = part.split(":")
            lo = top if a == "*" else int(a)
            hi = top if b == "*" else int(b)
            lo, hi = min(lo, hi), max(lo, hi)
            result.update(u for u in uids if lo <= u <= hi)
        else:
            value = top if part == "*" else int(part)
            if value in uids:
                result.add(value)
    return result


class _Handler(socketserver.StreamRequestHandler):
    server: "FakeImapServer"

    def send(self, line: str | bytes) -> None:
        data = line.encode("utf-8") if isinstance(line, str) else line
        self.wfile.write(data + b"\r\n")

    def handle(self) -> None:  # noqa: C901 - a protocol state machine
        box = self.server.mailbox
        self.selected: str | None = None
        self.read_only = True
        self.authenticated = False
        self.send("* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2 AUTH=PLAIN] Fake IMAP ready")
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            parts = line.split(" ", 2)
            if len(parts) < 2:
                continue
            tag, command = parts[0], parts[1].upper()
            rest = parts[2] if len(parts) > 2 else ""
            if command == "UID":
                sub, _, rest = rest.partition(" ")
                command = f"UID {sub.upper()}"
            masked = rest if command not in ("LOGIN", "AUTHENTICATE") else rest.split(" ")[0] + " ***"
            box.record(f"{command} {masked}".strip())

            if command == "CAPABILITY":
                self.send("* CAPABILITY IMAP4rev1 AUTH=XOAUTH2 AUTH=PLAIN")
                self.send(f"{tag} OK CAPABILITY completed")
            elif command == "NOOP":
                self.send(f"{tag} OK NOOP completed")
            elif command == "LOGIN":
                user, password = tokenize(rest)[:2]
                if box.passwords.get(user) == password:
                    self.authenticated = True
                    self.send(f"{tag} OK LOGIN completed")
                else:
                    self.send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)")
            elif command == "AUTHENTICATE":
                self.send("+ ")
                response = self.rfile.readline().strip()
                try:
                    decoded = base64.b64decode(response).decode("utf-8")
                except ValueError:
                    decoded = ""
                match = re.fullmatch(r"user=([^\x01]+)\x01auth=Bearer ([^\x01]+)\x01\x01", decoded)
                if match and box.oauth_tokens.get(match.group(1)) == match.group(2):
                    self.authenticated = True
                    self.send(f"{tag} OK AUTHENTICATE completed")
                else:
                    error = base64.b64encode(b'{"status":"401","schemes":"Bearer","scope":"https://mail.google.com/"}')
                    self.send(b"+ " + error)
                    self.rfile.readline()
                    self.send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)")
            elif command == "LOGOUT":
                self.send("* BYE Fake IMAP closing")
                self.send(f"{tag} OK LOGOUT completed")
                return
            elif not self.authenticated:
                self.send(f"{tag} NO not authenticated")
            elif command == "LIST":
                for name in box.folders:
                    self.send(f'* LIST (\\HasNoChildren) "/" "{name}"')
                self.send(f"{tag} OK LIST completed")
            elif command in ("EXAMINE", "SELECT"):
                name = tokenize(rest)[0]
                if name not in box.folders:
                    self.selected = None
                    self.send(f"{tag} NO [NONEXISTENT] Unknown folder")
                    continue
                self.selected = name
                self.read_only = command == "EXAMINE"
                msgs = box.folders[name]
                self.send("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
                self.send(f"* {len(msgs)} EXISTS")
                self.send("* 0 RECENT")
                self.send(f"* OK [UIDVALIDITY {box.uidvalidity.get(name, 1)}] UIDs valid")
                code = "[READ-ONLY] " if self.read_only and box.confirm_read_only else (
                    "" if self.read_only else "[READ-WRITE] ")
                self.send(f"{tag} OK {code}{command} completed")
            elif self.selected is None:
                self.send(f"{tag} BAD no mailbox selected")
            elif command == "UID SEARCH":
                tokens = tokenize(rest)
                msgs = box.folders[self.selected]
                if len(tokens) >= 2 and tokens[0].upper() == "SINCE":
                    day, mon, year = tokens[1].split("-")
                    since = datetime(int(year), MONTHS.index(mon) + 1, int(day), tzinfo=timezone.utc).date()
                    found = [m.uid for m in msgs if m.internaldate.astimezone(timezone.utc).date() >= since]
                else:
                    found = [m.uid for m in msgs]
                self.send("* SEARCH " + " ".join(str(u) for u in sorted(found)))
                self.send(f"{tag} OK SEARCH completed")
            elif command == "UID FETCH":
                self._fetch(tag, rest)
            elif command in ("UID STORE", "STORE"):
                if self.read_only:
                    self.send(f"{tag} NO mailbox is read-only")
                else:
                    self.send(f"{tag} OK STORE completed")
            elif command.replace("UID ", "") in WRITE_COMMANDS:
                self.send(f"{tag} OK {command} completed (recorded)")
            else:
                self.send(f"{tag} BAD unknown command")

    def _fetch(self, tag: str, rest: str) -> None:
        box = self.server.mailbox
        set_spec, _, items_spec = rest.partition(" ")
        msgs = box.folders[self.selected]
        wanted = parse_set(set_spec, [m.uid for m in msgs])
        items = split_fetch_items(items_spec)
        for seq, msg in enumerate(msgs, start=1):
            if msg.uid not in wanted:
                continue
            meta: list[str] = []
            literals: list[tuple[str, bytes]] = []
            for item in items:
                upper = item.upper()
                if upper == "UID":
                    continue
                if upper == "INTERNALDATE":
                    meta.append(f'INTERNALDATE "{internaldate(msg.internaldate)}"')
                elif upper == "RFC822.SIZE":
                    meta.append(f"RFC822.SIZE {len(msg.raw)}")
                elif upper == "FLAGS":
                    meta.append("FLAGS (" + " ".join(sorted(msg.flags)) + ")")
                elif upper.startswith(("BODY[", "BODY.PEEK[", "RFC822")):
                    peek = upper.startswith("BODY.PEEK[")
                    section = upper[upper.index("[") + 1 : upper.rindex("]")] if "[" in upper else ""
                    if section.startswith("HEADER.FIELDS"):
                        fields = section[section.index("(") + 1 : section.rindex(")")].split()
                        data = extract_header_fields(msg.raw, fields)
                    elif section == "HEADER":
                        data = re.split(rb"\r?\n\r?\n", msg.raw, maxsplit=1)[0] + b"\r\n\r\n"
                    else:
                        data = msg.raw
                    name = upper if upper.startswith("RFC822") else f"BODY[{section}]"
                    literals.append((name, data))
                    if not peek and not self.read_only and upper != "RFC822.HEADER":
                        msg.flags.add("\\Seen")
            uid_part = f"UID {msg.uid}"
            head = " ".join(([] if box.uid_after_literal else [uid_part]) + meta)
            if not literals:
                tail = f" {uid_part}" if box.uid_after_literal else ""
                self.send(f"* {seq} FETCH ({head}{tail})".replace("( ", "("))
                continue
            payload = f"* {seq} FETCH ({head}".replace("( ", "(").encode()
            for index, (name, data) in enumerate(literals):
                sep = b" " if (head or index) else b""
                payload += sep + f"{name} {{{len(data)}}}".encode() + b"\r\n" + data
            payload += (f" {uid_part}".encode() if box.uid_after_literal else b"") + b")"
            self.send(payload)
        self.send(f"{tag} OK FETCH completed")


class FakeImapServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, mailbox: FakeMailbox):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mailbox = mailbox
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    @property
    def port(self) -> int:
        return self.server_address[1]

    def start(self) -> "FakeImapServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
