"""Account management dialogs. Secrets go straight to the OS credential store."""

from __future__ import annotations

import logging
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from local_mail_cleaner import strings_pl as S
from local_mail_cleaner.credentials import (
    KIND_GOOGLE_CLIENT_SECRET,
    KIND_GOOGLE_REFRESH,
    KIND_PASSWORD,
    CredentialStoreUnavailable,
)
from local_mail_cleaner.models import Account
from local_mail_cleaner.oauth_google import ClientConfig, OAuthError, authorize_interactive, load_client_config
from local_mail_cleaner.providers import AUTH_OAUTH2, PROVIDERS, get_provider
from local_mail_cleaner.sanitize import redact
from local_mail_cleaner.ui.tasks import BackgroundTask

log = logging.getLogger(__name__)

_EMAIL = re.compile(r"^[^@\s\"<>]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
CREDENTIAL_NOTE = ("Hasła i tokeny są zapisywane wyłącznie w systemowym magazynie poświadczeń "
                   "(Windows: Menedżer poświadczeń), nigdy w plikach aplikacji ani w logach.")


def _modal(window: tk.Toplevel, master: tk.Misc, attempts: int = 20) -> None:
    """Make ``window`` modal without blocking (grab once it is actually mapped)."""
    window.transient(master)

    def grab(remaining: int) -> None:
        if not window.winfo_exists():
            return
        try:
            window.grab_set()
            window.focus_set()
        except tk.TclError:  # not viewable yet
            if remaining > 0:
                window.after(50, grab, remaining - 1)

    window.after(0, grab, attempts)


def has_credentials(ctx, account: Account) -> bool:
    kind = KIND_GOOGLE_REFRESH if get_provider(account.provider).auth == AUTH_OAUTH2 else KIND_PASSWORD
    return ctx.credentials.has(account.id, kind)


class AccountsDialog(tk.Toplevel):
    def __init__(self, master: tk.Misc, ctx, on_change):
        super().__init__(master)
        self.ctx = ctx
        self.on_change = on_change
        self.title("Konta pocztowe")
        self.resizable(True, False)
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(frame, height=8, width=90, activestyle="dotbox")
        self.listbox.grid(row=0, column=0, columnspan=4, sticky="nsew")
        self.listbox.bind("<Double-Button-1>", lambda e: self.edit())
        ttk.Button(frame, text="Dodaj…", command=self.add).grid(row=1, column=0, sticky="w", pady=8)
        ttk.Button(frame, text="Edytuj…", command=self.edit).grid(row=1, column=1, sticky="w", pady=8)
        ttk.Button(frame, text="Usuń…", command=self.delete).grid(row=1, column=2, sticky="w", pady=8)
        ttk.Button(frame, text="Zamknij", command=self.destroy).grid(row=1, column=3, sticky="e", pady=8)
        ttk.Label(frame, text=CREDENTIAL_NOTE, wraplength=640, foreground="#444").grid(
            row=2, column=0, columnspan=4, sticky="w")
        frame.columnconfigure(3, weight=1)
        self.accounts: list[Account] = []
        self.reload()
        _modal(self, master)

    def reload(self) -> None:
        self.accounts = self.ctx.accounts()
        self.listbox.delete(0, "end")
        for account in self.accounts:
            provider = PROVIDERS.get(account.provider)
            state = "dane logowania zapisane" if has_credentials(self.ctx, account) else "BRAK danych logowania"
            self.listbox.insert("end", f"{account.display_name}  —  {provider.label if provider else account.provider}"
                                       f"  —  {account.email}  —  {state}")

    def _changed(self) -> None:
        self.reload()
        self.on_change()

    def _selected(self) -> Account | None:
        selection = self.listbox.curselection()
        return self.accounts[selection[0]] if selection else None

    def add(self) -> None:
        AccountEditor(self, self.ctx, None, on_saved=self._changed)

    def edit(self) -> None:
        account = self._selected()
        if account is not None:
            AccountEditor(self, self.ctx, account, on_saved=self._changed)

    def delete(self) -> None:
        account = self._selected()
        if account is None:
            return
        if messagebox.askyesno(
            "Usuń konto",
            f"Usunąć konto „{account.display_name}” z aplikacji?\n\n"
            "Zostaną usunięte lokalne wyniki skanowania i zapisane w systemie dane logowania. "
            "Wiadomości w skrzynce NIE są zmieniane.",
            parent=self,
        ):
            self.ctx.delete_account(account.id)
            self._changed()


class AccountEditor(tk.Toplevel):
    def __init__(self, master: tk.Misc, ctx, account: Account | None, on_saved):
        super().__init__(master)
        self.ctx = ctx
        self.account = account
        self.on_saved = on_saved
        self.task: BackgroundTask | None = None
        self.pending_client: ClientConfig | None = None
        self.title("Edycja konta" if account else "Nowe konto")
        self.resizable(False, False)

        labels = {p.label: key for key, p in PROVIDERS.items()}
        self.provider_labels = labels
        initial = account or Account(provider="gmail", email="", host=PROVIDERS["gmail"].host,
                                     trusted_authserv_ids=list(PROVIDERS["gmail"].trusted_authserv_ids))
        self.provider_var = tk.StringVar(value=PROVIDERS[initial.provider].label)
        self.label_var = tk.StringVar(value=initial.label)
        self.email_var = tk.StringVar(value=initial.email)
        self.host_var = tk.StringVar(value=initial.host)
        self.port_var = tk.StringVar(value=str(initial.port))
        self.folders_var = tk.StringVar(value=", ".join(initial.folders))
        self.days_var = tk.StringVar(value=str(initial.scan_days))
        self.max_var = tk.StringVar(value=str(initial.max_messages))
        self.trusted_var = tk.StringVar(value=", ".join(initial.trusted_authserv_ids))
        self.password_var = tk.StringVar()
        self.client_status = tk.StringVar()
        self.token_status = tk.StringVar()
        self.password_status = tk.StringVar()
        self._last_provider = initial.provider

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)
        row = 0

        def add_row(label: str, widget: tk.Widget, note: str = "") -> None:
            nonlocal row
            ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=3, padx=(0, 8))
            widget.grid(row=row, column=1, sticky="ew", pady=3)
            if note:
                ttk.Label(body, text=note, foreground="#555", wraplength=260).grid(row=row, column=2, sticky="w", padx=8)
            row += 1

        provider_combo = ttk.Combobox(body, textvariable=self.provider_var, values=list(labels), state="readonly", width=34)
        provider_combo.bind("<<ComboboxSelected>>", lambda e: self._provider_changed())
        add_row("Dostawca:", provider_combo)
        add_row("Nazwa (opcjonalnie):", ttk.Entry(body, textvariable=self.label_var, width=36))
        add_row("Adres e-mail (login):", ttk.Entry(body, textvariable=self.email_var, width=36))
        self.host_combo = ttk.Combobox(body, textvariable=self.host_var, width=34)
        add_row("Serwer IMAP:", self.host_combo, "Sprawdź adres w pomocy dostawcy. Połączenie zawsze przez TLS.")
        add_row("Port:", ttk.Entry(body, textvariable=self.port_var, width=8), "IMAPS, zwykle 993.")
        folders_frame = ttk.Frame(body)
        ttk.Entry(folders_frame, textvariable=self.folders_var, width=28).pack(side="left", fill="x", expand=True)
        self.btn_folders = ttk.Button(folders_frame, text="Lista…", command=self.pick_folders)
        self.btn_folders.pack(side="left", padx=(4, 0))
        add_row("Foldery (po przecinku):", folders_frame, "Lista folderów jest pobierana tylko do odczytu (LIST).")
        add_row("Okres skanowania (dni):", ttk.Spinbox(body, from_=1, to=3650, textvariable=self.days_var, width=8))
        add_row("Maks. wiadomości na folder:", ttk.Spinbox(body, from_=100, to=100000, increment=500,
                                                             textvariable=self.max_var, width=8))
        add_row("Zaufane authserv-id:", ttk.Entry(body, textvariable=self.trusted_var, width=36),
                "Zaawansowane. Domyślnie tylko Gmail (mx.google.com). Puste = zawsze lokalna weryfikacja DKIM.")

        self.password_frame = ttk.LabelFrame(body, text="Hasło", padding=8)
        ttk.Label(self.password_frame, text="Hasło aplikacji (Yahoo) lub hasło skrzynki (IONOS):").grid(row=0, column=0, sticky="w")
        self.password_entry = ttk.Entry(self.password_frame, textvariable=self.password_var, show="•", width=34)
        self.password_entry.grid(row=1, column=0, sticky="w", pady=4)
        ttk.Label(self.password_frame, text="Pozostaw puste, aby nie zmieniać zapisanego hasła.",
                  foreground="#555").grid(row=2, column=0, sticky="w")
        ttk.Label(self.password_frame, textvariable=self.password_status).grid(row=3, column=0, sticky="w")

        self.oauth_frame = ttk.LabelFrame(body, text="Logowanie Google (OAuth)", padding=8)
        ttk.Button(self.oauth_frame, text="Wczytaj plik klienta OAuth (JSON)…",
                   command=self.load_client).grid(row=0, column=0, sticky="w")
        ttk.Label(self.oauth_frame, textvariable=self.client_status).grid(row=0, column=1, sticky="w", padx=8)
        self.btn_google = ttk.Button(self.oauth_frame, text="Zaloguj przez Google…", command=self.google_sign_in)
        self.btn_google.grid(row=1, column=0, sticky="w", pady=6)
        ttk.Label(self.oauth_frame, textvariable=self.token_status).grid(row=1, column=1, sticky="w", padx=8)
        ttk.Label(self.oauth_frame, wraplength=520, foreground="#555", text=(
            "Logowanie odbywa się w przeglądarce na stronie Google. Aplikacja na chwilę nasłuchuje tylko na "
            "127.0.0.1 (lokalnie), aby odebrać kod. Wymagany jest własny klient OAuth typu „Desktop app” "
            "— zobacz docs/SZYBKI_START.md.")).grid(row=2, column=0, columnspan=2, sticky="w")

        self.auth_row = row
        row += 1
        ttk.Label(body, text=CREDENTIAL_NOTE, wraplength=560, foreground="#444").grid(
            row=row, column=0, columnspan=3, sticky="w", pady=(8, 0))
        row += 1
        buttons = ttk.Frame(body)
        buttons.grid(row=row, column=0, columnspan=3, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Zapisz", command=self.save).pack(side="left", padx=4)
        ttk.Button(buttons, text="Anuluj", command=self.close).pack(side="left")
        body.columnconfigure(1, weight=1)

        self.protocol("WM_DELETE_WINDOW", self.close)
        self._provider_changed(initial=True)
        _modal(self, master)

    # ---------------------------------------------------------------- state

    @property
    def provider_key(self) -> str:
        return self.provider_labels[self.provider_var.get()]

    def _provider_changed(self, initial: bool = False) -> None:
        preset = get_provider(self.provider_key)
        if not initial and self.provider_key != self._last_provider:
            self.host_var.set(preset.host)
            self.port_var.set(str(preset.port))
            self.trusted_var.set(", ".join(preset.trusted_authserv_ids))
        self._last_provider = self.provider_key
        self.host_combo.configure(values=list(preset.host_choices or (preset.host,)))
        self.password_frame.grid_forget()
        self.oauth_frame.grid_forget()
        frame = self.oauth_frame if preset.auth == AUTH_OAUTH2 else self.password_frame
        frame.grid(row=self.auth_row, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self._refresh_status()

    def _refresh_status(self) -> None:
        account_id = self.account.id if self.account else None
        stored = lambda kind: bool(account_id) and self.ctx.credentials.has(account_id, kind)  # noqa: E731
        self.password_status.set("Hasło zapisane w systemie: " + ("tak" if stored(KIND_PASSWORD) else "nie"))
        if self.pending_client is not None:
            self.client_status.set("wczytano (zostanie zapisany po kliknięciu Zapisz)")
        elif self.account and self.account.oauth_client_id and stored(KIND_GOOGLE_CLIENT_SECRET):
            self.client_status.set("klient zapisany")
        else:
            self.client_status.set("brak klienta OAuth")
        self.token_status.set("zalogowano ✓" if stored(KIND_GOOGLE_REFRESH) else "nie zalogowano")

    def _collect(self) -> Account:
        email = self.email_var.get().strip()
        host = self.host_var.get().strip().lower()
        if not _EMAIL.match(email):
            raise ValueError("Podaj poprawny adres e-mail.")
        if not _HOST.match(host) or "." not in host:
            raise ValueError("Podaj poprawną nazwę serwera IMAP (bez https:// i bez portu).")
        try:
            port = int(self.port_var.get())
            days = int(self.days_var.get())
            max_messages = int(self.max_var.get())
        except ValueError:
            raise ValueError("Port, okres i limit muszą być liczbami.") from None
        if not 1 <= port <= 65535 or not 1 <= days <= 3650 or not 100 <= max_messages <= 100000:
            raise ValueError("Port 1–65535, okres 1–3650 dni, limit 100–100000 wiadomości.")
        folders = [f.strip() for f in self.folders_var.get().split(",") if f.strip()]
        if not folders or any(re.search(r"[\r\n\x00]", f) for f in folders):
            raise ValueError("Podaj co najmniej jeden folder (np. INBOX).")
        trusted = [t.strip().lower() for t in self.trusted_var.get().split(",") if t.strip()]
        if any(not _HOST.match(t) for t in trusted):
            raise ValueError("Zaufane authserv-id muszą być nazwami hostów.")
        account = Account(
            id=self.account.id if self.account else None,
            provider=self.provider_key, email=email, label=self.label_var.get().strip()[:80], host=host,
            port=port, folders=folders, scan_days=days, max_messages=max_messages,
            oauth_client_id=(self.pending_client.client_id if self.pending_client
                             else (self.account.oauth_client_id if self.account else "")),
            trusted_authserv_ids=trusted,
        )
        return account

    def _persist(self) -> Account:
        """Validate, save the account row and any newly entered secrets."""
        account = self._collect()
        with self.ctx.storage() as storage:
            storage.save_account(account)
        self.account = account
        password = self.password_var.get()
        if password and get_provider(account.provider).auth != AUTH_OAUTH2:
            self.ctx.credentials.set(account.id, KIND_PASSWORD, password)
        self.password_var.set("")
        if self.pending_client is not None:
            self.ctx.credentials.set(account.id, KIND_GOOGLE_CLIENT_SECRET, self.pending_client.client_secret)
            self.pending_client = None
        self.on_saved()
        self._refresh_status()
        return account

    def _try_persist(self) -> Account | None:
        try:
            return self._persist()
        except ValueError as exc:
            messagebox.showerror("Nieprawidłowe dane", str(exc), parent=self)
        except CredentialStoreUnavailable as exc:
            messagebox.showerror(
                "Magazyn poświadczeń",
                "Systemowy magazyn poświadczeń jest niedostępny, więc dane logowania nie zostały zapisane.\n\n"
                + redact(str(exc)), parent=self)
        return None

    # -------------------------------------------------------------- actions

    def save(self) -> None:
        if self._try_persist() is not None:
            self.close()

    def close(self) -> None:
        if self.task is not None:
            self.task.cancel.set()
        self.password_var.set("")
        self.destroy()

    def load_client(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Plik klienta OAuth (client_secret_*.json)",
                                          filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            self.pending_client = load_client_config(path)
        except OAuthError as exc:
            messagebox.showerror("Klient OAuth", S.error_text(exc.kind) + "\n\n" + str(exc), parent=self)
            return
        self._refresh_status()
        messagebox.showinfo(
            "Klient OAuth",
            "Wczytano klienta OAuth. Po zapisaniu konta plik JSON nie jest już potrzebny "
            "(sekret klienta trafia do systemowego magazynu poświadczeń).",
            parent=self,
        )

    def google_sign_in(self) -> None:
        if self.task is not None:
            return
        account = self._try_persist()
        if account is None:
            return
        secret = self.ctx.credentials.get(account.id, KIND_GOOGLE_CLIENT_SECRET)
        if not account.oauth_client_id or not secret:
            messagebox.showinfo("Google", "Najpierw wczytaj plik klienta OAuth (JSON).", parent=self)
            return
        client = ClientConfig(account.oauth_client_id, secret)
        self.btn_google.configure(state="disabled")
        self.token_status.set("czekam na logowanie w przeglądarce… (Anuluj zamyka okno)")

        def work(progress, cancel):
            return authorize_interactive(client, account.email, cancel_event=cancel,
                                         http_post=self.ctx.oauth_http_post)

        self.task = BackgroundTask(self, work, on_done=self._signed_in, on_error=self._sign_in_failed)

    def _signed_in(self, tokens) -> None:
        self.task = None
        self.btn_google.configure(state="normal")
        try:
            self.ctx.credentials.set(self.account.id, KIND_GOOGLE_REFRESH, tokens.refresh_token)
        except CredentialStoreUnavailable as exc:
            messagebox.showerror("Magazyn poświadczeń", redact(str(exc)), parent=self)
            return
        self.ctx.token_cache.forget(self.account.id)
        self._refresh_status()
        self.on_saved()

    def _sign_in_failed(self, exc: BaseException) -> None:
        self.task = None
        self.btn_google.configure(state="normal")
        self._refresh_status()
        kind = getattr(exc, "kind", "internal")
        if kind != "cancelled":
            messagebox.showerror("Google", S.error_text(kind), parent=self)

    def pick_folders(self) -> None:
        if self.task is not None:
            return
        account = self._try_persist()
        if account is None:
            return

        def work(progress, cancel):
            session = self.ctx.open_session(account)
            try:
                return [f.name for f in session.list_folders() if f.selectable]
            finally:
                session.logout()

        self.btn_folders.configure(state="disabled")
        self.task = BackgroundTask(self, work, on_done=self._show_folders, on_error=self._folders_failed)

    def _show_folders(self, names: list[str]) -> None:
        self.task = None
        self.btn_folders.configure(state="normal")
        FolderPicker(self, names, [f.strip() for f in self.folders_var.get().split(",") if f.strip()],
                     on_ok=lambda chosen: self.folders_var.set(", ".join(chosen)))

    def _folders_failed(self, exc: BaseException) -> None:
        self.task = None
        self.btn_folders.configure(state="normal")
        messagebox.showerror("Foldery", S.error_text(getattr(exc, "kind", "internal")), parent=self)


class FolderPicker(tk.Toplevel):
    def __init__(self, master: tk.Misc, names: list[str], current: list[str], on_ok):
        super().__init__(master)
        self.title("Wybierz foldery")
        self.names = names
        self.on_ok = on_ok
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Zaznacz foldery do skanowania (Ctrl+klik = wiele):").pack(anchor="w")
        self.listbox = tk.Listbox(frame, selectmode="extended", height=14, width=50)
        self.listbox.pack(fill="both", expand=True, pady=6)
        for index, name in enumerate(names):
            self.listbox.insert("end", name)
            if name in current:
                self.listbox.selection_set(index)
        buttons = ttk.Frame(frame)
        buttons.pack(anchor="e")
        ttk.Button(buttons, text="OK", command=self.ok).pack(side="left", padx=4)
        ttk.Button(buttons, text="Anuluj", command=self.destroy).pack(side="left")
        _modal(self, master)

    def ok(self) -> None:
        chosen = [self.names[i] for i in self.listbox.curselection()]
        if chosen:
            self.on_ok(chosen)
        self.destroy()
