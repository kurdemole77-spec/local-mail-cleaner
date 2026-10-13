"""Main window: read-only subscription table."""

from __future__ import annotations

import logging
import os
import sys
import tkinter as tk
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from local_mail_cleaner import STAGE, __version__
from local_mail_cleaner import strings_pl as S
from local_mail_cleaner.diagnostics import build_report
from local_mail_cleaner.export import export_csv
from local_mail_cleaner.models import CheckStatus, Subscription, UnsubMethod, Verification
from local_mail_cleaner.paths import project_root
from local_mail_cleaner.sanitize import redact
from local_mail_cleaner.ui.tasks import BackgroundTask

log = logging.getLogger(__name__)

COLUMN_IDS = ("sel", "mailbox", "sender", "list", "count", "latest", "method", "verification")
COLUMN_WIDTHS = {"sel": 34, "mailbox": 130, "sender": 260, "list": 200, "count": 90, "latest": 95,
                 "method": 230, "verification": 200}
ALL = "Wszystkie"
CHECKED, UNCHECKED = "☑", "☐"

ROW_TAGS = {
    Verification.VERIFIED_LOCAL: "verified",
    Verification.VERIFIED_PROVIDER: "verified",
    Verification.MANUAL_REVIEW: "manual",
    Verification.NOT_APPLICABLE: "na",
}


def _date(value: datetime | None) -> str:
    return value.astimezone().strftime("%Y-%m-%d") if value else "—"


def open_path(path: Path) -> None:
    """Open a local file or folder with the system's default application."""
    if sys.platform == "win32":
        os.startfile(str(path))  # noqa: S606 - local path chosen by the application
    else:
        webbrowser.open(path.resolve().as_uri())


class MainWindow:
    def __init__(self, root: tk.Tk, ctx):
        self.root = root
        self.ctx = ctx
        self.subs: dict[str, Subscription] = {}
        self.checked: set[str] = set()
        self.sort_column = "mailbox"
        self.sort_reverse = False
        self.task: BackgroundTask | None = None

        root.title(S.APP_TITLE + ("  [DEMO]" if ctx.demo else ""))
        root.geometry("1280x760")
        root.minsize(940, 560)
        root.report_callback_exception = self._report_exception
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.filter_var = tk.StringVar()
        self.mailbox_var = tk.StringVar(value=ALL)
        self.verification_var = tk.StringVar(value=ALL)
        self.status_var = tk.StringVar(value="Gotowe.")
        self.count_var = tk.StringVar(value="")

        self._build_menu()
        self._build_banner()
        self._build_toolbar()
        self._build_filters()
        self._build_status()  # packed before the expanding body so it is never squeezed out
        self._build_body()
        self.filter_var.trace_add("write", lambda *_: self.populate())
        self.refresh()

    # ------------------------------------------------------------------ layout

    def _build_menu(self) -> None:
        menu = tk.Menu(self.root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Eksportuj tabelę do CSV…", command=self.export)
        file_menu.add_separator()
        file_menu.add_command(label="Zakończ", command=self.on_close)
        menu.add_cascade(label="Plik", menu=file_menu)

        data_menu = tk.Menu(menu, tearoff=False)
        data_menu.add_command(label="Konta pocztowe…", command=self.open_accounts)
        data_menu.add_command(label="Usuń lokalne wyniki skanowania…", command=self.clear_results)
        menu.add_cascade(label="Dane", menu=data_menu)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Szybki start (PL)", command=self.open_quick_start)
        help_menu.add_command(label="Otwórz folder danych i logów", command=self.open_data_dir)
        help_menu.add_command(label="Zapisz raport diagnostyczny…", command=self.save_diagnostics)
        help_menu.add_separator()
        help_menu.add_command(label="O programie", command=self.about)
        menu.add_cascade(label="Pomoc", menu=help_menu)
        self.root.config(menu=menu)

    def _build_banner(self) -> None:
        text = S.READ_ONLY_BANNER + ("\n" + S.DEMO_BANNER if self.ctx.demo else "")
        banner = tk.Label(self.root, text=text, bg="#fff4ce", fg="#5c4400", anchor="w", justify="left",
                          padx=10, pady=6, wraplength=1200)
        banner.pack(fill="x")

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 6))
        bar.pack(fill="x")
        self.btn_accounts = ttk.Button(bar, text="Konta…", command=self.open_accounts)
        self.btn_scan = ttk.Button(bar, text="Skanuj (tylko odczyt)", command=self.start_scan)
        self.btn_verify = ttk.Button(bar, text="Weryfikuj DKIM zaznaczonych…", command=self.start_verify)
        self.btn_cancel = ttk.Button(bar, text="Anuluj", command=self.cancel_task, state="disabled")
        for widget in (self.btn_accounts, self.btn_scan, self.btn_verify, self.btn_cancel):
            widget.pack(side="left", padx=(0, 6))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        # Later stages. Disabled: stage A contains no code that performs these actions.
        self.btn_unsubscribe = ttk.Button(bar, text="Wypisz… (etap B)", state="disabled")
        self.btn_quarantine = ttk.Button(bar, text="Kwarantanna… (etap C)", state="disabled")
        self.btn_unsubscribe.pack(side="left", padx=(0, 6))
        self.btn_quarantine.pack(side="left")

    def _build_filters(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 0, 8, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="Szukaj:").pack(side="left")
        ttk.Entry(bar, textvariable=self.filter_var, width=28).pack(side="left", padx=(4, 12))
        ttk.Label(bar, text="Skrzynka:").pack(side="left")
        self.mailbox_combo = ttk.Combobox(bar, textvariable=self.mailbox_var, state="readonly", width=22)
        self.mailbox_combo.pack(side="left", padx=(4, 12))
        self.mailbox_combo.bind("<<ComboboxSelected>>", lambda e: self.populate())
        ttk.Label(bar, text="Weryfikacja:").pack(side="left")
        self.verification_combo = ttk.Combobox(
            bar, textvariable=self.verification_var, state="readonly", width=28,
            values=[ALL] + list(S.VERIFICATION.values()),
        )
        self.verification_combo.pack(side="left", padx=(4, 12))
        self.verification_combo.bind("<<ComboboxSelected>>", lambda e: self.populate())
        ttk.Button(bar, text="Zaznacz widoczne", command=self.check_visible).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Odznacz", command=self.uncheck_all).pack(side="left", padx=(0, 12))
        ttk.Label(bar, textvariable=self.count_var).pack(side="left")

    def _build_body(self) -> None:
        paned = ttk.Panedwindow(self.root, orient="vertical")
        paned.pack(fill="both", expand=True, padx=8)

        table_frame = ttk.Frame(paned)
        self.tree = ttk.Treeview(table_frame, columns=COLUMN_IDS, show="headings", selectmode="extended")
        for col in COLUMN_IDS:
            self.tree.heading(col, text=S.COLUMNS[col], command=lambda c=col: self.sort_by(c))
            anchor = "center" if col in ("sel", "count", "latest") else "w"
            self.tree.column(col, width=COLUMN_WIDTHS[col], anchor=anchor, stretch=col not in ("sel", "count"))
        self.tree.tag_configure("verified", background="#e6f4ea")
        self.tree.tag_configure("manual", background="#fff4e5")
        self.tree.tag_configure("unsafe", background="#fde8e8")
        self.tree.tag_configure("na", background="#f1f3f4")
        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<space>", lambda e: self.toggle_selected())
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_details())
        paned.add(table_frame, weight=4)

        details_frame = ttk.LabelFrame(paned, text="Szczegóły", padding=6)
        self.details = tk.Text(details_frame, height=11, wrap="word", relief="flat", state="disabled")
        dscroll = ttk.Scrollbar(details_frame, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=dscroll.set)
        self.details.pack(side="left", fill="both", expand=True)
        dscroll.pack(side="right", fill="y")
        paned.add(details_frame, weight=1)

    def _build_status(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 4))
        bar.pack(fill="x", side="bottom")
        self.progress = ttk.Progressbar(bar, mode="determinate", length=220)
        self.progress.pack(side="right")
        ttk.Label(bar, textvariable=self.status_var, anchor="w").pack(side="left", fill="x", expand=True)

    # ------------------------------------------------------------------- data

    @staticmethod
    def _iid(sub: Subscription) -> str:
        return f"{sub.account_id}|{sub.key}"

    def refresh(self) -> None:
        subscriptions = self.ctx.subscriptions()
        self.subs = {self._iid(s): s for s in subscriptions}
        self.checked &= set(self.subs)
        names = sorted({s.account_name for s in subscriptions} | {a.display_name for a in self.ctx.accounts()})
        self.mailbox_combo.configure(values=[ALL] + names)
        if self.mailbox_var.get() not in [ALL] + names:
            self.mailbox_var.set(ALL)
        self.populate()

    def _visible(self) -> list[Subscription]:
        needle = self.filter_var.get().strip().lower()
        mailbox = self.mailbox_var.get()
        verification = self.verification_var.get()
        result = []
        for sub in self.subs.values():
            if mailbox != ALL and sub.account_name != mailbox:
                continue
            if verification != ALL and S.VERIFICATION[sub.verification.value] != verification:
                continue
            haystack = " ".join((sub.account_name, sub.sender_name, sub.sender_addr, sub.list_id,
                                 sub.list_desc, sub.latest_subject)).lower()
            if needle and needle not in haystack:
                continue
            result.append(sub)
        return sorted(result, key=self._sort_key, reverse=self.sort_reverse)

    def _sort_key(self, sub: Subscription):
        column = self.sort_column
        if column == "count":
            return (sub.message_count,)
        if column == "latest":
            return (sub.latest_date or datetime.min.replace(tzinfo=timezone.utc),)
        if column == "sel":
            return (self._iid(sub) not in self.checked,)
        return (self._values(sub)[COLUMN_IDS.index(column)].lower(), sub.sender_addr)

    def _values(self, sub: Subscription) -> tuple[str, ...]:
        sender = f"{sub.sender_name} <{sub.sender_addr}>" if sub.sender_name else sub.sender_addr
        method = S.METHODS[sub.method.value] + (" + mailto" if sub.has_mailto else "")
        return (
            CHECKED if self._iid(sub) in self.checked else UNCHECKED,
            sub.account_name,
            sender,
            sub.list_id or "—",
            str(sub.message_count),
            _date(sub.latest_date),
            method,
            S.VERIFICATION[sub.verification.value],
        )

    def populate(self) -> None:
        focus = self.tree.focus()
        self.tree.delete(*self.tree.get_children())
        visible = self._visible()
        for sub in visible:
            tag = "unsafe" if sub.method == UnsubMethod.UNSAFE else ROW_TAGS[sub.verification]
            self.tree.insert("", "end", iid=self._iid(sub), values=self._values(sub), tags=(tag,))
        if focus and self.tree.exists(focus):
            self.tree.focus(focus)
            self.tree.selection_set(focus)
        self.count_var.set(f"Widoczne: {len(visible)} / {len(self.subs)}   Zaznaczone: {len(self.checked)}")
        self.show_details()

    def sort_by(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column, self.sort_reverse = column, column in ("count", "latest")
        self.populate()

    # -------------------------------------------------------------- selection

    def _on_click(self, event) -> str | None:
        if self.tree.identify_region(event.x, event.y) == "cell" and self.tree.identify_column(event.x) == "#1":
            iid = self.tree.identify_row(event.y)
            if iid:
                self.toggle(iid)
                return "break"
        return None

    def toggle(self, iid: str) -> None:
        if iid in self.checked:
            self.checked.discard(iid)
        else:
            self.checked.add(iid)
        if self.tree.exists(iid):
            self.tree.set(iid, "sel", CHECKED if iid in self.checked else UNCHECKED)
        self.count_var.set(f"Widoczne: {len(self.tree.get_children())} / {len(self.subs)}   "
                           f"Zaznaczone: {len(self.checked)}")

    def toggle_selected(self) -> None:
        for iid in self.tree.selection():
            self.toggle(iid)

    def check_visible(self) -> None:
        self.checked |= set(self.tree.get_children())
        self.populate()

    def uncheck_all(self) -> None:
        self.checked.clear()
        self.populate()

    def checked_subscriptions(self) -> list[Subscription]:
        iids = self.checked or set(self.tree.selection())
        return [self.subs[i] for i in iids if i in self.subs]

    # ---------------------------------------------------------------- details

    def show_details(self) -> None:
        iid = self.tree.focus() or (self.tree.selection()[0] if self.tree.selection() else "")
        sub = self.subs.get(iid)
        lines: list[str] = []
        if sub is None:
            lines.append("Wybierz wiersz, aby zobaczyć szczegóły. Kliknij kolumnę ✓ "
                         "(lub naciśnij spację), aby zaznaczyć subskrypcję.")
        else:
            sender = f"{sub.sender_name} <{sub.sender_addr}>" if sub.sender_name else sub.sender_addr
            lines += [
                f"Nadawca: {sender}",
                f"Skrzynka: {sub.account_name}",
                f"Lista (List-ID): {sub.list_id or 'brak'}" + (f"  —  {sub.list_desc}" if sub.list_desc else ""),
                f"Wiadomości: {sub.message_count}, ostatnia: {_date(sub.latest_date)}",
                f"Ostatni temat: {sub.latest_subject or '—'}",
                f"Metoda wypisania: {S.METHODS[sub.method.value]}" + (" (dostępny też mailto)" if sub.has_mailto else ""),
            ]
            if sub.targets:
                lines.append("Adresy wypisania (pokazywane są tylko serwery, pełne adresy nie są wyświetlane):")
                for target in sub.targets:
                    problems = ", ".join(S.reason_text(p) for p in target["problems"])
                    lines.append(f"   • {target['scheme']} → {target['host'] or '?'}"
                                 + (f"  [{problems}]" if problems else ""))
            lines.append(f"Weryfikacja: {S.VERIFICATION[sub.verification.value]}")
            for reason in sub.reasons:
                lines.append(f"   • {S.reason_text(reason)}")
            local = S.LOCAL_STATUS[sub.local_status.value]
            when = f" ({sub.local_checked_at})" if sub.local_checked_at else ""
            lines.append(f"Lokalna weryfikacja DKIM najnowszej wiadomości: {local}{when}")
            if sub.verification == Verification.MANUAL_REVIEW and sub.local_status == CheckStatus.NOT_RUN:
                lines.append("Wskazówka: zaznacz wiersz i użyj „Weryfikuj DKIM zaznaczonych…”.")
            lines.append("")
            lines.append(f"Etap {STAGE}: aplikacja tylko wyświetla informacje. Wypisywanie (etap B) i "
                         "kwarantanna (etap C) nie są jeszcze dostępne.")
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state="disabled")

    # ------------------------------------------------------------ operations

    def _set_busy(self, busy: bool, message: str = "") -> None:
        state = "disabled" if busy else "normal"
        for button in (self.btn_scan, self.btn_verify, self.btn_accounts):
            button.configure(state=state)
        self.btn_cancel.configure(state="normal" if busy else "disabled")
        if message:
            self.status_var.set(message)
        if not busy:
            self.progress.configure(value=0)

    def _on_progress(self, progress) -> None:
        stage = {"connecting": "łączenie", "searching": "wyszukiwanie", "fetching": "pobieranie nagłówków",
                 "saving": "zapisywanie", "verifying": "weryfikacja DKIM", "done": "zakończono"}.get(progress.stage, progress.stage)
        where = " / ".join(x for x in (progress.account, progress.folder) if x)
        counter = f" {progress.done}/{progress.total}" if progress.total else ""
        self.status_var.set(f"{where}: {stage}{counter}")
        if progress.total:
            self.progress.configure(maximum=progress.total, value=progress.done)

    def _task_error(self, exc: BaseException) -> None:
        self.task = None
        self._set_busy(False, "Błąd.")
        kind = getattr(exc, "kind", "internal")
        messagebox.showerror("Błąd", S.error_text(kind) + "\n\n" + redact(str(exc))[:300], parent=self.root)
        self.refresh()

    def start_scan(self) -> None:
        if self.task is not None:
            return
        if not self.ctx.accounts():
            messagebox.showinfo("Skanowanie", "Najpierw dodaj konto pocztowe (przycisk „Konta…”).",
                                parent=self.root)
            return
        self._set_busy(True, "Skanowanie (tylko odczyt)…")
        self.task = BackgroundTask(
            self.root,
            lambda progress, cancel: self.ctx.scan(progress=progress, cancel=cancel),
            on_done=self._scan_done, on_error=self._task_error, on_progress=self._on_progress,
        )

    def _scan_done(self, results) -> None:
        self.task = None
        self._set_busy(False)
        self.refresh()
        problems = []
        for result in results:
            if result.status == "error":
                problems.append(f"{result.account}: {S.error_text(result.error_kind)}")
            elif result.skipped_folders:
                problems.append(f"{result.account}: pominięto foldery: {', '.join(result.skipped_folders)}")
        cancelled = any(r.status == "cancelled" for r in results)
        self.status_var.set(("Skanowanie anulowane. " if cancelled else "Skanowanie zakończone. ")
                            + f"Subskrypcje: {len(self.subs)}.")
        if problems:
            messagebox.showwarning("Skanowanie", "\n".join(problems), parent=self.root)

    def start_verify(self) -> None:
        if self.task is not None:
            return
        subs = [s for s in self.checked_subscriptions() if s.method != UnsubMethod.NONE]
        if not subs:
            messagebox.showinfo("Weryfikacja DKIM", "Zaznacz co najmniej jedną subskrypcję z nagłówkiem List-Unsubscribe.",
                                parent=self.root)
            return
        confirm = messagebox.askyesno(
            "Lokalna weryfikacja DKIM",
            f"Dla {len(subs)} subskrypcji aplikacja pobierze pełną treść NAJNOWSZEJ wiadomości "
            "w trybie tylko do odczytu (EXAMINE + BODY.PEEK — wiadomość nie zostanie oznaczona jako przeczytana) "
            "i sprawdzi podpis DKIM, pobierając klucze publiczne z DNS.\n\n"
            "Nic nie zostanie wysłane do nadawców ani zmienione w skrzynce. Kontynuować?",
            parent=self.root,
        )
        if not confirm:
            return
        self._set_busy(True, "Weryfikacja DKIM…")
        self.task = BackgroundTask(
            self.root,
            lambda progress, cancel: self.ctx.verify(subs, progress=progress, cancel=cancel),
            on_done=self._verify_done, on_error=self._task_error, on_progress=self._on_progress,
        )

    def _verify_done(self, results) -> None:
        self.task = None
        self._set_busy(False)
        self.refresh()
        passed = sum(1 for r in results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
        errors = sorted({r.error_kind for r in results if r.error_kind})
        text = f"Zgodne: {passed}, niepotwierdzone: {failed}."
        if errors:
            text += "\nBłędy: " + "; ".join(S.error_text(e) for e in errors)
        self.status_var.set("Weryfikacja zakończona. " + text.replace("\n", " "))
        messagebox.showinfo("Weryfikacja DKIM", text, parent=self.root)

    def cancel_task(self) -> None:
        if self.task is not None:
            self.task.cancel.set()
            self.status_var.set("Anulowanie…")

    # ------------------------------------------------------------- dialogs

    def open_accounts(self) -> None:
        if self.ctx.demo:
            messagebox.showinfo("Konta", "W trybie demo konta są syntetyczne i nie można ich edytować.",
                                parent=self.root)
            return
        from local_mail_cleaner.ui.accounts_dialog import AccountsDialog

        AccountsDialog(self.root, self.ctx, on_change=self.refresh)

    def export(self) -> None:
        visible = self._visible()
        if not visible:
            messagebox.showinfo("Eksport", "Tabela jest pusta.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")], initialfile="subskrypcje.csv")
        if not path:
            return
        count = export_csv(path, visible)
        self.status_var.set(f"Zapisano {count} wierszy do pliku CSV.")

    def clear_results(self) -> None:
        if not messagebox.askyesno(
            "Usuń wyniki",
            "Usunąć lokalne wyniki skanowania z bazy aplikacji?\n\n"
            "Konta i zapisane dane logowania pozostaną. Wiadomości w skrzynkach nie są zmieniane.",
            parent=self.root,
        ):
            return
        with self.ctx.storage() as storage:
            storage.delete_all_scan_data()
        self.refresh()

    def open_quick_start(self) -> None:
        path = project_root() / "docs" / "SZYBKI_START.md"
        if path.exists():
            open_path(path)
        else:
            messagebox.showinfo("Szybki start", "Nie znaleziono pliku docs/SZYBKI_START.md.", parent=self.root)

    def open_data_dir(self) -> None:
        open_path(self.ctx.base_dir)

    def save_diagnostics(self) -> None:
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension=".txt",
                                            filetypes=[("Tekst", "*.txt")], initialfile="lmc_diagnostyka.txt")
        if not path:
            return
        with self.ctx.storage() as storage:
            report = build_report(self.ctx.base_dir, self.ctx.log_path, storage, self.ctx.credentials)
        Path(path).write_text(report, encoding="utf-8")
        messagebox.showinfo("Raport diagnostyczny",
                            "Zapisano raport. Nie zawiera haseł, tokenów, adresów e-mail ani pełnych adresów URL.",
                            parent=self.root)

    def about(self) -> None:
        messagebox.showinfo(
            "O programie",
            f"Local Mail Cleaner {__version__}\nEtap {STAGE}: skaner tylko do odczytu.\n\n"
            "Działa lokalnie. Bez telemetrii, bez chmury, bez modeli językowych.",
            parent=self.root,
        )

    def on_close(self) -> None:
        if self.task is not None:
            self.task.cancel.set()
        self.root.destroy()

    def _report_exception(self, exc_type, exc, tb) -> None:
        log.error("Unhandled exception in the user interface", exc_info=(exc_type, exc, tb))
        messagebox.showerror("Błąd", S.error_text("internal"), parent=self.root)
