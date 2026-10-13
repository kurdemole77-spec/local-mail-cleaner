# Local Mail Cleaner — szybki start (etap A)

Local Mail Cleaner to mała aplikacja na komputer z Windows. Przegląda Twoje
skrzynki Gmail, Yahoo i IONOS i pokazuje w tabeli, jakie newslettery
prenumerujesz.

## Co robi etap A, a czego nie robi

Etap A **tylko czyta**:

- otwiera foldery w trybie tylko do odczytu (polecenie IMAP `EXAMINE`); jeśli
  serwer nie potwierdzi tego trybu, skanowanie się zatrzymuje;
- pobiera wyłącznie wybrane nagłówki (`BODY.PEEK`), więc **wiadomości nie są
  oznaczane jako przeczytane**;
- grupuje wiadomości w subskrypcje i pokazuje: skrzynkę, nadawcę, listę
  (List-ID), liczbę wiadomości, datę ostatniej, metodę wypisania i status
  weryfikacji.

Etap A **nie** wypisuje z newsletterów, nie wysyła e-maili, nie przenosi i nie
usuwa wiadomości. Przyciski „Wypisz… (etap B)” i „Kwarantanna… (etap C)” są
celowo nieaktywne.

> Aplikacja nie była jeszcze testowana na prawdziwych skrzynkach ani na
> Windows. Testy automatyczne używają wyłącznie wymyślonych wiadomości.
> Szczegóły: `PROJECT_STATUS.md`.

## 1. Wymagania

- Windows 10 lub 11.
- Python 3.10 lub nowszy ze strony https://www.python.org/downloads/windows/
  W instalatorze zaznacz **„Add python.exe to PATH”**. Opcja **„tcl/tk and
  IDLE”** musi zostać zaznaczona (w instalacji domyślnej jest).
- Połączenie z internetem przy pierwszym uruchomieniu (instalacja bibliotek).

## 2. Pierwsze uruchomienie

1. Rozpakuj (lub sklonuj) folder aplikacji, np. do `C:\Programy\local-mail-cleaner`.
2. Kliknij dwukrotnie **`start_windows.bat`**.
   Jeśli Windows wyświetli ostrzeżenie o pliku pobranym z internetu, upewnij
   się, że plik pochodzi z Twojego repozytorium, i wybierz „Uruchom”.
3. Przy pierwszym uruchomieniu skrypt:
   - znajduje Pythona 3.10+,
   - tworzy folder `.venv` obok skryptu,
   - instaluje przypięte wersje bibliotek (`dkimpy`, `dnspython`, `keyring`)
     i sprawdza sumę SHA-256 każdego pobranego pliku,
   - uruchamia aplikację.
4. Kolejne uruchomienia od razu otwierają aplikację.

Opcje skryptu (np. `start_windows.bat --demo` w wierszu poleceń):

| Opcja | Działanie |
|---|---|
| `--demo` | dane syntetyczne, bez łączenia ze skrzynkami |
| `--console` | zostawia okno konsoli z logiem (zanonimizowanym) |
| `--check` | sprawdza Pythona, Tkinter, biblioteki i magazyn haseł |
| `--diagnostics` | wypisuje zanonimizowany raport diagnostyczny |
| `--reinstall` | instaluje biblioteki od nowa |

### Instalacja ręczna (gdyby skrypt nie zadziałał)

W wierszu poleceń, w folderze aplikacji:

```
py -3 -m venv .venv
.venv\Scripts\python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv\Scripts\python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
.venv\Scripts\python -m local_mail_cleaner check
.venv\Scripts\pythonw -m local_mail_cleaner
```

## 3. Najpierw tryb demo

Uruchom `start_windows.bat --demo` i kliknij **„Skanuj (tylko odczyt)”**.
Zobaczysz kilkanaście wymyślonych subskrypcji (tylko domeny `example.*`),
w tym przypadki podejrzane: podrobiony wynik weryfikacji, zduplikowane
nagłówki, niebezpieczne adresy. Tryb demo nie łączy się z żadnym serwerem
i nic nie zapisuje na stałe.

## 4. Dodawanie kont

Kliknij **„Konta…” → „Dodaj…”**, wybierz dostawcę i podaj adres e-mail.

**Hasła i tokeny wpisuj wyłącznie w oknie aplikacji.** Trafiają od razu do
Menedżera poświadczeń Windows. Nigdy nie wklejaj ich do czatu, zgłoszenia ani
e-maila, nawet przy prośbie o pomoc.

### Gmail (logowanie Google, OAuth)

Gmail wymaga własnego „klienta OAuth”. Konfiguruje się go jednorazowo:

1. Wejdź na https://console.cloud.google.com/ i utwórz projekt, np. „Local Mail Cleaner”.
2. W sekcji **Google Auth Platform / OAuth consent screen**:
   - podaj nazwę aplikacji i swój adres e-mail,
   - jako odbiorców (Audience) wybierz **External**,
   - zostaw status **Testing** i dodaj swój adres Gmail jako **Test user**.
3. W sekcji **Data Access / Scopes** dodaj zakres `https://mail.google.com/`
   (Gmail innego nie akceptuje dla IMAP).
4. W sekcji **Clients** utwórz klienta typu **Desktop app** i pobierz plik JSON
   (`client_secret_….json`).
5. Jeśli konsola o to poprosi, włącz **Gmail API** (APIs & Services → Library).
6. W aplikacji: dostawca **Gmail** → **„Wczytaj plik klienta OAuth (JSON)…”**
   → **„Zaloguj przez Google…”** (konto zapisze się automatycznie) → po
   zalogowaniu **„Zapisz”**. Logowanie odbywa się w przeglądarce, na stronie
   Google. Aplikacja na chwilę nasłuchuje tylko lokalnie (127.0.0.1), żeby
   odebrać kod logowania.
7. Po zapisaniu plik JSON nie jest już potrzebny: sekret klienta trafia do
   Menedżera poświadczeń. Plik możesz usunąć.

Warto wiedzieć:

- Google pokaże ostrzeżenie „Google nie zweryfikował tej aplikacji”. To
  normalne dla własnego klienta: wybierz „Zaawansowane” → „Przejdź do…”.
- Dopóki projekt ma status „Testing”, Google unieważnia logowanie mniej więcej
  po 7 dniach. Wtedy kliknij ponownie „Zaloguj przez Google…”.
- W kontach firmowych (Google Workspace) administrator może blokować IMAP lub
  aplikacje OAuth.

### Yahoo Mail

1. Na stronie konta Yahoo otwórz **Bezpieczeństwo konta** i wygeneruj
   **hasło aplikacji**.
2. W aplikacji wybierz dostawcę **Yahoo Mail**, podaj adres e-mail i wklej
   hasło aplikacji w polu „Hasło”. Serwer: `imap.mail.yahoo.com`, port `993`.

### IONOS

1. Login to pełny adres e-mail, hasło to hasło skrzynki (ustawisz je
   w panelu IONOS).
2. Serwer IMAP zależy od kraju umowy, np. `imap.ionos.de`, `imap.ionos.co.uk`,
   `imap.ionos.com`. Sprawdź właściwy adres w pomocy IONOS lub w panelu.
   Port `993`.

### Foldery i zakres skanowania

- Domyślnie skanowany jest folder `INBOX`. Przycisk **„Lista…”** pobiera listę
  folderów z serwera (tylko do odczytu) i pozwala zaznaczyć kilka.
- W Gmailu możesz dodać np. `[Gmail]/Wszystkie`. Ta sama wiadomość w kilku
  folderach liczy się raz.
- „Okres skanowania” (domyślnie 365 dni) i „Maks. wiadomości na folder”
  (domyślnie 5000) ograniczają, ile nagłówków zostanie pobranych.

## 5. Skanowanie i tabela

Kliknij **„Skanuj (tylko odczyt)”**. Pasek stanu pokazuje postęp, a „Anuluj”
przerywa skanowanie.

| Kolumna | Znaczenie |
|---|---|
| ✓ | zaznaczenie (kliknij komórkę albo naciśnij spację) |
| Skrzynka | konto, z którego pochodzą wiadomości |
| Nadawca | nazwa i adres nadawcy najnowszej wiadomości |
| Lista (List-ID) | identyfikator listy; po nim grupowane są subskrypcje |
| Wiadomości | liczba wiadomości z tej subskrypcji |
| Ostatnia | data najnowszej wiadomości |
| Metoda wypisania | jednym kliknięciem (RFC 8058), link HTTPS, e-mail, link HTTP, niebezpieczny adres, brak |
| Weryfikacja | czy nagłówki wypisania są uwierzytelnione |

Statusy weryfikacji:

- **Zweryfikowano (dostawca)**: Gmail potwierdził podpis DKIM, a podpis
  obejmuje nagłówki wypisania i pasuje do domeny nadawcy.
- **Zweryfikowano (lokalny DKIM)**: aplikacja sama sprawdziła podpis.
- **Wymaga ręcznej oceny**: nie da się tego potwierdzić. Powody znajdziesz
  w panelu „Szczegóły”. Sama obecność podpisu DKIM nie jest dowodem.
- **Nie dotyczy**: brak nagłówka List-Unsubscribe.

Kolory wierszy: zielony = zweryfikowano, pomarańczowy = wymaga oceny,
czerwony = niebezpieczny adres, szary = nie dotyczy.

Panel „Szczegóły” pokazuje tylko nazwy serwerów wypisania, a nie pełne adresy
(mogą zawierać Twoje osobiste tokeny).

**Plik → Eksportuj tabelę do CSV…** zapisuje widoczne wiersze (bez pełnych
adresów wypisania).

## 6. Weryfikacja DKIM (opcjonalna)

Dla Yahoo i IONOS aplikacja domyślnie nie ufa wynikom dostawcy, więc
większość wierszy ma status „Wymaga ręcznej oceny”. Aby sprawdzić podpis
samodzielnie:

1. Zaznacz wiersze.
2. Kliknij **„Weryfikuj DKIM zaznaczonych…”** i potwierdź.

Aplikacja pobierze pełną treść **najnowszej** wiadomości każdej subskrypcji
(nadal tylko do odczytu, bez oznaczania jako przeczytana) i sprawdzi podpis,
pobierając klucz publiczny z DNS. Do nadawców nic nie jest wysyłane. Przy
starszych wiadomościach weryfikacja może się nie udać, jeśli nadawca zmienił
klucz. Wtedy status zostaje „Wymaga ręcznej oceny”.

## 7. Gdzie są dane i jak je usunąć

| Co | Gdzie |
|---|---|
| Baza wyników skanowania | `%LOCALAPPDATA%\LocalMailCleaner\local_mail_cleaner.sqlite3` |
| Logi (zanonimizowane) | `%LOCALAPPDATA%\LocalMailCleaner\logs\` |
| Hasła, tokeny, sekret klienta OAuth | Menedżer poświadczeń Windows (wpisy „LocalMailCleaner”) |

- Folder danych otworzysz przez **Pomoc → Otwórz folder danych i logów**.
- Baza zawiera adresy nadawców, tematy, daty i nagłówki List-* (także pełne
  adresy wypisania). Nie zawiera treści wiadomości ani haseł.
- **Dane → Usuń lokalne wyniki skanowania…** czyści wyniki.
- Usunięcie konta w oknie „Konta…” kasuje też jego wyniki i zapisane hasła.
- Aby usunąć wszystko: usuń folder danych i wpisy „LocalMailCleaner”
  w Menedżerze poświadczeń (Panel sterowania → Menedżer poświadczeń →
  Poświadczenia systemu Windows).

Aplikacja nie wysyła żadnej telemetrii, nie korzysta z chmury ani z modeli
językowych i nie uruchamia serwera WWW.

## 8. Gdy coś nie działa

1. Uruchom `start_windows.bat --check`.
2. Zapisz raport: **Pomoc → Zapisz raport diagnostyczny…**. Raport nie
   zawiera haseł, tokenów, adresów e-mail ani pełnych adresów URL.
3. Możesz go przekazać przy prośbie o pomoc. **Nie dołączaj** haseł,
   tokenów, plików JSON klienta OAuth ani treści prawdziwych wiadomości.

Najczęstsze komunikaty:

| Komunikat | Co zrobić |
|---|---|
| Logowanie nie powiodło się | Sprawdź hasło aplikacji (Yahoo) lub hasło skrzynki (IONOS); dla Gmaila zaloguj się ponownie przez Google. |
| Zapisane logowanie Google wygasło | Kliknij „Zaloguj przez Google…” (status „Testing” = co ok. 7 dni). |
| Serwer nie potwierdził trybu tylko do odczytu | Skanowanie zatrzymano celowo. Zgłoś nazwę dostawcy. |
| Błąd TLS | Certyfikat serwera nie przeszedł weryfikacji. Sprawdź adres serwera. |
| Magazyn poświadczeń niedostępny | Hasło nie zostało zapisane. Na Windows nie powinno się to zdarzyć: uruchom `--check`. |

## 9. Ograniczenia etapu A

- Brak wypisywania, wysyłania e-maili i przenoszenia wiadomości (etapy B i C).
- Brak testów na prawdziwych skrzynkach i na Windows.
- Obsługiwany jest tylko IMAP z TLS na porcie 993 (bez STARTTLS na porcie 143).
- Bez List-ID dwa różne newslettery od tego samego nadawcy, korzystające
  z tego samego serwera wypisania, pokażą się jako jedna subskrypcja.
- Nazw folderów zawierających przecinek nie da się wpisać w polu „Foldery”.
