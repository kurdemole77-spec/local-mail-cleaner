"""Polish user-interface texts (shared by the GUI and the command line)."""

from __future__ import annotations

APP_TITLE = "Local Mail Cleaner — Etap A (tylko odczyt)"
READ_ONLY_BANNER = (
    "TRYB TYLKO DO ODCZYTU: aplikacja pobiera wyłącznie nagłówki (EXAMINE + BODY.PEEK). "
    "Nie wypisuje z subskrypcji, nie wysyła e-maili, nie przenosi i nie usuwa wiadomości."
)
DEMO_BANNER = "TRYB DEMO: dane syntetyczne, bez połączeń z prawdziwymi skrzynkami."

COLUMNS = {
    "sel": "✓",
    "mailbox": "Skrzynka",
    "sender": "Nadawca",
    "list": "Lista (List-ID)",
    "count": "Wiadomości",
    "latest": "Ostatnia",
    "method": "Metoda wypisania",
    "verification": "Weryfikacja",
}

METHODS = {
    "one_click": "Jednym kliknięciem (RFC 8058)",
    "https_link": "Link HTTPS (ręcznie w przeglądarce)",
    "mailto": "E-mail (mailto)",
    "http_link": "Link HTTP bez szyfrowania (ręcznie)",
    "unsafe": "Niebezpieczny adres — tylko ręcznie",
    "none": "Brak",
}

VERIFICATION = {
    "verified_local": "Zweryfikowano (lokalny DKIM)",
    "verified_provider": "Zweryfikowano (dostawca)",
    "manual_review": "Wymaga ręcznej oceny",
    "not_applicable": "Nie dotyczy",
}

LOCAL_STATUS = {
    "pass": "zgodny",
    "fail": "niezgodny / niepotwierdzony",
    "not_run": "nie sprawdzano",
}

REASONS = {
    # authentication evidence
    "no_dkim_signature": "brak podpisu DKIM",
    "dkim_signature_unverified": "podpis DKIM obecny, ale niezweryfikowany (sama obecność nie jest dowodem)",
    "provider_evidence_not_trusted": "dla tej skrzynki nie ufamy wynikom dostawcy — użyj lokalnej weryfikacji DKIM",
    "no_trusted_authentication_results": "brak nagłówka Authentication-Results od dostawcy",
    "top_authentication_results_not_trusted": "najwyższy nagłówek Authentication-Results nie pochodzi od zaufanego dostawcy",
    "provider_dkim_not_pass": "dostawca nie potwierdził DKIM (wynik inny niż pass)",
    "no_matching_signature": "nie znaleziono podpisu DKIM pasującego do wyniku dostawcy",
    "ambiguous_signature_match": "kilka podpisów pasuje do wyniku dostawcy — niejednoznaczne",
    "unsubscribe_headers_not_signed": "podpis DKIM nie obejmuje nagłówka List-Unsubscribe",
    "unsubscribe_post_header_not_signed": "podpis DKIM nie obejmuje nagłówka List-Unsubscribe-Post",
    "signer_not_aligned_with_sender": "domena podpisu nie odpowiada domenie nadawcy",
    "weak_signature_algorithm": "słaby algorytm podpisu (np. rsa-sha1)",
    "signature_uses_body_length_limit": "podpis obejmuje tylko część treści (znacznik l=)",
    "sender_domain_unknown": "nie można ustalić domeny nadawcy",
    "dkim_signature_invalid": "lokalna weryfikacja DKIM nie powiodła się (np. brak klucza w DNS lub zmieniona treść)",
    "dkim_verification_error": "błąd podczas lokalnej weryfikacji DKIM",
    "dkim_library_unavailable": "brak biblioteki dkimpy",
    "message_too_large_to_verify": "wiadomość zbyt duża do weryfikacji",
    "duplicate_security_headers": "zduplikowane nagłówki From/List-Unsubscribe (możliwa próba podszycia)",
    "unsafe_unsubscribe_targets": "adresy wypisania nie przeszły kontroli bezpieczeństwa",
    "local_check_failed_provider_passed": "lokalna weryfikacja przeczy wynikowi dostawcy",
    "message_reference_stale": "folder został zmieniony na serwerze (UIDVALIDITY) — zeskanuj ponownie",
    "message_not_found": "nie znaleziono wiadomości na serwerze — zeskanuj ponownie",
    # header problems
    "headers_too_large": "nagłówki zbyt duże",
    "duplicate_list_unsubscribe": "kilka nagłówków List-Unsubscribe",
    "duplicate_list_unsubscribe_post": "kilka nagłówków List-Unsubscribe-Post",
    "duplicate_from": "kilka nagłówków From",
    "duplicate_list_id": "kilka nagłówków List-ID",
    "malformed_list_unsubscribe": "nieprawidłowy nagłówek List-Unsubscribe",
    "list_unsubscribe_too_long": "nagłówek List-Unsubscribe zbyt długi",
    "too_many_uris": "zbyt wiele adresów w List-Unsubscribe",
    "malformed_list_id": "nieprawidłowy nagłówek List-ID",
    "multiple_from_addresses": "kilka adresów w polu From",
    "invalid_from": "nieprawidłowe pole From",
    "invalid_list_unsubscribe_post": "List-Unsubscribe-Post ma niewłaściwą wartość",
    # destination problems
    "not_https": "adres nie używa HTTPS",
    "insecure_http": "adres HTTP bez szyfrowania",
    "too_long": "adres zbyt długi",
    "invalid_chars": "niedozwolone znaki w adresie",
    "userinfo": "adres zawiera dane logowania (user@host)",
    "nonstandard_port": "niestandardowy port",
    "no_host": "brak nazwy serwera",
    "invalid_host": "nieprawidłowa nazwa serwera",
    "ip_literal": "adres IP zamiast nazwy domeny",
    "forbidden_address": "adres lokalny, prywatny lub zarezerwowany",
    "local_hostname": "nazwa lokalna lub zarezerwowana",
    "mailto_invalid": "nieprawidłowy adres mailto",
    "mailto_multiple_recipients": "mailto z wieloma odbiorcami",
    "unsupported_scheme": "nieobsługiwany rodzaj adresu",
}

ERRORS = {
    "connection": "Nie można połączyć się z serwerem IMAP.",
    "tls": "Błąd TLS: certyfikat serwera nie został zweryfikowany.",
    "auth": "Logowanie nie powiodło się (sprawdź hasło aplikacji / ponownie zaloguj się do Google).",
    "protocol": "Serwer odpowiedział nieoczekiwanie.",
    "read_only": "Serwer nie potwierdził trybu tylko do odczytu — skanowanie zatrzymane dla bezpieczeństwa.",
    "internal": "Nieoczekiwany błąd aplikacji (szczegóły w logu).",
    "config": "Nieprawidłowy plik klienta OAuth (wymagany typ „Desktop app”).",
    "cancelled": "Anulowano.",
    "timeout": "Upłynął czas na zalogowanie.",
    "denied": "Logowanie do Google nie zostało zakończone.",
    "token": "Google nie wydał wymaganych uprawnień (zakres https://mail.google.com/).",
    "network": "Błąd sieci podczas komunikacji z Google.",
    "reauth": "Zapisane logowanie Google wygasło — zaloguj się ponownie.",
    "account_mismatch": "Zalogowano innym kontem Google niż skonfigurowane.",
}


def reason_text(code: str) -> str:
    return REASONS.get(code, code)


def error_text(kind: str) -> str:
    return ERRORS.get(kind, kind)
