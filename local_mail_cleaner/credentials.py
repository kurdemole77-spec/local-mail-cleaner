"""Secrets in the operating system's credential store (via ``keyring``).

On Windows this is the Windows Credential Manager. Secrets are never written to
the database, configuration files or logs. If no secure backend is available
the store refuses to save anything (fail closed) instead of falling back to a
plaintext file.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

SERVICE = "LocalMailCleaner"

KIND_PASSWORD = "password"
KIND_GOOGLE_REFRESH = "google_refresh_token"
KIND_GOOGLE_CLIENT_SECRET = "google_client_secret"
ALL_KINDS = (KIND_PASSWORD, KIND_GOOGLE_REFRESH, KIND_GOOGLE_CLIENT_SECRET)

_INSECURE_BACKEND_MODULES = ("keyrings.alt", "keyring.backends.fail", "keyring.backends.null")


class CredentialStoreUnavailable(RuntimeError):
    pass


class CredentialStore:
    """Thin wrapper so the backend can be replaced in tests."""

    def __init__(self, backend=None):
        self._backend = backend

    def _keyring(self):
        if self._backend is not None:
            return self._backend
        try:
            import keyring
        except ImportError:
            raise CredentialStoreUnavailable("keyring package is not installed") from None
        backend = keyring.get_keyring()
        module = type(backend).__module__
        names = [module] + [type(b).__module__ for b in getattr(backend, "backends", [])]
        chained = getattr(backend, "backends", None)
        if chained is not None and not chained:
            raise CredentialStoreUnavailable("no OS credential store backend available")
        if any(n.startswith(_INSECURE_BACKEND_MODULES) for n in names):
            raise CredentialStoreUnavailable(f"insecure keyring backend refused: {module}")
        return backend

    def backend_name(self) -> str:
        try:
            backend = self._keyring()
        except CredentialStoreUnavailable as exc:
            return f"unavailable ({exc})"
        return f"{type(backend).__module__}.{type(backend).__name__}"

    @staticmethod
    def _username(account_id: int, kind: str) -> str:
        if kind not in ALL_KINDS:
            raise ValueError(f"unknown secret kind: {kind}")
        return f"account-{int(account_id)}:{kind}"

    def set(self, account_id: int, kind: str, secret: str) -> None:
        if not secret:
            raise ValueError("empty secret")
        self._keyring().set_password(SERVICE, self._username(account_id, kind), secret)
        log.info("Stored %s for account %d in the OS credential store", kind, account_id)

    def get(self, account_id: int, kind: str) -> str | None:
        return self._keyring().get_password(SERVICE, self._username(account_id, kind))

    def has(self, account_id: int, kind: str) -> bool:
        try:
            return bool(self.get(account_id, kind))
        except CredentialStoreUnavailable:
            return False

    def delete(self, account_id: int, kind: str) -> None:
        try:
            self._keyring().delete_password(SERVICE, self._username(account_id, kind))
        except Exception as exc:  # keyring raises PasswordDeleteError when absent
            if type(exc).__name__ != "PasswordDeleteError":
                raise

    def delete_all(self, account_id: int) -> None:
        for kind in ALL_KINDS:
            self.delete(account_id, kind)


class MemoryBackend:
    """In-memory keyring backend for tests and demo mode. Never used for real accounts."""

    def __init__(self):
        self.data: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self.data[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self.data.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        self.data.pop((service, username), None)
