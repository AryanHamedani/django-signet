from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.conf import settings as django_settings

DEFAULTS: dict[str, Any] = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=14),
    "ALGORITHM": "HS256",
    "SIGNING_KEY": None,  # None -> fall back to settings.SECRET_KEY
    "VERIFYING_KEY": None,
    "AUDIENCE": None,
    "ISSUER": None,
    "LEEWAY": timedelta(seconds=0),
    "GRACE_WINDOW": timedelta(seconds=10),
    "GRACE_CACHE": "default",
    # A dotted path, not a class: settings.py cannot import a module that
    # imports models. See django_signet.sessions.stores.factory.get_store.
    "STORE": "django_signet.sessions.stores.orm.ORMTokenStore",
    "STORE_OPTIONS": {},
    "COOKIE_PREFIX": "signet",
    "COOKIE_SAMESITE": "Lax",
    "COOKIE_SECURE": True,
    "COOKIE_HTTPONLY": True,
    # The auth mount prefix, not the refresh endpoint alone: logout and
    # logout-all revoke via the refresh credential, so it has to reach them.
    "COOKIE_REFRESH_PATH": "/api/auth/",
    "COOKIE_DOMAIN": None,
    "COOKIE_ACCESS_NAME": None,  # None -> derive from prefix + prefix rules
    "COOKIE_REFRESH_NAME": None,
    "COOKIE_CSRF_NAME": None,
}

_UNSET: Any = object()


class setting:
    """Resolve a configurable value.

    Resolution order, highest first:
      1. a literal assigned on a subclass (which shadows this descriptor entirely)
      2. the project's ``SIGNET`` settings dict
      3. the ``default`` passed here, else ``DEFAULTS[name]``

    Rule 1 needs no code: assigning a plain value on a subclass shadows the
    descriptor through normal attribute lookup, so ``__get__`` never runs.
    Nothing is cached, so ``override_settings`` works in tests.
    """

    def __init__(self, name: str, default: Any = _UNSET) -> None:
        self.name = name
        self.default = default

    def __get__(self, obj: Any, owner: type | None = None) -> Any:
        overrides = getattr(django_settings, "SIGNET", {}) or {}
        if self.name in overrides:
            return overrides[self.name]
        if self.default is not _UNSET:
            return self.default
        return DEFAULTS[self.name]
