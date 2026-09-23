"""Django system checks for ``manage.py check``.

Rationale for existing at all: a ``__Host-`` cookie with a non-root path is
silently dropped by the browser - no error, no log line, the request just
arrives unauthenticated. System checks turn that kind of invisible runtime
failure into a loud startup failure instead of a production mystery.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.cache import InvalidCacheBackendError, caches
from django.core.checks import CheckMessage, Error
from django.core.checks import Warning as CheckWarning


def _signet() -> dict[str, Any]:
    return getattr(settings, "SIGNET", {}) or {}


def check_cookie_security(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    cfg = _signet()
    if settings.DEBUG or cfg.get("COOKIE_SECURE", True):
        return []
    return [
        Error(
            "Signet cookies are configured with secure=False while DEBUG=False.",
            hint="Authentication cookies must only travel over HTTPS in "
            "production. Remove COOKIE_SECURE=False from the SIGNET setting.",
            id="signet.E001",
        )
    ]


def check_cookie_prefix(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    cfg = _signet()
    name = cfg.get("COOKIE_REFRESH_NAME") or ""
    path = cfg.get("COOKIE_REFRESH_PATH", "/api/auth/refresh")
    if name.startswith("__Host-") and path != "/":
        return [
            Error(
                f"Cookie {name!r} uses the __Host- prefix but is scoped to "
                f"path {path!r}.",
                hint="__Host- requires Path=/. Browsers silently drop the "
                "cookie otherwise, so requests arrive unauthenticated with no "
                "error. Use the __Secure- prefix for path-scoped cookies.",
                id="signet.E002",
            )
        ]
    return []


def check_grace_cache(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    alias = _signet().get("GRACE_CACHE", "default")
    if alias is None:
        return []  # explicitly disabled: strict mode, nothing to warn about
    try:
        caches[alias]
    except InvalidCacheBackendError:
        return [
            CheckWarning(
                f"SIGNET['GRACE_CACHE'] names cache alias {alias!r}, which is "
                "not configured.",
                hint="Without a cache the refresh grace window cannot work, "
                "so concurrent refreshes from two tabs will be treated as "
                "token theft. Configure the cache, or set GRACE_CACHE=None to "
                "choose strict RFC 9700 behaviour deliberately.",
                id="signet.W003",
            )
        ]
    return []


def check_signing_key(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """RS algorithms need both an explicit signing (private) key and an
    explicit verifying (public) key - ``SECRET_KEY`` is not a valid RSA key
    for either role. ``get_backend()`` raises ``ImproperlyConfigured`` when
    either is missing, so every request would fail: this is a deployment
    that cannot verify a single token, not a style concern, hence ``Error``
    rather than ``Warning``.
    """
    cfg = _signet()
    algorithm = cfg.get("ALGORITHM", "HS256")
    if not algorithm.startswith("RS"):
        return []
    missing = [key for key in ("SIGNING_KEY", "VERIFYING_KEY") if not cfg.get(key)]
    if not missing:
        return []
    return [
        Error(
            f"ALGORITHM is {algorithm!r} but {' and '.join(missing)} "
            f"{'is' if len(missing) == 1 else 'are'} not set.",
            hint="RSA algorithms need an explicit PEM private key "
            "(SIGNING_KEY) and public key (VERIFYING_KEY); SECRET_KEY is "
            "not a valid RSA key for either. get_backend() raises "
            "ImproperlyConfigured for either being missing, so every "
            "request would fail.",
            id="signet.E004",
        )
    ]


ALL_CHECKS = (
    check_cookie_security,
    check_cookie_prefix,
    check_grace_cache,
    check_signing_key,
)
