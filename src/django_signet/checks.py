"""Django system checks for ``manage.py check``.

Rationale for existing at all: a ``__Host-`` cookie with a non-root path is
silently dropped by the browser - no error, no log line, the request just
arrives unauthenticated. System checks turn that kind of invisible runtime
failure into a loud startup failure instead of a production mystery.

A check must never itself raise. Whatever a misconfigured project actually
put in ``SIGNET`` - the wrong shape entirely, or a field of the wrong type -
the outcome has to be a reported message, not an unhandled traceback from
``manage.py check``. That would be the exact failure mode this module
exists to prevent, one level up. ``_signet()`` degrades any non-dict
``SIGNET`` to ``{}`` so every check below it is quiet rather than crashing;
``check_signet_setting_shape`` is the one check that names the real
problem. ``_as_str()`` gives the same treatment to individual fields: a
field present with the wrong type is treated as absent rather than reaching
a string API and raising.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.cache import InvalidCacheBackendError, caches
from django.core.checks import CheckMessage, Error
from django.core.checks import Warning as CheckWarning


def _raw_signet() -> Any:
    return getattr(settings, "SIGNET", None)


def _signet() -> dict[str, Any]:
    raw = _raw_signet()
    return raw if isinstance(raw, dict) else {}


def _as_str(value: Any, default: str) -> str:
    """``dict.get(key, default)`` only substitutes ``default`` when the key
    is *absent* - a key present with the wrong type, or an explicit
    ``None`` (several ``DEFAULTS`` entries use ``None`` as a "derive this"
    sentinel), still comes through unchanged and would otherwise reach
    ``.startswith()`` and raise. Treating anything that isn't already a
    ``str`` as absent keeps every caller crash-proof without silently
    hiding a *correctly-typed* misconfiguration.
    """
    return value if isinstance(value, str) else default


def check_signet_setting_shape(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    raw = _raw_signet()
    if raw is None or isinstance(raw, dict):
        return []
    return [
        Error(
            f"SIGNET setting must be a dict, got {type(raw).__name__}.",
            hint="Set SIGNET = {...} in your project settings, or remove it "
            "entirely to use the library defaults.",
            id="signet.E005",
        )
    ]


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
    name = _as_str(cfg.get("COOKIE_REFRESH_NAME"), "")
    if not name.startswith("__Host-"):
        return []

    path = _as_str(cfg.get("COOKIE_REFRESH_PATH"), "/api/auth/refresh")
    domain = cfg.get("COOKIE_DOMAIN")
    problems = []
    if path != "/":
        problems.append(f"is scoped to path {path!r}")
    if domain is not None:
        problems.append(f"sets Domain={domain!r}")
    if not problems:
        return []

    return [
        Error(
            f"Cookie {name!r} uses the __Host- prefix but "
            + " and ".join(problems)
            + ".",
            hint="__Host- requires Path=/ and no Domain attribute. Browsers "
            "silently drop the cookie otherwise, so requests arrive "
            "unauthenticated with no error. Use the __Secure- prefix "
            "instead.",
            id="signet.E002",
        )
    ]


def check_grace_cache(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    alias = _signet().get("GRACE_CACHE", "default")
    if alias is None:
        return []  # explicitly disabled: strict mode, nothing to warn about
    try:
        caches[alias]
    except (InvalidCacheBackendError, TypeError):
        # TypeError covers an unhashable alias (a list, say) - it can never
        # name a real cache either, so it degrades the same way as an
        # unknown one.
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
    algorithm = _as_str(cfg.get("ALGORITHM"), "HS256")
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
    check_signet_setting_shape,
    check_cookie_security,
    check_cookie_prefix,
    check_grace_cache,
    check_signing_key,
)
