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
problem. ``_as_str()`` gives the same treatment to individual fields inside
the checks that dereference them: a field present with the wrong type is
treated as absent rather than reaching a string API and raising.

Surviving is not the same as passing, though: a check that silently falls
back to a safe default for a wrong-typed setting produces a clean
``manage.py check`` for a configuration that cannot actually work (an
``ALGORITHM`` that is not a string, a cookie name that is not a string)
and fails only later, at request time, with nothing at startup having said
so. ``check_setting_types`` is the one check that reports *that* - crash
avoidance and misconfiguration reporting are two different jobs, done by
two different functions.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.cache import InvalidCacheBackendError, caches
from django.core.checks import CheckMessage, Error
from django.core.checks import Warning as CheckWarning
from django.core.exceptions import ImproperlyConfigured

from django_signet.sessions.stores.factory import get_store


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


# Settings every other check dereferences as a string: a wrong type here
# either crashes the dereferencing check (guarded elsewhere by _as_str) or -
# worse - is silently tolerated and reaches an API that fails later, at
# request time, with no system check ever having said a word. ALGORITHM and
# COOKIE_REFRESH_PATH have no legitimate non-str value; the three
# cookie-name settings legitimately accept None ("derive the name from
# COOKIE_PREFIX"). COOKIE_REFRESH_PATH belongs here rather than being left
# to _as_str()'s silent fallback: a wrong-typed path does not degrade to
# the default - it is written straight into the cookie's ``Path`` attribute
# (e.g. ``Path=42`` for an int), which every browser silently declines to
# match against the real refresh endpoint. That is the same silently-dropped-
# cookie failure signet.E002 exists to catch, reached through a different
# attribute, so a wrong type here must be just as loud.
_REQUIRES_STR: tuple[str, ...] = ("ALGORITHM", "COOKIE_REFRESH_PATH")
_REQUIRES_STR_OR_NONE: tuple[str, ...] = (
    "COOKIE_REFRESH_NAME",
    "COOKIE_ACCESS_NAME",
    "COOKIE_CSRF_NAME",
)


def _wrong_type_error(key: str, value: Any, expected: str) -> CheckMessage:
    return Error(
        f"SIGNET[{key!r}] must be {expected}, got {type(value).__name__}.",
        hint=f"Fix the type of SIGNET[{key!r}] in your project settings. "
        "A wrong-typed value here does not crash manage.py check (the "
        "checks that read it fall back safely), but it does reach live "
        "code at request time and fail there instead - silently, as far "
        "as this check suite is concerned.",
        id="signet.E006",
    )


def check_setting_types(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Reports, rather than tolerates, a present-but-wrong-typed setting.

    The functions below (``check_cookie_prefix``, ``check_signing_key``)
    already guard themselves against this with ``_as_str()`` so *they*
    never raise - but a silent fallback to a default is not the same as a
    passing configuration. ``ALGORITHM=123`` or
    ``COOKIE_REFRESH_NAME=999`` both pass every other check cleanly and
    both fail at request time (``get_backend()`` rejects a non-string
    algorithm; a non-string cookie name can never be set on a response).
    This is the check that says so at startup instead.
    """
    cfg = _signet()
    errors: list[CheckMessage] = []
    for key in _REQUIRES_STR:
        if key in cfg and not isinstance(cfg[key], str):
            errors.append(_wrong_type_error(key, cfg[key], "a str"))
    for key in _REQUIRES_STR_OR_NONE:
        value = cfg.get(key)
        if key in cfg and value is not None and not isinstance(value, str):
            errors.append(_wrong_type_error(key, value, "a str or None"))
    return errors


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


def check_token_store(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """The configured ``STORE`` must build, and a store that cannot revoke
    every session for a user must say so at startup.

    Warning, not Error, for the second: ``CacheTokenStore`` is a supported,
    documented configuration. But under it a password change revokes
    nothing (the receiver logs a warning and lets the save through) and
    logout-all answers 501 - and a deployment should learn that from
    ``manage.py check``, not from an incident.
    """
    if not isinstance(_raw_signet(), dict | None):
        return []  # signet.E005 reports the real problem
    try:
        store = get_store()
    except ImproperlyConfigured as exc:
        return [
            Error(
                str(exc),
                hint="Point SIGNET['STORE'] at a TokenStore subclass, by "
                "dotted path, and make STORE_OPTIONS match its constructor.",
                id="signet.E010",
            )
        ]
    if store.supports_revoke_all_for_user:
        return []
    return [
        CheckWarning(
            f"The configured token store ({type(store).__name__}) cannot "
            "revoke every session for a user: password-change revocation "
            "and logout-all are unavailable under it.",
            hint="A password change will be saved but will leave existing "
            "sessions live until they expire, and POST logout-all returns "
            "501. Use ORMTokenStore if either matters; see docs/stores.md.",
            id="signet.W007",
        )
    ]


ALL_CHECKS = (
    check_signet_setting_shape,
    check_setting_types,
    check_cookie_security,
    check_cookie_prefix,
    check_grace_cache,
    check_signing_key,
    check_token_store,
)
