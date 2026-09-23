"""Checks on the token and store settings: the ``SIGNET`` dict's shape and
types, the signing keys, the grace cache and the token store."""

from __future__ import annotations

from typing import Any

from django.core.cache import InvalidCacheBackendError, caches
from django.core.checks import CheckMessage, Error
from django.core.checks import Warning as CheckWarning
from django.core.exceptions import ImproperlyConfigured

from django_signet.checks._common import _as_str, _raw_signet, _signet
from django_signet.sessions.stores.factory import get_store


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
# match against the real auth endpoints. That is the same silently-dropped-
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
    """RS algorithms need explicit keys - ``SECRET_KEY`` is not a valid RSA
    key for either role - but the two keys do different jobs, and missing
    each one breaks a different thing.

    No ``VERIFYING_KEY`` is an ``Error`` (signet.E004): ``get_backend()``
    raises ``ImproperlyConfigured``, so not a single token can be verified
    and every authenticated request fails.

    No ``SIGNING_KEY`` is a ``Warning`` (signet.W011): ``get_backend()``
    still builds a backend that verifies, and only ``sign()`` raises - so
    login and refresh fail while access tokens minted elsewhere are
    accepted. That is exactly a verify-only resource server, which
    legitimately holds no private key and must not fail
    ``manage.py check``; anywhere else it is a deployment that cannot mint
    tokens.
    """
    cfg = _signet()
    algorithm = _as_str(cfg.get("ALGORITHM"), "HS256")
    if not algorithm.startswith("RS"):
        return []
    messages: list[CheckMessage] = []
    if not cfg.get("VERIFYING_KEY"):
        messages.append(
            Error(
                f"ALGORITHM is {algorithm!r} but VERIFYING_KEY is not set.",
                hint="RSA algorithms need an explicit PEM public key "
                "(VERIFYING_KEY); SECRET_KEY is not a valid RSA key. "
                "get_backend() raises ImproperlyConfigured without it, so "
                "no token can be verified and every request would fail.",
                id="signet.E004",
            )
        )
    if not cfg.get("SIGNING_KEY"):
        messages.append(
            CheckWarning(
                f"ALGORITHM is {algorithm!r} but SIGNING_KEY is not set, so "
                "this deployment cannot mint tokens: login and refresh will "
                "fail.",
                hint="Expected for a verify-only resource server, which "
                "accepts access tokens minted elsewhere and holds no private "
                "key. Anywhere that serves login or refresh, set SIGNING_KEY "
                "to the PEM private key; SECRET_KEY is not a valid RSA key.",
                id="signet.W011",
            )
        )
    return messages


def _unusable_store_error(message: str) -> CheckMessage:
    return Error(
        message,
        hint="Point SIGNET['STORE'] at a TokenStore subclass, by "
        "dotted path, and make STORE_OPTIONS match its constructor.",
        id="signet.E010",
    )


def check_token_store(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """The configured ``STORE`` must build, and a store that cannot revoke
    every session for a user must say so at startup.

    Warning, not Error, for the second: ``CacheTokenStore`` is a supported,
    documented configuration. But under it a password change revokes
    nothing (the receiver logs a warning and lets the save through) and
    logout-all answers 501 - and a deployment should learn that from
    ``manage.py check``, not from an incident.

    *Any* exception from building the store is reported as signet.E010,
    not only the ``ImproperlyConfigured`` that :func:`get_store` raises for
    an unimportable path or a constructor signature mismatch: a store's
    own constructor may reject its ``STORE_OPTIONS`` with whatever it
    likes (``ValueError``, say), and a check must never raise. Only this
    check swallows it - ``get_store()`` itself still raises at runtime, so
    a broken store fails loudly when it is used.
    """
    if not isinstance(_raw_signet(), dict | None):
        return []  # signet.E005 reports the real problem
    try:
        store = get_store()
    except ImproperlyConfigured as exc:
        return [_unusable_store_error(str(exc))]
    except Exception as exc:
        return [
            _unusable_store_error(
                f"SIGNET['STORE'] = {_signet().get('STORE')!r} could not be "
                f"constructed: {type(exc).__name__}: {exc}"
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
