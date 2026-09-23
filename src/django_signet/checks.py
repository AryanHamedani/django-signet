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

What these checks cannot see: configuration written as Python on a class.
They read the ``SIGNET`` settings dict (and, for ``signet.E008``, the real
URLconf); a ``CookiePolicy(secure=False, httponly=False)`` constructed in
a subclass, a ``store = X()`` pinned on one class, or any hook override is
arbitrary code, and cannot be exhaustively introspected. A clean
``manage.py check`` means the *settings* are coherent - not that every
class-level override is.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from django.conf import settings
from django.core.cache import InvalidCacheBackendError, caches
from django.core.checks import CheckMessage, Error
from django.core.checks import Warning as CheckWarning
from django.core.exceptions import ImproperlyConfigured
from django.urls import NoReverseMatch, URLResolver, get_resolver, reverse

from django_signet.conf import DEFAULTS
from django_signet.sessions.stores.factory import get_store
from django_signet.views import RefreshCredentialView


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


def check_cookie_httponly(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Warning, not Error: unlike ``secure=False`` there is no local-HTTP
    reason to need it, but it is a deliberate, settable choice - and the
    CSRF cookie is JavaScript-readable by design, so this flag governs the
    access and refresh cookies only."""
    if _signet().get("COOKIE_HTTPONLY", True):
        return []
    return [
        CheckWarning(
            "Signet access and refresh cookies are configured with "
            "httponly=False, so any script on the page can read the tokens.",
            hint="One XSS then exfiltrates a 14-day refresh token - the "
            "exposure httpOnly cookies exist to prevent. Remove "
            "COOKIE_HTTPONLY=False from the SIGNET setting.",
            id="signet.W009",
        )
    ]


# The explicitly nameable cookies, with the path each one is set at. The
# access and CSRF cookies are always set at "/"; the refresh cookie at
# COOKIE_REFRESH_PATH (None here, resolved per call).
_COOKIE_NAME_SETTINGS: tuple[tuple[str, str | None], ...] = (
    ("COOKIE_ACCESS_NAME", "/"),
    ("COOKIE_REFRESH_NAME", None),
    ("COOKIE_CSRF_NAME", "/"),
)


def _prefix_violations(name: str, *, secure: bool, path: str, domain: Any) -> list[str]:
    """The requirements of ``name``'s browser-enforced prefix that a cookie
    with these attributes breaks, each as a phrase naming the requirement
    and what the settings do instead. Browsers match the prefixes
    case-insensitively, so ``__host-`` is held to ``__Host-``'s rules."""
    lowered = name.lower()
    if lowered.startswith("__host-"):
        prefix = "__Host-"
    elif lowered.startswith("__secure-"):
        prefix = "__Secure-"
    else:
        return []
    violations = []
    if not secure:
        violations.append(
            f"the {prefix} prefix requires Secure, but COOKIE_SECURE is False"
        )
    if prefix == "__Host-" and path != "/":
        violations.append(
            f"the __Host- prefix requires Path=/, but it is set at path {path!r}"
        )
    if prefix == "__Host-" and domain is not None:
        violations.append(
            "the __Host- prefix requires no Domain, but COOKIE_DOMAIN sets "
            f"Domain={domain!r}"
        )
    return violations


def check_cookie_prefix(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Every explicitly named cookie must keep its prefix's contract.

    Browsers enforce cookie-name prefixes: a ``__Host-`` cookie must be
    ``Secure``, set at ``Path=/`` and carry no ``Domain``; a ``__Secure-``
    cookie must be ``Secure``. One that breaks the rule is silently dropped
    - no error, no log line - so every request arrives unauthenticated.

    Checked for ``COOKIE_ACCESS_NAME``, ``COOKIE_REFRESH_NAME`` and
    ``COOKIE_CSRF_NAME``: the refresh cookie is set at
    ``COOKIE_REFRESH_PATH``, the other two always at ``/``. A name left
    ``None`` is derived by ``CookiePolicy``, which only picks a prefix the
    cookie's attributes satisfy, so it is never flagged. One message per
    violated requirement, each naming the setting and the cookie.
    """
    cfg = _signet()
    secure = cfg.get("COOKIE_SECURE", True)
    domain = cfg.get("COOKIE_DOMAIN")
    refresh_path = _as_str(
        cfg.get("COOKIE_REFRESH_PATH"), DEFAULTS["COOKIE_REFRESH_PATH"]
    )
    errors: list[CheckMessage] = []
    for key, fixed_path in _COOKIE_NAME_SETTINGS:
        name = _as_str(cfg.get(key), "")
        path = fixed_path if fixed_path is not None else refresh_path
        for violation in _prefix_violations(
            name, secure=secure, path=path, domain=domain
        ):
            errors.append(
                Error(
                    f"SIGNET[{key!r}] = {name!r}: {violation}.",
                    hint="Browsers silently drop a cookie that breaks its "
                    "name prefix's rules, so requests arrive unauthenticated "
                    "with no error. Fix the attribute, or choose a name the "
                    "cookie can keep: __Secure- for a path-scoped or "
                    "Domain-scoped cookie, or leave the name unset (None) "
                    "to have it derived.",
                    id="signet.E002",
                )
            )
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


def _named_views(
    resolver: URLResolver, namespaces: tuple[str, ...] = ()
) -> Iterator[tuple[str, Any]]:
    """Every named, class-based route in the URLconf, as
    ``(qualified_name, view_class)``."""
    for entry in resolver.url_patterns:
        if isinstance(entry, URLResolver):
            nested = (*namespaces, entry.namespace) if entry.namespace else namespaces
            yield from _named_views(entry, nested)
        elif entry.name and hasattr(entry.callback, "view_class"):
            yield ":".join((*namespaces, entry.name)), entry.callback.view_class


def _cookie_path_covers(cookie_path: str, url: str) -> bool:
    """Whether a browser sends a cookie scoped to ``cookie_path`` to
    ``url``. Paths match at ``/`` boundaries (RFC 6265 section 5.1.4), not
    as string prefixes: ``/api/auth`` covers ``/api/auth/refresh`` but not
    ``/api/authn/refresh``."""
    if not url.startswith(cookie_path):
        return False
    return (
        len(url) == len(cookie_path)
        or cookie_path.endswith("/")
        or url[len(cookie_path)] == "/"
    )


def _refresh_path_error(name: str, view_class: Any) -> CheckMessage | None:
    if not (
        isinstance(view_class, type) and issubclass(view_class, RefreshCredentialView)
    ):
        return None
    policy = view_class.transport.cookie_policy
    if policy is None:
        return None  # a header transport sets no cookie to scope
    if not isinstance(policy.refresh_path, str):
        return None  # signet.E006 reports the real problem
    try:
        url = reverse(name)
    except NoReverseMatch:
        return None  # a route that needs arguments has no single URL
    if _cookie_path_covers(policy.refresh_path, url):
        return None
    return Error(
        f"{view_class.__name__} is mounted at {url!r}, outside its refresh "
        f"cookie's path {policy.refresh_path!r}.",
        hint="A browser only sends a cookie to URLs under its Path, so "
        "refresh, logout and logout-all would never receive the refresh "
        "cookie - refresh fails and logout cannot revoke, with no error. "
        "Set COOKIE_REFRESH_PATH (or the realm's CookiePolicy refresh_path) "
        "to the prefix the auth URLs are mounted at.",
        id="signet.E008",
    )


def check_refresh_cookie_path(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Every mounted endpoint that reads the refresh cookie must sit under
    that cookie's ``Path``.

    Walks the real URLconf rather than trusting the default mount point,
    so it covers ``django_signet.urls`` mounted anywhere and every realm
    built with ``signet_urls()``. Mounting at ``/auth/`` with the default
    ``/api/auth/`` path is caught here, at startup, instead of surfacing as
    silent refresh failures in production.
    """
    if not getattr(settings, "ROOT_URLCONF", None):
        return []
    if not isinstance(_raw_signet(), dict | None):
        return []  # signet.E005 reports the real problem
    found = (
        _refresh_path_error(name, view_class)
        for name, view_class in _named_views(get_resolver())
    )
    return [error for error in found if error is not None]


ALL_CHECKS = (
    check_signet_setting_shape,
    check_setting_types,
    check_cookie_security,
    check_cookie_httponly,
    check_cookie_prefix,
    check_grace_cache,
    check_signing_key,
    check_token_store,
    check_refresh_cookie_path,
)
