"""Checks on the cookie settings: ``Secure``, ``HttpOnly``, ``SameSite`` and
the browser-enforced name prefixes."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.checks import CheckMessage, Error
from django.core.checks import Warning as CheckWarning

from django_signet.checks._common import _as_str, _signet
from django_signet.conf import DEFAULTS


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


def check_cookie_samesite(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """``SameSite=None`` without ``Secure`` is a cookie browsers refuse.

    Chromium-based browsers reject such a cookie outright - no error, no
    log line, the same silent drop ``signet.E002`` exists to catch - so a
    cross-site setup that turns off ``COOKIE_SECURE`` for local HTTP
    stops authenticating with nothing said. A Warning rather than an Error
    because enforcement varies between browser engines. Matched
    case-insensitively, as browsers read the attribute.
    """
    cfg = _signet()
    samesite = _as_str(cfg.get("COOKIE_SAMESITE"), "")
    if samesite.lower() != "none" or cfg.get("COOKIE_SECURE", True):
        return []
    return [
        CheckWarning(
            "SIGNET['COOKIE_SAMESITE'] is 'None' but COOKIE_SECURE is False: "
            "browsers reject a SameSite=None cookie that is not Secure.",
            hint="Chromium-based browsers drop these cookies silently, so "
            "requests arrive unauthenticated with no error. Serve over "
            "HTTPS with COOKIE_SECURE left on, or use SameSite=Lax (the "
            "default), which a same-site frontend does not need to change.",
            id="signet.W012",
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
