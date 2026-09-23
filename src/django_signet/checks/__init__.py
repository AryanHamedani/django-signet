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

from django_signet.checks.cookies import (
    check_cookie_httponly,
    check_cookie_prefix,
    check_cookie_samesite,
    check_cookie_security,
)
from django_signet.checks.settings import (
    check_grace_cache,
    check_setting_types,
    check_signet_setting_shape,
    check_signing_key,
    check_token_store,
)
from django_signet.checks.urls import check_refresh_cookie_path

__all__ = [
    "ALL_CHECKS",
    "check_cookie_httponly",
    "check_cookie_prefix",
    "check_cookie_samesite",
    "check_cookie_security",
    "check_grace_cache",
    "check_refresh_cookie_path",
    "check_setting_types",
    "check_signet_setting_shape",
    "check_signing_key",
    "check_token_store",
]

ALL_CHECKS = (
    check_signet_setting_shape,
    check_setting_types,
    check_cookie_security,
    check_cookie_httponly,
    check_cookie_samesite,
    check_cookie_prefix,
    check_grace_cache,
    check_signing_key,
    check_token_store,
    check_refresh_cookie_path,
)
