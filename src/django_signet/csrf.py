from __future__ import annotations

import hmac
import secrets
from typing import Any

from django_signet.exceptions import CSRFFailed
from django_signet.transport.cookie import CookiePolicy

CSRF_HEADER = "HTTP_X_CSRF_TOKEN"

# GET/HEAD/OPTIONS/TRACE never mutate state, so double-submit adds nothing
# for them - and requiring it would break plain navigation and preflight.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def new_csrf_token() -> str:
    """A fresh, unpredictable token. Not a JWT, not tied to a session -
    just a value the client can only have if it already read the cookie."""
    return secrets.token_urlsafe(32)


def issue_csrf(response: Any, policy: CookiePolicy, token: str | None = None) -> str:
    """Set the double-submit cookie and return the token that was set.

    Deliberately NOT httponly: the client has to read this cookie in
    JavaScript in order to echo it back in the ``CSRF_HEADER`` header,
    which is the entire mechanism. Setting it HttpOnly by reflex - the
    right default for every *other* cookie this library issues - would
    break the scheme without raising anywhere; the browser would just stop
    sending a header the client can no longer read.

    path="/" is load-bearing, not a stylistic default: policy.csrf_name
    resolves to a __Host--prefixed name under the default secure settings
    (see CookiePolicy.csrf_name), and __Host- cookies are only honoured by
    the browser at Path=/. Set it anywhere else and the browser silently
    drops the cookie - no exception, no log line - and every legitimate
    unsafe request then fails validate_csrf(), which looks like a bug in
    the check itself rather than in how the cookie was issued.

    ``token``, if supplied, is trusted as-is and written straight into the
    cookie: it must come from this library (e.g. a fixed value in a test,
    or a value already vetted by the caller), never from client input. A
    caller that let the client choose its own CSRF token would let an
    attacker set matching cookie and header values from their own page,
    defeating the entire double-submit scheme.
    """
    token = token or new_csrf_token()
    response.set_cookie(
        policy.csrf_name,
        token,
        path="/",
        domain=policy.domain,
        secure=policy.secure,
        httponly=False,
        samesite=policy.samesite,
    )
    return token


def validate_csrf(request: Any, policy: CookiePolicy) -> None:
    """Enforce the double-submit check on unsafe methods.

    Cookies are attached by the browser automatically, so a cookie alone
    proves nothing about who sent the request - that ambient attachment is
    precisely what makes CSRF possible. The header, in contrast, can only
    have been set by JavaScript that read the cookie, which a cross-site
    page cannot do (same-origin policy). Matching the two proves the
    request originated from a page that could read this site's cookies.

    The comparison uses hmac.compare_digest rather than `==` so a mismatch
    takes the same time regardless of where the strings first differ -
    an ordinary equality check would leak that position through response
    timing and turn the guard into an oracle for brute-forcing the token.
    """
    if request.method in SAFE_METHODS:
        return
    cookie = request.COOKIES.get(policy.csrf_name) or ""
    header = request.META.get(CSRF_HEADER) or ""
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise CSRFFailed("CSRF double-submit check failed")
