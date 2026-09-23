"""DRF authentication classes: cookie, header, and hybrid access-token auth.

``BaseJWTAuthentication.authenticate()`` is the one place three ideas meet:
DRF's absence-vs-failure contract, a single generic failure message
regardless of cause, and the strict/non-strict trade-off between a
stateless access-token check and one that also asserts the session family
is still live. See the class docstring for how the hooks fit together.
"""

from __future__ import annotations

import uuid
from typing import Any

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from django_signet.csrf import validate_csrf
from django_signet.exceptions import (
    SignetError,
    TokenInvalid,
    TokenRevoked,
    TransportError,
)
from django_signet.sessions.stores.base import TokenStore
from django_signet.sessions.stores.orm import ORMTokenStore
from django_signet.tokens.access import AccessToken
from django_signet.tokens.base import Token
from django_signet.transport.base import Transport
from django_signet.transport.cookie import CookieTransport
from django_signet.transport.header import HeaderTransport, HybridTransport

# One message for every failure, whatever the cause. A reviewer greps this
# string across the test suite - it must never vary with what actually
# went wrong, or the client learns which check failed.
GENERIC_FAILURE = "Invalid or expired credentials."

# Sentinel distinguishing "no is_active attribute at all" from an actual
# value, including a falsy one - getattr's own default can't do that,
# since None (or False) is a legitimate value we'd otherwise conflate
# with "not present".
_NO_IS_ACTIVE: Any = object()


class BaseJWTAuthentication(BaseAuthentication):
    """Template Method: ``authenticate()`` owns the fixed sequence -
    extract, verify, (maybe) CSRF, (maybe) family liveness, application
    claims, user lookup - and subclasses only swap the transport and the
    strictness. Override the hooks below, not ``authenticate()`` itself.

    Two invariants hold for every subclass:

    1. Absence is not failure. A ``TransportError`` from ``get_token``
       means "this request carries none of my credential", so
       ``authenticate()`` returns ``None`` and lets DRF try the next
       authenticator - never ``AuthenticationFailed``.
    2. One failure message. Every other ``SignetError`` - a bad signature,
       an expired or revoked token, a failed CSRF check, an inactive user -
       collapses to the same ``AuthenticationFailed(GENERIC_FAILURE)``. The
       distinct exception types exist for ``on_authentication_failed`` and
       the signal layer, never for the client.
    """

    transport: Transport = CookieTransport()
    token_class: type[Token] = AccessToken
    store: TokenStore = ORMTokenStore()
    strict: bool = False
    enforce_csrf: bool = True

    # ------------------------------------------------------------- template

    def authenticate(self, request: Any) -> tuple[Any, dict[str, Any]] | None:
        try:
            raw = self.get_token(request)
        except TransportError:
            # DRF's contract for "not my scheme": let another authenticator
            # try, rather than failing the request outright.
            return None

        try:
            claims = self.token_class().verify(raw)
            self._enforce_csrf_if_needed(request)
            if self.strict:
                self.check_family(claims)
            self.validate_claims(claims)
            user = self.get_user(claims)
        except SignetError as exc:
            self.on_authentication_failed(exc)
            raise AuthenticationFailed(GENERIC_FAILURE) from None
        return (user, claims)

    def authenticate_header(self, request: Any) -> str:
        _ = request  # required by BaseAuthentication's signature, unused here
        return 'Bearer realm="api"'

    # ---------------------------------------------------------------- hooks

    def get_token(self, request: Any) -> str:
        """Pull the raw access token off the wire. Raise
        ``TransportError`` - never anything else - to signal absence."""
        return self.transport.extract_access(request)

    def get_user(self, claims: dict[str, Any]) -> Any:
        """Resolve ``claims['sub']`` to a user and reject an inactive one.

        This deliberately does NOT mirror Django's own
        ``ModelBackend.user_can_authenticate``, which treats a missing
        ``is_active`` attribute as active - safe there only because
        ``AbstractBaseUser`` guarantees the attribute exists. This is an
        auth *library* whose job includes hardening against
        CVE-2024-22513 - "disabled accounts keep working" - so it fails
        closed instead: a user model that doesn't define ``is_active`` at
        all is rejected, not silently trusted. Any conventional user model
        (anything deriving from ``AbstractBaseUser``/``AbstractUser``) is
        unaffected, since it always has the attribute.
        """
        user_model = get_user_model()
        try:
            user = user_model.objects.get(pk=claims["sub"])
        except (
            user_model.DoesNotExist,
            KeyError,
            ValueError,
            TypeError,
            # What a UUID-keyed custom user model's UUIDField.get_prep_value()
            # raises for a `sub` that isn't a valid UUID - without this, a
            # malformed subject on such a model is an unhandled 500 with the
            # raw claim value in a debug traceback, not the generic 401
            # every other bad-credential cause here produces.
            ValidationError,
        ) as exc:
            raise TokenInvalid("credential subject could not be resolved") from exc

        is_active = getattr(user, "is_active", _NO_IS_ACTIVE)
        if is_active is _NO_IS_ACTIVE:
            raise TokenRevoked("credential subject has no is_active attribute")
        if not is_active:
            raise TokenRevoked("credential subject is not active")
        return user

    def validate_claims(self, claims: dict[str, Any]) -> None:
        """Override to enforce application-specific claims (tenant, scope,
        anything beyond what ``Token.verify`` already checked). Raise any
        ``SignetError`` to reject - it is folded into the same generic
        response as every other failure here."""

    def on_authentication_failed(self, exc: SignetError) -> None:
        """Observability hook: log, alert, fire a signal. Whatever this
        does, the client still receives ``GENERIC_FAILURE`` regardless -
        this hook can react to the failure, never change the response."""

    # ------------------------------------------------------------- internals

    def should_enforce_csrf(self, request: Any) -> bool:
        """CSRF only matters for a credential the browser attached on its
        own (see ``Transport.is_ambient``) - a header credential a client
        set explicitly can't be forged by a third-party page the way an
        ambient cookie can.

        ``HybridTransport`` can authenticate either way on the very same
        class, so ``is_ambient`` alone isn't enough for it: only ask for
        CSRF when *this* request actually took the cookie path.
        """
        if not self.enforce_csrf or not self.transport.is_ambient:
            return False
        if isinstance(self.transport, HybridTransport):
            return self.transport.used_cookie(request)
        return True

    def _enforce_csrf_if_needed(self, request: Any) -> None:
        """Run the double-submit check when ``should_enforce_csrf`` says
        to. Split out from that method - rather than reading
        ``self.transport.policy`` there directly - because only
        ``CookieTransport`` and ``HybridTransport`` carry a
        ``CookiePolicy``; ``Transport`` itself does not. In this codebase
        ``should_enforce_csrf`` only ever returns ``True`` for one of
        those two (``HeaderTransport.is_ambient`` is always ``False``),
        and the ``isinstance`` check here is what lets static typing
        confirm that instead of assuming it.

        A third-party ``Transport`` could in principle be ambient without
        being either of those two - and if ``should_enforce_csrf`` says a
        request needs CSRF enforcement, that decision must never be
        silently dropped just because this method doesn't know how to
        carry it out. The ``else`` branch below turns that combination
        into a loud ``NotImplementedError`` instead of an unenforced
        credential: a live security check that got skipped without a
        trace is worse than one that breaks the request outright.
        """
        if not self.should_enforce_csrf(request):
            return
        if isinstance(self.transport, CookieTransport | HybridTransport):
            validate_csrf(request, self.transport.policy)
            return
        raise NotImplementedError(
            f"{type(self.transport).__name__}.is_ambient is True, so "
            "should_enforce_csrf() requires a CSRF check, but this "
            "transport carries no CookiePolicy for _enforce_csrf_if_needed() "
            "to validate against. Give it a `.policy` (a CookiePolicy) or "
            "override should_enforce_csrf()/_enforce_csrf_if_needed() to "
            "handle it explicitly - do not let CSRF go silently unchecked."
        )

    def check_family(self, claims: dict[str, Any]) -> None:
        """The ``Strict*`` half of the trade-off: one store lookup to
        confirm the session family named by ``sid`` is still live, so a
        revoked session stops authenticating immediately rather than only
        once its still-valid access token expires on its own."""
        sid = claims.get("sid")
        if not sid:
            raise TokenRevoked("token carries no session id")
        try:
            family_id = uuid.UUID(str(sid))
        except ValueError as exc:
            raise TokenInvalid("token carries a malformed session id") from exc
        if not self.store.is_live(family_id):
            raise TokenRevoked("session is no longer live")


class HeaderJWTAuthentication(BaseJWTAuthentication):
    """``Authorization: Bearer <token>``. Never ambient, so CSRF never
    applies (see ``should_enforce_csrf``)."""

    transport = HeaderTransport()


class CookieJWTAuthentication(BaseJWTAuthentication):
    """``Secure``/``HttpOnly`` cookie. Always ambient, so every unsafe
    request must carry a matching CSRF double-submit pair."""

    transport = CookieTransport()


class HybridJWTAuthentication(BaseJWTAuthentication):
    """Cookie first, header fallback. CSRF is enforced only when this
    particular request actually authenticated via the cookie."""

    transport = HybridTransport()


class StrictHeaderJWTAuthentication(HeaderJWTAuthentication):
    """Adds a family-liveness check to :class:`HeaderJWTAuthentication`."""

    strict = True


class StrictCookieJWTAuthentication(CookieJWTAuthentication):
    """Adds a family-liveness check to :class:`CookieJWTAuthentication`."""

    strict = True


class StrictHybridJWTAuthentication(HybridJWTAuthentication):
    """Adds a family-liveness check to :class:`HybridJWTAuthentication`."""

    strict = True
