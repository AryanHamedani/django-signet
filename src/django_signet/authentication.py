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

        The active check mirrors Django's own
        ``ModelBackend.user_can_authenticate``: a missing ``is_active``
        attribute passes (some custom user models don't define it), but an
        explicit ``False`` is always rejected. Skipping this check is the
        exact CVE-2024-22513 regression - a disabled account must lose API
        access immediately, not merely once its outstanding access token
        expires on its own.
        """
        user_model = get_user_model()
        try:
            user = user_model.objects.get(pk=claims["sub"])
        except (user_model.DoesNotExist, KeyError, ValueError, TypeError) as exc:
            raise TokenInvalid("credential subject could not be resolved") from exc
        is_active = getattr(user, "is_active", None)
        if not (is_active or is_active is None):
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
        ``CookiePolicy``; ``Transport`` itself does not, and
        ``should_enforce_csrf`` only ever returns ``True`` when the
        transport is one of those two (``HeaderTransport.is_ambient`` is
        always ``False``). The ``isinstance`` check here is what lets
        static typing confirm that instead of assuming it.
        """
        if not self.should_enforce_csrf(request):
            return
        if isinstance(self.transport, CookieTransport | HybridTransport):
            validate_csrf(request, self.transport.policy)

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
