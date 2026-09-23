"""DRF authentication classes: cookie, header, and hybrid access-token auth.

``BaseJWTAuthentication.authenticate()`` is the one place three ideas meet:
DRF's absence-vs-failure contract, a single generic failure message
regardless of cause, and the strict/non-strict trade-off between a
stateless access-token check and one that also asserts the session family
is still live. See the class docstring for how the hooks fit together.
"""

from __future__ import annotations

from typing import Any

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

from django_signet.csrf import csrf_policy, validate_csrf
from django_signet.exceptions import (
    CSRFFailed,
    SignetError,
    TokenRevoked,
    TransportError,
)
from django_signet.sessions.stores.factory import ConfiguredStore
from django_signet.tokens.access import AccessToken
from django_signet.tokens.base import Token
from django_signet.tokens.claims import session_id
from django_signet.transport.base import Transport
from django_signet.transport.cookie import CookieTransport
from django_signet.transport.header import HeaderTransport, HybridTransport
from django_signet.users import get_active_user

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
       distinct exception types exist for ``on_authentication_failed``,
       never for the client. No signal is sent on a failure.
    """

    transport: Transport = CookieTransport()
    token_class: type[Token] = AccessToken
    store = ConfiguredStore()  # the configured SIGNET["STORE"]; see get_store()
    strict: bool = False
    enforce_csrf: bool = True

    def __init__(self, transport: Transport | None = None) -> None:
        """DRF instantiates authentication classes with no arguments, so the
        class attribute is the default. A view passes its own ``transport``
        (see ``TokenVerifyView.get_authenticators``) so that it verifies
        exactly the credential it issues - never a second, independently
        configured copy of it."""
        super().__init__()
        if transport is not None:
            self.transport = transport

    # ------------------------------------------------------------- template

    def authenticate(self, request: Any) -> tuple[Any, dict[str, Any]] | None:
        """The fixed sequence: extract, verify, (maybe) CSRF, (maybe)
        family liveness, application claims, user lookup. See the class
        docstring for the two invariants this method enforces - never
        override it directly; override the hooks instead.
        """
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
        except CSRFFailed as exc:
            # 403, not 401, as DRF's SessionAuthentication and this
            # library's own refresh and logout views answer it: the access
            # token verified, so a 401 would send the client to refresh a
            # session that is fine and hide the real fault - a missing or
            # wrong CSRF header. The body stays GENERIC_FAILURE, and the
            # check runs after verify, so only the token's holder learns
            # anything from the status.
            self.on_authentication_failed(exc)
            raise PermissionDenied(GENERIC_FAILURE) from None
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

        Delegates to :func:`django_signet.users.get_active_user`, the same
        function the refresh path uses, so a disabled account is refused
        identically whether it presents an access token here or a refresh
        token to ``RotationPolicy.rotate``. See that module for why a user
        model with no ``is_active`` attribute at all fails closed.
        """
        return get_active_user(claims.get("sub"))

    def validate_claims(self, claims: dict[str, Any]) -> None:
        """Override to enforce application-specific claims (tenant, scope,
        anything beyond what ``Token.verify`` already checked). Raise any
        ``SignetError`` to reject - it is folded into the same generic
        response as every other failure here."""

    def on_authentication_failed(self, exc: SignetError) -> None:
        """Observability hook: log, alert, fire a signal of your own - the
        library sends none on a failure. Called with the ``SignetError``
        before ``AuthenticationFailed(GENERIC_FAILURE)`` is raised; when
        the hook returns normally the client receives that generic failure
        whatever the cause. An exception the hook raises propagates in its
        place."""

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
        to, against the transport's own cookie policy. ``csrf_policy``
        raises ``NotImplementedError`` for an ambient transport that has
        none: a CSRF decision must never be silently dropped just because
        there is nothing to validate it against.
        """
        if self.should_enforce_csrf(request):
            validate_csrf(request, csrf_policy(self.transport))

    def check_family(self, claims: dict[str, Any]) -> None:
        """The ``Strict*`` half of the trade-off: one store lookup to
        confirm the session family named by ``sid`` is still live, so a
        revoked session stops authenticating immediately rather than only
        once its still-valid access token expires on its own."""
        family_id = session_id(claims)
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
