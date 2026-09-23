from __future__ import annotations

from typing import Any

from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django_signet.authentication import GENERIC_FAILURE, BaseJWTAuthentication
from django_signet.csrf import csrf_policy, issue_csrf, validate_csrf
from django_signet.exceptions import CSRFFailed, SignetError, TransportError
from django_signet.models import RevocationReason
from django_signet.serializers import TokenObtainSerializer
from django_signet.sessions.rotation import RotationPolicy
from django_signet.signals import send, token_issued, token_refreshed
from django_signet.transport.base import Transport
from django_signet.transport.cookie import CookieTransport
from django_signet.transport.header import HybridTransport


class SignetViewMixin:
    """Shared plumbing, and the unit of configuration: a *realm*.

    ``transport`` and ``rotation`` are class attributes so a subclass can
    swap either without touching project settings, and every hook below is
    a method a subclass can override. A subclass of this mixin, handed to
    :func:`django_signet.urls.signet_urls`, becomes all five endpoints at
    once - so login, refresh, verify and logout share one transport, one
    rotation policy and one ``get_claims``, and cannot drift apart.
    """

    transport: Transport = CookieTransport()
    rotation = RotationPolicy()
    #: Whether this request proved it came from our own origin - see
    #: :meth:`clear_cookies`. Per request: Django builds a fresh view
    #: instance for each one, so this never leaks between requests.
    origin_proven: bool = False

    def get_claims(self, user: Any) -> dict[str, Any]:
        """Extra claims to embed in both tokens. Reserved claims are ignored.

        Called at login and again on every refresh, with the user freshly
        loaded from the refresh token's subject - so a claim defined here
        survives rotation and tracks the user's current state. Login and
        refresh are separate views: define this once, on a class both
        share, or the two will disagree.
        """
        _ = user  # part of the overridable hook signature, unused by default
        return {}

    def get_response_data(self, user: Any, pair: Any) -> dict[str, Any]:
        """With cookie transport this deliberately contains no tokens."""
        _ = user, pair  # part of the overridable hook signature, unused by default
        return {"authenticated": True}

    def set_cookies(self, response: Any, pair: Any) -> None:
        """Write the pair through the transport, plus a CSRF cookie - but
        only for an ambient transport. A header credential cannot be
        forged cross-site, so it needs no CSRF token, and a transport that
        sets no cookies has no policy to issue one with."""
        self.transport.attach(response, pair)
        if self.transport.is_ambient:
            issue_csrf(
                response,
                csrf_policy(self.transport),
                expires=pair.refresh.expires_at,
            )

    def client_ip(self, request: Any) -> str | None:
        ip: str | None = request.META.get("REMOTE_ADDR")
        return ip

    def failure(self) -> Response:
        response = Response(
            {"detail": GENERIC_FAILURE}, status=status.HTTP_401_UNAUTHORIZED
        )
        self.clear_cookies(response)
        return response

    def clear_cookies(self, response: Any) -> None:
        """The one place a response deletes cookies, and the one rule for
        when: only once the request proved it came from our own origin.

        Under ``SameSite=Lax`` a cross-site top-level form POST carries
        none of the victim's cookies, but the browser still honours the
        ``Set-Cookie`` deletions in the response - so clearing on a
        request that presented nothing would let one forged POST log
        anyone out. :meth:`RefreshCredentialView.read_refresh_credential`
        sets ``origin_proven`` once a refresh credential is presented and,
        if it arrived ambiently, has passed the CSRF check; a header
        credential is proof in itself, since a cross-site page cannot set
        one. That keeps the dead-session loop-breaker - an invalid
        credential our own page sent is cleared - and nothing else.
        """
        if self.origin_proven:
            self.transport.clear(response)

    def csrf_failure(self) -> Response:
        """A failed double-submit check, not a bad credential.

        Deliberately does NOT call ``self.transport.clear(response)``. The
        caller may be holding a perfectly valid refresh token - only the
        CSRF proof failed - and clearing cookies here would turn a failed
        CSRF check into a logout oracle: a cross-site page could force a
        legitimate user's cookies to be wiped with a single unauthenticated
        POST, no token theft required. ``failure()`` clears cookies because
        an invalid/expired/reused *credential* genuinely can't be used
        again anyway; a missing or forged CSRF header says nothing about
        whether the credential itself is still good, so it must survive.
        403, not 401: this is a distinct, intentionally-observable signal
        from "no valid credential" - REST convention for "you're allowed to
        be here, but this specific safety check failed" - and every
        response body in this library already collapses to the same
        ``GENERIC_FAILURE`` string regardless of cause, so the status code
        alone carries no more information than "an authenticated write was
        blocked", not which check blocked it.
        """
        return Response({"detail": GENERIC_FAILURE}, status=status.HTTP_403_FORBIDDEN)


class TokenObtainView(SignetViewMixin, APIView):
    # Tuples, not lists: immutable, and Sequence[...] (the base class's
    # declared type) is happy with either - a list here would also trip
    # ruff's mutable-class-attribute check (RUF012), and annotating as
    # ClassVar to silence it would conflict with APIView's own (instance
    # -level) declaration of the same names.
    authentication_classes = ()
    permission_classes = (AllowAny,)
    # JSON only. A cross-site page can submit a form-encoded POST with no
    # preflight, but not application/json; accepting forms here allowed
    # login CSRF - logging a victim's browser into the attacker's account.
    parser_classes = (JSONParser,)
    serializer_class = TokenObtainSerializer

    def post(self, request: Any) -> Response:
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        pair = self.rotation.open_session(
            user,
            extra=self.get_claims(user),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            ip_address=self.client_ip(request),
        )
        response = Response(self.get_response_data(user, pair))
        self.set_cookies(response, pair)
        send(
            token_issued,
            sender=type(self),
            user=user,
            family=pair.family,
            request=request,
        )
        return response


class RefreshCredentialView(SignetViewMixin, APIView):
    """Base for the endpoints that act on the *refresh* credential:
    refresh, logout and logout-all.

    None of them authenticates through the access token. It lives five
    minutes and its cookie expires with it, so an endpoint that required
    it could not log out a session that had been idle for longer - and
    that is most sessions. The refresh credential is what keeps a session
    alive, so it is what these endpoints read, verify and act on; its
    cookie path defaults to the auth mount prefix so that it reaches all
    three.
    """

    authentication_classes = ()
    permission_classes = (AllowAny,)

    def refresh_is_ambient(self, request: Any) -> bool:
        """Whether *this* request's refresh credential arrived as a cookie
        the browser attached on its own, rather than a header the client
        set explicitly - the same ambient/non-ambient distinction
        ``BaseJWTAuthentication.should_enforce_csrf`` makes for the access
        token, applied here to the refresh token these views actually read.

        Not ``HybridTransport.used_cookie()``: that helper checks for the
        *access* cookie, which is what the authenticator's own CSRF
        decision needs. These views never touch the access token at all,
        so the right question is whether the refresh credential itself
        came from ``self.transport.cookie`` - checked directly rather than
        reusing a helper that would silently answer a different question.
        """
        transport = self.transport
        if isinstance(transport, HybridTransport):
            try:
                transport.cookie.extract_refresh(request)
            except TransportError:
                return False
            return True
        return transport.is_ambient

    def read_refresh_credential(self, request: Any) -> str:
        """The raw refresh token this request presents, CSRF-checked when it
        is ambient. The one implementation every refresh-credential
        endpoint uses.

        Raises ``TransportError`` when the request carries none, and
        ``CSRFFailed`` when it arrived ambiently without a matching
        double-submit pair. Ambient credentials are exactly what makes
        CSRF possible; a header a client set explicitly can't be forged by
        a third-party page the same way. The check runs before the token
        is used for anything: a request that fails it must not be able to
        consume - and thereby burn the grace window on, or trigger reuse
        detection against - a refresh token it was never entitled to
        present, nor revoke the session it names.
        """
        raw = self.transport.extract_refresh(request)
        if self.refresh_is_ambient(request):
            validate_csrf(request, csrf_policy(self.transport))
        self.origin_proven = True
        return raw

    def signed_out(self, detail: str) -> Response:
        response = Response({"detail": detail})
        self.clear_cookies(response)
        return response


class TokenRefreshView(RefreshCredentialView):
    def post(self, request: Any) -> Response:
        try:
            raw = self.read_refresh_credential(request)
        except CSRFFailed:
            return self.csrf_failure()
        except TransportError:
            return self.failure()

        try:
            pair = self.rotation.rotate(raw, get_claims=self.get_claims)
        except SignetError:
            # Covers invalid, expired, revoked and reused alike. The family
            # has already been burned by the policy where appropriate.
            return self.failure()

        response = Response(self.get_response_data(None, pair))
        self.set_cookies(response, pair)
        send(
            token_refreshed,
            sender=type(self),
            user=getattr(pair.family, "user", None),
            family=pair.family,
            request=request,
        )
        return response


class TokenVerifyView(SignetViewMixin, APIView):
    authentication_classes: tuple[type[BaseAuthentication], ...] = (
        BaseJWTAuthentication,
    )
    permission_classes = (IsAuthenticated,)

    def get_authenticators(self) -> list[BaseAuthentication]:
        """Every Signet authenticator this view lists is bound to the
        view's *own* transport, so verify reads exactly the credential this
        realm's login issued. ``authentication_classes`` still chooses the
        behaviour - ``StrictCookieJWTAuthentication`` for a liveness check,
        a subclass with its own ``validate_claims`` - but never a second,
        independently configured transport. A non-Signet authenticator is
        instantiated as DRF would.
        """
        return [
            auth(transport=self.transport)
            if issubclass(auth, BaseJWTAuthentication)
            else auth()
            for auth in self.authentication_classes
        ]

    def get(self, request: Any) -> Response:
        return Response({"authenticated": True, "user_id": request.user.pk})


class LogoutView(RefreshCredentialView):
    """Revoke the session the refresh credential names.

    Idempotent: with no credential, or one that no longer verifies, there
    is nothing to revoke and the answer is still success. Cookies are
    cleared whenever a credential was presented (and passed CSRF), so
    "log out" leaves the browser signed out; with none presented there is
    nothing to clear (see ``clear_cookies``).
    """

    reason = RevocationReason.LOGOUT

    def post(self, request: Any) -> Response:
        try:
            raw = self.read_refresh_credential(request)
        except CSRFFailed:
            return self.csrf_failure()
        except TransportError:
            return self.signed_out("Signed out.")
        try:
            self.rotation.revoke(raw, self.reason)
        except SignetError:
            # A cookie client is signed out by the clearing below whatever
            # its token's state. A header client has no cookies to clear,
            # so a credential that revoked nothing must not be reported as
            # a sign-out.
            if not self.refresh_is_ambient(request):
                return self.failure()
        return self.signed_out("Signed out.")


class LogoutAllView(RefreshCredentialView):
    """Revoke every session of the refresh credential's user.

    Unlike logout this needs a refresh token that redeems (see
    ``RotationPolicy.revoke_all``); without one it answers 401 - clearing
    the cookies only if a credential was presented (see
    ``clear_cookies``).
    """

    reason = RevocationReason.LOGOUT_ALL

    def post(self, request: Any) -> Response:
        try:
            raw = self.read_refresh_credential(request)
            self.rotation.revoke_all(raw, self.reason)
        except CSRFFailed:
            return self.csrf_failure()
        except SignetError:
            return self.failure()
        except NotImplementedError:
            # A cache-backed store cannot enumerate a user's families. Say so
            # plainly rather than surfacing a 500 for a documented limitation.
            return Response(
                {
                    "detail": "Logout-everywhere is not supported by the "
                    "configured token store."
                },
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )
        return self.signed_out("Signed out everywhere.")
