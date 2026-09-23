from __future__ import annotations

from typing import Any

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django_signet.authentication import (
    GENERIC_FAILURE,
    CookieJWTAuthentication,
)
from django_signet.csrf import issue_csrf, validate_csrf
from django_signet.exceptions import CSRFFailed, SignetError, TransportError
from django_signet.models import RevocationReason
from django_signet.serializers import TokenObtainSerializer
from django_signet.sessions.rotation import RotationPolicy
from django_signet.signals import token_issued, token_refreshed
from django_signet.transport.cookie import CookieTransport
from django_signet.transport.header import HybridTransport


class SignetViewMixin:
    """Shared plumbing. ``transport`` and ``rotation`` are class attributes so
    a subclass can swap either without touching project settings."""

    transport = CookieTransport()
    rotation = RotationPolicy()

    def get_claims(self, user: Any) -> dict[str, Any]:
        """Extra claims to embed in both tokens. Reserved claims are ignored."""
        _ = user  # part of the overridable hook signature, unused by default
        return {}

    def get_response_data(self, user: Any, pair: Any) -> dict[str, Any]:
        """With cookie transport this deliberately contains no tokens."""
        _ = user, pair  # part of the overridable hook signature, unused by default
        return {"authenticated": True}

    def set_cookies(self, response: Any, pair: Any) -> None:
        self.transport.attach(response, pair)
        issue_csrf(response, self.transport.policy)

    def client_ip(self, request: Any) -> str | None:
        ip: str | None = request.META.get("REMOTE_ADDR")
        return ip

    def failure(self) -> Response:
        response = Response(
            {"detail": GENERIC_FAILURE}, status=status.HTTP_401_UNAUTHORIZED
        )
        self.transport.clear(response)
        return response

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
        token_issued.send(
            sender=type(self), user=user, family=pair.family, request=request
        )
        return response


class TokenRefreshView(SignetViewMixin, APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)

    def refresh_is_ambient(self, request: Any) -> bool:
        """Whether *this* request's refresh credential arrived as a cookie
        the browser attached on its own, rather than a header the client
        set explicitly - the same ambient/non-ambient distinction
        ``BaseJWTAuthentication.should_enforce_csrf`` makes for the access
        token, applied here to the refresh token this view actually reads.

        Not ``HybridTransport.used_cookie()``: that helper checks for the
        *access* cookie, which is what the authenticator's own CSRF
        decision needs. This view never touches the access token at all,
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

    def post(self, request: Any) -> Response:
        try:
            raw = self.transport.extract_refresh(request)
        except TransportError:
            return self.failure()

        # Ambient credentials (a cookie the browser attaches on its own)
        # are exactly what makes CSRF possible; a header a client set
        # explicitly can't be forged by a third-party page the same way.
        # This runs before the token is ever redeemed: a request that
        # fails this check must not be able to consume - and thereby burn
        # the grace window on, or trigger reuse detection against - a
        # refresh token it was never entitled to present.
        if self.refresh_is_ambient(request):
            try:
                validate_csrf(request, self.transport.policy)
            except CSRFFailed:
                return self.csrf_failure()

        try:
            pair = self.rotation.rotate(raw)
        except SignetError:
            # Covers invalid, expired, revoked and reused alike. The family
            # has already been burned by the policy where appropriate.
            return self.failure()

        response = Response(self.get_response_data(None, pair))
        self.set_cookies(response, pair)
        token_refreshed.send(
            sender=type(self),
            user=getattr(pair.family, "user", None),
            family=pair.family,
            request=request,
        )
        return response


class TokenVerifyView(SignetViewMixin, APIView):
    authentication_classes = (CookieJWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request: Any) -> Response:
        return Response({"authenticated": True, "user_id": request.user.pk})


class LogoutView(SignetViewMixin, APIView):
    authentication_classes = (CookieJWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    reason = RevocationReason.LOGOUT

    def post(self, request: Any) -> Response:
        family_id = request.auth.get("sid") if request.auth else None
        if family_id:
            self.rotation.store.revoke_family(family_id, self.reason)
        response = Response({"detail": "Signed out."})
        self.transport.clear(response)
        return response


class LogoutAllView(SignetViewMixin, APIView):
    authentication_classes = (CookieJWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    reason = RevocationReason.LOGOUT_ALL

    def post(self, request: Any) -> Response:
        try:
            self.rotation.store.revoke_all_for_user(request.user, self.reason)
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
        response = Response({"detail": "Signed out everywhere."})
        self.transport.clear(response)
        return response
