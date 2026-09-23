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
from django_signet.csrf import issue_csrf
from django_signet.exceptions import SignetError, TransportError
from django_signet.models import RevocationReason
from django_signet.serializers import TokenObtainSerializer
from django_signet.sessions.rotation import RotationPolicy
from django_signet.signals import token_issued, token_refreshed
from django_signet.transport.cookie import CookieTransport


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

    def post(self, request: Any) -> Response:
        try:
            raw = self.transport.extract_refresh(request)
        except TransportError:
            return self.failure()
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
