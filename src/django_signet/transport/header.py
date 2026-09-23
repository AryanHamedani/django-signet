from __future__ import annotations

from typing import Any

from django_signet.exceptions import TransportError
from django_signet.transport.base import Transport
from django_signet.transport.cookie import CookiePolicy, CookieTransport


class HeaderTransport(Transport):
    """``Authorization: Bearer <token>``.

    For mobile and service-to-service clients, which never attach the
    header on their own - so this transport is never ambient and is never
    subject to CSRF.
    """

    def __init__(
        self, header: str = "HTTP_AUTHORIZATION", keyword: str = "Bearer"
    ) -> None:
        self.header = header
        self.keyword = keyword

    def _read(self, request: Any) -> str:
        raw: str = request.META.get(self.header, "")
        parts = raw.split()
        if len(parts) != 2 or parts[0] != self.keyword:
            raise TransportError("missing or malformed Authorization header")
        return parts[1]

    def extract_access(self, request: Any) -> str:
        return self._read(request)

    def extract_refresh(self, request: Any) -> str:
        return self._read(request)

    def attach(self, response: Any, pair: Any) -> None:
        response.data = {
            **(getattr(response, "data", None) or {}),
            "access": pair.access.value,
            "refresh": pair.refresh.value,
        }

    def clear(self, response: Any) -> None:
        _ = response  # nothing is stored client-side by this transport;
        # kept named `response` (not `_response`) to match the ABC and the
        # other two implementations - a caller may bind by keyword.


class HybridTransport(Transport):
    """A cookie transport that also *reads* a header for authentication.

    Extraction prefers the cookie and falls back to ``Authorization:
    Bearer``, so an authentication class using it accepts either. But every
    write goes to cookies: ``attach`` sets them, and nothing is returned in
    the body. That makes it **not** a transport for mobile or service
    clients - a header-based refresh through it consumes the presented
    refresh token and hands the successor back only in ``Set-Cookie``,
    which such a client never reads, so its session is lost. Use
    ``HeaderTransport`` (a header realm) for them. Full mobile support in
    hybrid is deferred to a later version.
    """

    def __init__(
        self,
        cookie: CookieTransport | None = None,
        header: HeaderTransport | None = None,
    ) -> None:
        self.cookie = cookie or CookieTransport()
        self.header = header or HeaderTransport()

    @property
    def is_ambient(self) -> bool:
        # A hybrid request *can* be authenticated ambiently, via the
        # cookie, so the CSRF check must not skip it outright. Whether a
        # given request actually took the ambient path is what
        # used_cookie() answers.
        return True

    @property
    def policy(self) -> CookiePolicy:
        """Delegate to the cookie half: only the cookie path is ambient, so
        the cookie policy is the one CSRF is issued and checked against."""
        return self.cookie.policy

    @property
    def cookie_policy(self) -> CookiePolicy:
        return self.cookie.policy

    def _try(self, name: str, request: Any) -> str:
        try:
            result: str = getattr(self.cookie, name)(request)
            return result
        except TransportError:
            result = getattr(self.header, name)(request)
            return result

    def extract_access(self, request: Any) -> str:
        return self._try("extract_access", request)

    def extract_refresh(self, request: Any) -> str:
        return self._try("extract_refresh", request)

    def used_cookie(self, request: Any) -> bool:
        """Which path authenticated this request. The CSRF check needs to
        know, because only the cookie path is ambient."""
        try:
            self.cookie.extract_access(request)
        except TransportError:
            return False
        return True

    def attach(self, response: Any, pair: Any) -> None:
        self.cookie.attach(response, pair)

    def clear(self, response: Any) -> None:
        self.cookie.clear(response)
