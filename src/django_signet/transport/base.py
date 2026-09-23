from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from django_signet.transport.cookie import CookiePolicy


class Transport(abc.ABC):
    """Moves tokens between the library and the wire.

    Deliberately knows nothing about storage or auth: every method here
    trades in raw strings and loosely-typed request/response objects, never
    a :class:`SessionPair <django_signet.sessions.rotation.SessionPair>` or
    a store. Importing either would cross the architectural boundary
    ``lint-imports`` enforces - transport moves bytes, nothing more.
    """

    @abc.abstractmethod
    def extract_access(self, request: Any) -> str:
        """Return the raw access token, or raise ``TransportError``."""

    @abc.abstractmethod
    def extract_refresh(self, request: Any) -> str:
        """Return the raw refresh token, or raise ``TransportError``."""

    @abc.abstractmethod
    def attach(self, response: Any, pair: Any) -> None:
        """Write a freshly minted pair onto ``response``.

        ``pair`` is typed loosely on purpose - see the class docstring.
        """

    @abc.abstractmethod
    def clear(self, response: Any) -> None:
        """Remove any credential this transport attached, e.g. on logout."""

    @property
    def is_ambient(self) -> bool:
        """True when the browser attaches the credential automatically.

        Ambient credentials are what make CSRF possible, so the CSRF check
        keys off this rather than off the class name.
        """
        return False

    @property
    def cookie_policy(self) -> CookiePolicy | None:
        """The cookie naming and flags this transport writes with, or
        ``None`` for a transport that sets no cookies.

        Everything that needs a policy - issuing and validating the CSRF
        cookie, the refresh-path system check - asks this, polymorphically,
        instead of assuming every transport has one. That assumption once
        made ``HeaderTransport`` on a login view a 500.
        """
        return None
