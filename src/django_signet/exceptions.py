class SignetError(Exception):
    """Base for every internal Signet failure.

    None reaches the client as itself. The authentication classes turn
    every one into the same generic ``AuthenticationFailed``, so an
    authenticated request's response never discloses which check failed.
    The refresh, logout and logout-all views answer with status codes of
    their own instead: 403 for ``CSRFFailed`` and the generic 401 for a bad
    credential, except that logout answers 200 for a cookie credential it
    cannot revoke (see ``LogoutView``).
    """


class TokenInvalid(SignetError):
    """Malformed, tampered, or wrongly-signed token."""


class TokenExpired(SignetError):
    """Structurally valid but past its expiry."""


class TokenRevoked(SignetError):
    """Belongs to a family that has been revoked."""


class TokenReused(SignetError):
    """A consumed refresh token was replayed outside the grace window."""


class CSRFFailed(SignetError):
    """Cookie-authenticated unsafe request failed the double-submit check."""


class TransportError(SignetError):
    """No token present, or the transport could not read it."""
