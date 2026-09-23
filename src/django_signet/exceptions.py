class SignetError(Exception):
    """Base for every internal Signet failure.

    These never reach the client. The DRF surface catches them and raises a
    generic ``AuthenticationFailed`` so no response discloses which check failed.
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
