from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django_signet.conf import setting
from django_signet.exceptions import TokenInvalid
from django_signet.tokens.backends import SigningBackend, get_backend
from django_signet.tokens.claims import build_claims


@dataclass(frozen=True)
class MintedToken:
    """A freshly signed token and the metadata about it.

    ``value`` is the raw, live credential; ``claims`` duplicates it (``sub``,
    ``sid``, etc.). Neither belongs in a log line or an exception traceback,
    so both are excluded from the generated ``__repr__`` - a stray
    ``logger.info(minted)`` prints the object's identity, not the secret.
    """

    value: str = field(repr=False)
    jti: str
    expires_at: datetime
    claims: dict[str, Any] = field(repr=False)


class Token(abc.ABC):
    """Base for every token flavour.

    Subclasses set ``typ`` and ``lifetime``. ``typ`` is verified on decode,
    which is what stops a refresh token being replayed as an access token.
    """

    typ: str
    lifetime: timedelta

    audience = setting("AUDIENCE")
    issuer = setting("ISSUER")
    leeway = setting("LEEWAY")

    def get_backend(self) -> SigningBackend:
        """The signing backend named by the project's ``SIGNET`` settings.
        Resolved afresh on every call, like every other ``setting()``-backed
        value, so ``override_settings`` works in tests.
        """
        return get_backend()

    def mint(
        self,
        subject: str,
        *,
        family_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> MintedToken:
        """Build and sign a fresh token for ``subject``.

        ``family_id`` becomes the ``sid`` claim when given;
        :meth:`RefreshToken.mint <django_signet.tokens.refresh.RefreshToken.mint>`
        requires it. ``extra`` is merged in under the reserved claims -
        see :func:`django_signet.tokens.claims.build_claims` for why a
        reserved claim can never be overwritten by it.
        """
        claims, expires_at = build_claims(
            subject=subject,
            typ=self.typ,
            lifetime=self.lifetime,
            family_id=family_id,
            audience=self.audience,
            issuer=self.issuer,
            extra=extra,
        )
        return MintedToken(
            value=self.get_backend().sign(claims),
            jti=claims["jti"],
            expires_at=expires_at,
            claims=claims,
        )

    def verify(self, raw: str) -> dict[str, Any]:
        """Decode, then check this is the right token flavour and every
        required claim is present, raising ``TokenInvalid``/``TokenExpired``
        (never a bare ``KeyError`` or a crypto-library exception) for
        anything wrong. ``typ`` is what stops a refresh token being
        replayed as an access token.
        """
        claims = self.get_backend().verify(
            raw, audience=self.audience, issuer=self.issuer, leeway=self.leeway
        )
        if claims.get("typ") != self.typ:
            raise TokenInvalid(f"expected typ={self.typ!r}, got {claims.get('typ')!r}")
        # The signing backend's `require` option only demands `exp` - a
        # correctly-signed token missing `sub` or `jti` passes the crypto
        # layer intact and would otherwise reach a caller as a KeyError (a
        # 500) rather than a failed credential (a 401). Close that here,
        # where `typ` is already being checked.
        if "sub" not in claims or "jti" not in claims:
            raise TokenInvalid("token is missing required claims")
        return claims
