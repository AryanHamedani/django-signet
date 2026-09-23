from __future__ import annotations

from typing import Any

from django_signet.conf import setting
from django_signet.tokens.base import MintedToken, Token


class RefreshToken(Token):
    """Long-lived credential that redeems for a fresh pair. Never
    presented on an ordinary request - only to refresh, logout and
    logout-all - and its digest, never its raw value, is what a
    ``TokenStore`` persists.
    """

    typ = "refresh"
    lifetime = setting("REFRESH_TOKEN_LIFETIME")

    def mint(
        self,
        subject: str,
        *,
        family_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> MintedToken:
        """Same as :meth:`Token.mint`, but ``family_id`` is required: a
        refresh token with no ``sid`` could never be traced back to the
        family it belongs to, so minting one without it is a caller bug
        raised immediately rather than a token issued that can never be
        revoked as a group.
        """
        if family_id is None:
            raise ValueError("RefreshToken.mint() requires a family_id")
        return super().mint(subject, family_id=family_id, extra=extra)
