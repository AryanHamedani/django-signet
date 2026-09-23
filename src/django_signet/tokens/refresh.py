from __future__ import annotations

from typing import Any

from django_signet.conf import setting
from django_signet.tokens.base import MintedToken, Token


class RefreshToken(Token):
    typ = "refresh"
    lifetime = setting("REFRESH_TOKEN_LIFETIME")

    def mint(
        self,
        subject: str,
        *,
        family_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> MintedToken:
        if family_id is None:
            raise ValueError("RefreshToken.mint() requires a family_id")
        return super().mint(subject, family_id=family_id, extra=extra)
