from __future__ import annotations

from django_signet.conf import setting
from django_signet.tokens.base import Token


class AccessToken(Token):
    """Short-lived, presented on every authenticated request. Carries
    ``sid`` so a ``Strict*`` authentication class can check the session
    family is still live without touching the refresh token.
    """

    typ = "access"
    lifetime = setting("ACCESS_TOKEN_LIFETIME")
