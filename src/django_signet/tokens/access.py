from __future__ import annotations

from django_signet.conf import setting
from django_signet.tokens.base import Token


class AccessToken(Token):
    typ = "access"
    lifetime = setting("ACCESS_TOKEN_LIFETIME")
