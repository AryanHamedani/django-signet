from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from django.utils import timezone

RESERVED = frozenset({"sub", "typ", "jti", "iat", "nbf", "exp", "aud", "iss", "sid"})


def build_claims(
    *,
    subject: str,
    typ: str,
    lifetime: timedelta,
    family_id: str | None = None,
    audience: str | None = None,
    issuer: str | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], datetime]:
    """Build a claim set. Returns ``(claims, expires_at)``.

    ``extra`` is merged first so reserved claims always win - a caller cannot
    overwrite ``sub`` or ``exp`` through a custom ``get_claims`` hook.
    """
    now = timezone.now()
    expires_at = now + lifetime
    claims: dict[str, Any] = dict(extra or {})
    for key in RESERVED & claims.keys():
        del claims[key]
    claims.update(
        {
            "sub": subject,
            "typ": typ,
            "jti": str(uuid.uuid4()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
    )
    if family_id is not None:
        claims["sid"] = family_id
    if audience is not None:
        claims["aud"] = audience
    if issuer is not None:
        claims["iss"] = issuer
    return claims, expires_at
