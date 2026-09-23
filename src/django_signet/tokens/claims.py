from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from django.utils import timezone

from django_signet.exceptions import TokenInvalid, TokenRevoked


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

    The reserved claims are built into their own dict and merged in last, via
    ``{**(extra or {}), **reserved}``. A later-dict key always wins a
    collision in that merge, so a reserved claim cannot be overwritten by
    ``extra`` no matter what it contains - this is structural, not a rule
    that a second "reserved names" list has to be kept in sync with. A
    caller cannot overwrite ``sub`` or ``exp`` through a custom
    ``get_claims`` hook.

    ``family_id``, ``audience`` and ``issuer`` are the exception: when one is
    ``None`` it is simply absent from ``reserved``, so an ``extra`` key of
    the same name survives untouched. That's intentional - those three are
    optional claims the library itself is declining to set, not reserved
    claims it is trying to protect.
    """
    now = timezone.now()
    expires_at = now + lifetime
    reserved: dict[str, Any] = {
        "sub": subject,
        "typ": typ,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if family_id is not None:
        reserved["sid"] = family_id
    if audience is not None:
        reserved["aud"] = audience
    if issuer is not None:
        reserved["iss"] = issuer

    claims: dict[str, Any] = {**(extra or {}), **reserved}
    return claims, expires_at


def session_id(claims: dict[str, Any]) -> uuid.UUID:
    """The session family a verified token names in its ``sid`` claim.

    Raises ``TokenRevoked`` when the claim is absent - a token that names
    no session cannot belong to a live one - and ``TokenInvalid`` when it
    is present but not a UUID. The one parser for ``sid``: the ``Strict*``
    liveness check and every refresh-credential revocation both use it.
    """
    sid = claims.get("sid")
    if not sid:
        raise TokenRevoked("token carries no session id")
    try:
        return uuid.UUID(str(sid))
    except ValueError as exc:
        raise TokenInvalid("token carries a malformed session id") from exc
