"""Resolve a token's subject to a user, failing closed.

The one definition of "may this subject still hold a credential?". Both
``BaseJWTAuthentication.get_user`` (every authenticated request) and
``RotationPolicy.get_user`` (every refresh) call :func:`get_active_user`,
so the CVE-2024-22513 rule - a disabled account keeps working - cannot be
fixed on one path and left open on the other. It was, once: the refresh
path never loaded the user at all, and minted fresh tokens for disabled
accounts.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from django_signet.exceptions import TokenInvalid, TokenRevoked

# Sentinel distinguishing "no is_active attribute at all" from an actual
# value, including a falsy one - getattr's own default can't do that,
# since None (or False) is a legitimate value we'd otherwise conflate
# with "not present".
_NO_IS_ACTIVE: Any = object()


def load_user(subject: Any) -> Any:
    """Look ``subject`` up by primary key, or raise ``TokenInvalid``.

    Every lookup failure collapses to the same exception, so no caller can
    turn a malformed ``sub`` into a 500 carrying the raw claim value in a
    debug traceback.
    """
    user_model = get_user_model()
    try:
        return user_model.objects.get(pk=subject)
    except (
        user_model.DoesNotExist,
        ValueError,
        TypeError,
        # What a UUID-keyed custom user model's UUIDField.get_prep_value()
        # raises for a `sub` that isn't a valid UUID.
        ValidationError,
    ) as exc:
        raise TokenInvalid("credential subject could not be resolved") from exc


def ensure_active(user: Any) -> Any:
    """Return ``user`` if it is active, else raise ``TokenRevoked``.

    This deliberately does NOT mirror Django's own
    ``ModelBackend.user_can_authenticate``, which treats a missing
    ``is_active`` attribute as active - safe there only because
    ``AbstractBaseUser`` guarantees the attribute exists. An auth library
    hardening against CVE-2024-22513 fails closed instead: a user model
    that doesn't define ``is_active`` at all is rejected, not silently
    trusted. Any conventional user model (anything deriving from
    ``AbstractBaseUser``/``AbstractUser``) is unaffected.
    """
    is_active = getattr(user, "is_active", _NO_IS_ACTIVE)
    if is_active is _NO_IS_ACTIVE:
        raise TokenRevoked("credential subject has no is_active attribute")
    if not is_active:
        raise TokenRevoked("credential subject is not active")
    return user


def get_active_user(subject: Any) -> Any:
    """:func:`load_user` then :func:`ensure_active`."""
    return ensure_active(load_user(subject))
