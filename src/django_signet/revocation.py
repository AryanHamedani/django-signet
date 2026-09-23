"""Password-change session revocation.

Wired as a ``pre_save`` receiver on the user model (see ``apps.py``), not
``post_save``: the previous password hash has to be read and compared
*before* Django overwrites the row, and ``pre_save`` is the last point at
which the outgoing row is still queryable independently of ``instance``.
"""

from __future__ import annotations

from typing import Any

from django_signet.models import RevocationReason


def revoke_on_password_change(sender: Any, instance: Any, **_kwargs: Any) -> None:
    """Revoke every session when a user's password changes.

    Access tokens already issued remain valid until they expire, which is the
    documented trade-off of stateless verification. Refresh is cut off at once,
    so the blast radius is one access-token lifetime.

    Two things this deliberately guards against:

    - A brand-new user (``instance.pk is None``) has no previous row to
      compare against and nothing to revoke, so it must be handled before
      any query is made - querying first would raise on every signup.
    - A save that does not touch the password (e.g. an unrelated profile
      edit) must not revoke anything, or every profile edit would log the
      user out everywhere. Only a genuine hash change triggers revocation.
    """
    if instance.pk is None:
        return
    try:
        previous = sender.objects.get(pk=instance.pk)
    except sender.DoesNotExist:
        return
    if previous.password == instance.password:
        return

    from django_signet.sessions.stores.orm import ORMTokenStore

    ORMTokenStore().revoke_all_for_user(instance, RevocationReason.PASSWORD_CHANGE)
