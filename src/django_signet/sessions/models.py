from __future__ import annotations

import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models
from django.utils import timezone

from django_signet.signals import family_revoked, send


class RevocationReason(models.TextChoices):
    LOGOUT = "logout", "Logout"
    LOGOUT_ALL = "logout_all", "Logout everywhere"
    REUSE_DETECTED = "reuse_detected", "Refresh token reuse detected"
    PASSWORD_CHANGE = "password_change", "Password changed"
    EXPIRED = "expired", "Expired"
    ADMIN = "admin", "Revoked by an administrator"


class TokenFamily(models.Model):
    """One login session. Every rotation stays inside the same family, so
    replaying a consumed token lets us burn the whole lineage at once."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="signet_families",
        on_delete=models.CASCADE,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    revoked_reason = models.CharField(
        max_length=32, null=True, blank=True, choices=RevocationReason.choices
    )
    user_agent = models.CharField(max_length=256, blank=True, default="")
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        verbose_name_plural = "token families"
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["user", "revoked_at"])
        ]

    def __str__(self) -> str:
        return f"TokenFamily({self.id})"

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()

    def revoke(self, reason: str) -> None:
        """Idempotent: the first reason recorded is the one that sticks, so a
        later routine logout cannot mask an earlier security event.

        The guard has to be a single conditional ``UPDATE``, not a check on
        ``self.revoked_at`` followed by an unconditional save: two instances
        of the same row loaded before either was revoked would both pass an
        in-memory check, and the second write would silently replace a
        recorded security incident. ``WHERE revoked_at IS NULL`` lets the
        database - not this process - decide which caller wins.
        """
        now = timezone.now()
        updated = TokenFamily.objects.filter(
            pk=self.pk, revoked_at__isnull=True
        ).update(revoked_at=now, revoked_reason=reason)
        if not updated:
            return
        self.revoked_at = now
        self.revoked_reason = reason
        send(
            family_revoked,
            sender=type(self),
            user=self.user,
            family=self,
            reason=reason,
        )


class IssuedToken(models.Model):
    """A single refresh token, stored only as a digest - never the raw
    value. ``digest`` is a SHA-256 hex digest (see ``hashing.token_digest``);
    there is nowhere in this model that a live credential could be written."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    family = models.ForeignKey(
        TokenFamily, related_name="tokens", on_delete=models.CASCADE
    )
    digest = models.CharField(max_length=64, unique=True, db_index=True)
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    consumed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"IssuedToken({self.id})"
