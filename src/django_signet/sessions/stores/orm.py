from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, cast

from django.utils import timezone

from django_signet.models import IssuedToken, TokenFamily
from django_signet.sessions.stores.base import (
    ConsumeResult,
    FamilyLike,
    Outcome,
    TokenStore,
)


class ORMTokenStore(TokenStore):
    """Default store. Allowlist semantics: a family must exist and be live.

    ``consume()`` is classify-then-claim rather than the
    ``select_for_update()``-in-a-transaction shape one might reach for
    first. ``select_for_update()`` is a no-op on SQLite - a deferred
    transaction lets two concurrent callers both observe
    ``consumed_at IS NULL`` and both proceed, which makes reuse detection
    silently unreliable on exactly the backend this project tests against.
    A conditional ``UPDATE ... WHERE consumed_at IS NULL`` is atomic on
    every backend and needs no row locking: the database, not this
    process, decides which caller's write wins.
    """

    def open_family(
        self,
        user: Any,
        expires_at: datetime,
        *,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> TokenFamily:
        return TokenFamily.objects.create(
            user=user,
            expires_at=expires_at,
            user_agent=user_agent[:256],
            ip_address=ip_address,
        )

    def issue(
        self, family: FamilyLike, digest: str, expires_at: datetime
    ) -> IssuedToken:
        # The ABC only promises FamilyLike - any structurally-compatible
        # object, in principle from any TokenStore's open_family(). This
        # store only ever passes its own real TokenFamily instances
        # through this port in practice (mixing stores mid-family is a
        # caller bug the type system can't catch either way), and the FK
        # assignment below needs the concrete model, not just the
        # protocol's shape.
        return IssuedToken.objects.create(
            family=cast(TokenFamily, family), digest=digest, expires_at=expires_at
        )

    def consume(self, digest: str) -> ConsumeResult:
        try:
            token = IssuedToken.objects.select_related("family").get(digest=digest)
        except IssuedToken.DoesNotExist:
            return ConsumeResult(Outcome.NOT_FOUND)

        family = token.family
        now = timezone.now()
        if family.revoked_at is not None:
            return ConsumeResult(Outcome.FAMILY_REVOKED, family, token)
        if token.expires_at <= now or family.expires_at <= now:
            return ConsumeResult(Outcome.EXPIRED, family, token)

        return self._claim(token, family, now)

    def _claim(
        self, token: IssuedToken, family: TokenFamily, now: datetime
    ) -> ConsumeResult:
        """The atomic step: claim the token if, and only if, the database
        still shows it unconsumed *and* its family still unrevoked at write
        time. Both are re-checked in the same conditional UPDATE, not just
        ``consumed_at`` - otherwise a revocation landing between classify
        and claim (e.g. a sibling token's reuse burning this family) would
        still let this token be claimed and reported LIVE, undercutting the
        instant-revocation guarantee burning a family exists to provide.

        A zero-row result is now ambiguous by construction - already
        consumed, or the family was just revoked - so it is resolved with
        one extra read. That only runs on the rare, already-contended
        path."""
        claimed = IssuedToken.objects.filter(
            pk=token.pk,
            consumed_at__isnull=True,
            family__revoked_at__isnull=True,
        ).update(consumed_at=now)
        if not claimed:
            return self._resolve_claim_conflict(token, family)

        token.consumed_at = now
        TokenFamily.objects.filter(pk=family.pk).update(last_used_at=now)
        return ConsumeResult(Outcome.LIVE, family, token)

    def _resolve_claim_conflict(
        self, token: IssuedToken, family: TokenFamily
    ) -> ConsumeResult:
        """Only reached when the conditional UPDATE in ``_claim`` affected
        zero rows. Re-read the family to tell the two possible causes
        apart: they trigger different behaviour upstream (FAMILY_REVOKED
        does not burn the family again; ALREADY_CONSUMED does)."""
        fresh_family = TokenFamily.objects.get(pk=family.pk)
        if fresh_family.revoked_at is not None:
            return ConsumeResult(Outcome.FAMILY_REVOKED, fresh_family, token)
        return ConsumeResult(Outcome.ALREADY_CONSUMED, fresh_family, token)

    def is_live(self, family_id: uuid.UUID) -> bool:
        return TokenFamily.objects.filter(
            pk=family_id, revoked_at__isnull=True, expires_at__gt=timezone.now()
        ).exists()

    def revoke_family(self, family_id: uuid.UUID, reason: str) -> None:
        try:
            family = TokenFamily.objects.get(pk=family_id)
        except TokenFamily.DoesNotExist:
            return
        family.revoke(reason)

    def revoke_all_for_user(self, user: Any, reason: str) -> None:
        """Each ``revoke()`` call is already an atomic, idempotent
        conditional UPDATE (see ``TokenFamily.revoke``), so no additional
        locking is needed here - and, per the same reasoning that rules out
        ``select_for_update()`` in ``consume()``, one would not help on
        SQLite anyway."""
        for family in TokenFamily.objects.filter(user=user, revoked_at__isnull=True):
            family.revoke(reason)

    def purge_expired(self) -> int:
        qs = TokenFamily.objects.filter(expires_at__lte=timezone.now())
        count = qs.count()
        qs.delete()
        return count
