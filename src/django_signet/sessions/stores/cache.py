from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.cache import caches
from django.utils import timezone

from django_signet.sessions.stores.base import (
    ConsumeResult,
    FamilyLike,
    Outcome,
    TokenLike,
    TokenStore,
)
from django_signet.signals import family_revoked, send

if TYPE_CHECKING:
    from django.core.cache.backends.base import BaseCache

_FAMILY = "signet:fam:{}"
_TOKEN = "signet:tok:{}"
_CONSUMED = "signet:used:{}"
_REVOKED = "signet:rev:{}"


@dataclass
class _CachedFamily:
    """Satisfies ``FamilyLike`` structurally - never a real model instance,
    there is no row, no table - so it can stand in for a ``TokenFamily``
    anywhere the ``TokenStore`` port promises one."""

    id: uuid.UUID
    user: Any
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    user_agent: str = ""
    ip_address: str | None = None

    @property
    def is_live(self) -> bool:
        # Matches TokenFamily.is_live exactly, including the boundary
        # direction: a family expiring at exactly `now` is not live.
        return self.revoked_at is None and self.expires_at > timezone.now()


@dataclass
class _CachedToken:
    """Satisfies ``TokenLike`` structurally, standing in for an
    ``IssuedToken`` the same way ``_CachedFamily`` stands in for a
    ``TokenFamily``."""

    id: uuid.UUID
    family_id: uuid.UUID
    digest: str
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None


class CacheTokenStore(TokenStore):
    """Cache-backed store, opposite defaults from ``ORMTokenStore``.

    ``deny_by_default=False`` (the default) is an allowlist: a family
    must exist in the cache and be unexpired for ``is_live()`` to say
    yes. ``deny_by_default=True`` is a denylist: absence means live,
    only an explicit ``revoke_family()`` says no. Same interface,
    opposite default - see ``TokenStore``.

    Atomicity comes entirely from ``cache.add()``, which sets a key only
    when it is absent. That compare-and-set is the one atomic primitive
    every Django cache backend implements; there are no transactions and
    no conditional updates here. ``consume()`` decides LIVE versus
    ALREADY_CONSUMED solely from whether its own ``add()`` call won -
    never from a prior read - because a read-then-write decision leaves
    a gap two concurrent callers can both land in and both "win".

    One thing this store cannot do that ``ORMTokenStore`` can: fold a
    family's revocation state into the same atomic write as the claim.
    The best available approximation, and the one used below, is to
    re-check the revocation key immediately after winning the claim.
    That narrows the window in which a mid-flight revocation is missed;
    it does not close it. See docs/stores.md.
    """

    supports_revoke_all_for_user: ClassVar[bool] = False

    def __init__(self, alias: str = "default", deny_by_default: bool = False) -> None:
        self.alias = alias
        self.deny_by_default = deny_by_default

    @property
    def cache(self) -> BaseCache:
        return caches[self.alias]

    @staticmethod
    def _ttl(expires_at: datetime) -> int:
        # Floored well above zero - not to keep an expired token usable,
        # it never is, consume() always compares expires_at itself - but
        # so an already-expired entry reliably survives long enough after
        # being written for consume() to read it back and classify it as
        # EXPIRED. A 1-second floor would flake under any real scheduling
        # delay between issue() and the read that follows it, reporting
        # the misleading NOT_FOUND instead once the cache evicted it first.
        return max(60, int((expires_at - timezone.now()).total_seconds()))

    def _is_revoked(self, family_id: uuid.UUID) -> bool:
        return self.cache.get(_REVOKED.format(family_id)) is not None

    def open_family(
        self,
        user: Any,
        expires_at: datetime,
        *,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> FamilyLike:
        # Carried along for parity with TokenFamily, but not for an audit
        # trail a cache cannot offer anyway: this entry, and everything
        # in it, disappears with its TTL or a cache flush.
        family = _CachedFamily(
            id=uuid.uuid4(),
            user=user,
            expires_at=expires_at,
            user_agent=user_agent[:256],
            ip_address=ip_address,
        )
        self.cache.set(_FAMILY.format(family.id), family, self._ttl(expires_at))
        return family

    def issue(self, family: FamilyLike, digest: str, expires_at: datetime) -> TokenLike:
        token = _CachedToken(
            id=uuid.uuid4(),
            family_id=family.id,
            digest=digest,
            issued_at=timezone.now(),
            expires_at=expires_at,
        )
        self.cache.set(_TOKEN.format(digest), token, self._ttl(expires_at))
        return token

    def consume(self, digest: str) -> ConsumeResult:
        token = self.cache.get(_TOKEN.format(digest))
        if token is None:
            return ConsumeResult(Outcome.NOT_FOUND)

        family = self.cache.get(_FAMILY.format(token.family_id))
        if family is None or self._is_revoked(token.family_id):
            return ConsumeResult(Outcome.FAMILY_REVOKED, family, token)
        if token.expires_at <= timezone.now():
            return ConsumeResult(Outcome.EXPIRED, family, token)

        # The atomic decision, and the only one: add() sets the consumed
        # marker only if it was absent. Exactly one racing caller can
        # ever win it, and the outcome below is decided by that return
        # value alone.
        won = self.cache.add(
            _CONSUMED.format(digest), True, self._ttl(token.expires_at)
        )
        if not won:
            return ConsumeResult(Outcome.ALREADY_CONSUMED, family, token)

        # Narrows, but cannot close, the revocation-versus-claim window:
        # a revocation landing between the pre-check above and this
        # add() winning is caught here. One landing after this line has
        # already run is not - see the class docstring and docs/stores.md.
        if self._is_revoked(token.family_id):
            return ConsumeResult(Outcome.FAMILY_REVOKED, family, token)
        return ConsumeResult(Outcome.LIVE, family, token)

    def is_live(self, family_id: uuid.UUID) -> bool:
        if self._is_revoked(family_id):
            return False
        if self.deny_by_default:
            return True
        family = self.cache.get(_FAMILY.format(family_id))
        return bool(family is not None and family.is_live)

    def revoke_family(self, family_id: uuid.UUID, reason: str) -> None:
        # add(), not set(): first-reason-wins, matching TokenFamily.revoke()'s
        # idempotency guard - a later routine LOGOUT must not silently
        # overwrite an earlier REUSE_DETECTED security event. Cached
        # forever (timeout=None), not for the family's remaining TTL: a
        # denylist that let its own revocation entry expire would
        # silently revive the family it was recording as dead.
        #
        # family_revoked fires on exactly the path TokenFamily.revoke()
        # fires it: the first, winning revocation of a family this store
        # actually holds. A family the cache no longer has (expired,
        # evicted, never issued) records the marker but reports nothing -
        # there is no user or family to hand a receiver, and the ORM
        # adapter is silent for an unknown family too.
        family = self.cache.get(_FAMILY.format(family_id))
        won = self.cache.add(_REVOKED.format(family_id), reason, None)
        self.cache.delete(_FAMILY.format(family_id))
        if won and family is not None:
            family.revoked_at = timezone.now()
            family.revoked_reason = reason
            send(
                family_revoked,
                sender=_CachedFamily,
                user=family.user,
                family=family,
                reason=reason,
            )

    def revoke_all_for_user(self, user: Any, reason: str) -> None:
        raise NotImplementedError(
            f"CacheTokenStore cannot enumerate {user.pk!r}'s token families "
            f"to revoke them all for {reason!r} - a cache has no query "
            "interface and django.core.cache.cache.keys() is not part of "
            "Django's cache API (nor available on every backend). Use "
            "ORMTokenStore, or maintain your own application-level index "
            "of family ids per user, if you need logout-everywhere."
        )

    def purge_expired(self) -> int:
        # Nothing to do: every key this store writes carries its own TTL,
        # so expired entries are already gone from the cache by the time
        # anything could purge them.
        return 0
