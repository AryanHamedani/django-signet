from __future__ import annotations

import abc
import enum
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar, Protocol


class FamilyLike(Protocol):
    """What every ``TokenStore`` implementation's family object must offer,
    and nothing more. A structural protocol, not a base class: ``orm.py``'s
    ``TokenFamily`` and ``cache.py``'s ``_CachedFamily`` satisfy it without
    either knowing the other exists, which is the point of ``TokenStore``
    being a port with more than one adapter.

    Every member here is read by a real caller, not mirrored from the model
    for completeness:

    - ``id`` - ``issue()`` needs it to link a token to its family
      (``cache.py``'s ``issue()`` reads ``family.id`` directly; ``orm.py``'s
      relies on it via the FK assignment), and the rotation layer needs it
      to mint a token's ``sid`` claim once a family is open.
    - ``user`` - ``open_family()`` receives it and every implementation
      stores it back onto the family it creates.
    - ``expires_at`` - read by both ``is_live`` implementations (the
      model's, in ``TokenFamily.is_live``, and ``_CachedFamily.is_live``)
      to decide liveness, and by ``consume()`` in both stores.
    - ``revoked_at`` / ``revoked_reason`` - read by ``TokenFamily.is_live``
      and mirrored by ``_CachedFamily.is_live``; ``revoked_reason`` is what
      ``revoke_family()`` records and what a caller inspects afterwards.
    - ``is_live`` - the one property both ``is_live()`` store methods
      delegate to when they have a family object in hand.
    """

    id: uuid.UUID
    user: Any
    expires_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None

    @property
    def is_live(self) -> bool: ...


class TokenLike(Protocol):
    """What every ``TokenStore`` implementation's issued-token object must
    offer. Same structural relationship to ``IssuedToken`` and
    ``_CachedToken`` as ``FamilyLike`` has to the two family types.

    - ``id`` - the token's own identity, mirroring ``IssuedToken.id``.
    - ``family_id`` - the FK id every ``consume()`` implementation reads to
      look up the owning family (``IssuedToken.family_id`` is Django's
      auto-generated raw-FK attribute; ``_CachedToken.family_id`` is the
      same value stored directly, since a cache entry has no FK descriptor
      to generate it from).
    - ``digest`` - what ``consume()`` was called with in the first place;
      carried on the result so a caller doesn't have to thread it through
      separately.
    - ``issued_at`` / ``expires_at`` / ``consumed_at`` - the token
      lifecycle fields both ``consume()`` implementations read to decide
      ``EXPIRED`` vs ``LIVE`` vs ``ALREADY_CONSUMED``, and that a caller
      reporting on a consume result would want to inspect.
    """

    id: uuid.UUID
    family_id: uuid.UUID
    digest: str
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None


class Outcome(enum.Enum):
    """Every state ``TokenStore.consume()`` can report for a digest.

    How ``RotationPolicy`` acts on each, at refresh and at logout and
    logout-all alike:

    - ``LIVE`` redeems.
    - ``ALREADY_CONSUMED`` redeems too while the grace window still holds
      the pair this token's rotation produced - the benign double-tab
      replay. Without a grace entry it is reuse: the family is burned
      (unless ``burn_family_on_reuse`` is off) and ``TokenReused`` raised.
    - ``NOT_FOUND``, ``EXPIRED`` and ``FAMILY_REVOKED`` are refused, as
      ``TokenInvalid``, ``TokenExpired`` and ``TokenRevoked``.
    """

    NOT_FOUND = "not_found"
    LIVE = "live"
    ALREADY_CONSUMED = "already_consumed"
    EXPIRED = "expired"
    FAMILY_REVOKED = "family_revoked"


@dataclass(frozen=True)
class ConsumeResult:
    """What ``TokenStore.consume()`` returns: the outcome, and the family
    and token it was decided against when either exists.

    ``issued_token`` is ``None`` only for ``NOT_FOUND``. ``family`` is
    ``None`` for ``NOT_FOUND`` too, and under ``CacheTokenStore`` it can
    also be ``None`` for ``FAMILY_REVOKED``: revoking a family deletes its
    cache entry, and a family whose entry expired or was evicted is
    reported as revoked. For every other outcome both name the record the
    decision was made about, so a caller can revoke the family or report
    on the token without a second lookup.
    """

    outcome: Outcome
    family: FamilyLike | None = None
    issued_token: TokenLike | None = None


class TokenStore(abc.ABC):
    """The single abstraction behind both whitelist and blacklist semantics.

    They are not separate features. A denylist returns ``True`` from
    ``is_live`` unless something was explicitly revoked; an allowlist returns
    ``False`` unless something was explicitly issued. Same interface,
    opposite default.
    """

    #: ``False`` for an adapter whose ``revoke_all_for_user`` raises
    #: ``NotImplementedError`` by design. Read by system check signet.W007,
    #: so the gap is announced at startup; the runtime paths still catch
    #: the exception itself, so an adapter that forgets to set this fails
    #: safe rather than crashing.
    supports_revoke_all_for_user: ClassVar[bool] = True

    @abc.abstractmethod
    def open_family(
        self,
        # ``Any``, not ``AbstractBaseUser``: ``settings.AUTH_USER_MODEL`` is
        # swappable, and django-stubs resolves ``TokenFamily.user`` to the
        # concrete configured model, which a caller-supplied abstract type
        # would not statically match.
        user: Any,
        expires_at: datetime,
        *,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> FamilyLike:
        """Create an empty family. The caller mints the first refresh token
        against the returned id, then calls ``issue()``."""

    @abc.abstractmethod
    def issue(self, family: FamilyLike, digest: str, expires_at: datetime) -> TokenLike:
        """Record a newly minted refresh token's digest against
        ``family``, so a later ``consume()`` can find and classify it."""

    @abc.abstractmethod
    def consume(self, digest: str) -> ConsumeResult:
        """Mark a token consumed and report its prior state ATOMICALLY.

        A non-atomic implementation makes reuse detection racy and therefore
        useless: two concurrent replays could both observe an unconsumed
        token and both succeed.
        """

    @abc.abstractmethod
    def is_live(self, family_id: uuid.UUID) -> bool:
        """Whether the family is still usable. What a ``Strict*``
        authentication class checks on every request to stop a revoked
        session authenticating immediately, rather than only once its
        still-valid access token expires on its own.

        An allowlist store (``ORMTokenStore``, and ``CacheTokenStore`` by
        default) answers ``True`` only for a family it holds that is
        unrevoked and unexpired. A denylist store
        (``CacheTokenStore(deny_by_default=True)``) answers ``True`` for
        any family, known or not, unless a revocation was recorded for it.
        """

    @abc.abstractmethod
    def revoke_family(self, family_id: uuid.UUID, reason: str) -> None:
        """Revoke one session family, recording ``reason``.

        A requirement on every implementation: afterwards
        :meth:`is_live` must answer ``False`` for ``family_id``, and
        :meth:`consume` must report ``FAMILY_REVOKED`` for its tokens,
        **even for
        a family the store does not hold** (expired, purged, evicted, never
        issued). An allowlist store gets that for free - an unknown family
        is already not live, so ``ORMTokenStore`` does nothing for one. A
        denylist store treats an unknown family as live, so it must record
        the revocation anyway (``CacheTokenStore`` writes a marker that
        outlives every token of the family); one that skipped it would fail
        open, and ``Strict*`` would keep accepting the revoked session.

        The first revocation of a family wins: a later call must not
        overwrite the recorded ``reason``.
        """

    @abc.abstractmethod
    def revoke_all_for_user(self, user: Any, reason: str) -> None:
        """Revoke every live family belonging to ``user`` - logout-all and
        password-change revocation both go through this. An adapter that
        cannot enumerate a user's families raises ``NotImplementedError``
        and sets ``supports_revoke_all_for_user = False`` so system check
        ``signet.W007`` can say so at startup.
        """

    @abc.abstractmethod
    def purge_expired(self) -> int:
        """Delete every expired family (and its tokens), returning how
        many were removed. What ``manage.py signet_purge`` calls; nothing
        else in this library does, so a store that never runs it keeps
        expired sessions forever.
        """
