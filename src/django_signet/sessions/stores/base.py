from __future__ import annotations

import abc
import enum
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


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
    NOT_FOUND = "not_found"
    LIVE = "live"
    ALREADY_CONSUMED = "already_consumed"
    EXPIRED = "expired"
    FAMILY_REVOKED = "family_revoked"


@dataclass(frozen=True)
class ConsumeResult:
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
    def issue(
        self, family: FamilyLike, digest: str, expires_at: datetime
    ) -> TokenLike: ...

    @abc.abstractmethod
    def consume(self, digest: str) -> ConsumeResult:
        """Mark a token consumed and report its prior state ATOMICALLY.

        A non-atomic implementation makes reuse detection racy and therefore
        useless: two concurrent replays could both observe an unconsumed
        token and both succeed.
        """

    @abc.abstractmethod
    def is_live(self, family_id: uuid.UUID) -> bool: ...

    @abc.abstractmethod
    def revoke_family(self, family_id: uuid.UUID, reason: str) -> None: ...

    @abc.abstractmethod
    def revoke_all_for_user(self, user: Any, reason: str) -> None: ...

    @abc.abstractmethod
    def purge_expired(self) -> int: ...
