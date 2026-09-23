from __future__ import annotations

import abc
import enum
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from django_signet.models import IssuedToken, TokenFamily


class Outcome(enum.Enum):
    NOT_FOUND = "not_found"
    LIVE = "live"
    ALREADY_CONSUMED = "already_consumed"
    EXPIRED = "expired"
    FAMILY_REVOKED = "family_revoked"


@dataclass(frozen=True)
class ConsumeResult:
    outcome: Outcome
    family: TokenFamily | None = None
    issued_token: IssuedToken | None = None


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
    ) -> TokenFamily:
        """Create an empty family. The caller mints the first refresh token
        against the returned id, then calls ``issue()``."""

    @abc.abstractmethod
    def issue(
        self, family: TokenFamily, digest: str, expires_at: datetime
    ) -> IssuedToken: ...

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
