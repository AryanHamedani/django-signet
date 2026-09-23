"""Rotation, reuse detection, and the idempotent grace window.

This is the security-critical heart of the library: every refresh cycles
through :meth:`RotationPolicy.rotate`, and every reuse decision is made
here.

**The grace cache is the only place a raw token exists outside the
client.** ``open_family``/``issue``/``consume`` on :class:`TokenStore
<django_signet.sessions.stores.base.TokenStore>` only ever see a digest -
but a benign replay (two tabs, React StrictMode) has to be answered with
the exact bytes the first caller already received, so the rendered
:class:`MintedToken <django_signet.tokens.base.MintedToken>` pair is cached
for the grace window under the digest of the refresh token that produced
it. Every entry carries the grace window itself as its cache timeout -
never ``None`` - so a stale entry cannot outlive the window it exists to
bound.

Set ``grace_cache = None`` on a subclass to disable the window entirely and
fall back to strict RFC 9700 behaviour, where *any* replay of a consumed
refresh token burns its family. A missing or misconfigured cache alias
degrades the same way: silently disabling reuse detection would be the
worst possible failure mode for this library, so anything that stops the
grace cache from being reachable must make rotation *stricter*, never more
permissive.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.core.cache import InvalidCacheBackendError, caches
from django.utils import timezone

from django_signet.conf import setting
from django_signet.exceptions import (
    TokenExpired,
    TokenInvalid,
    TokenReused,
    TokenRevoked,
)
from django_signet.hashing import token_digest
from django_signet.models import RevocationReason
from django_signet.sessions.stores.base import ConsumeResult, Outcome, TokenStore
from django_signet.sessions.stores.orm import ORMTokenStore
from django_signet.signals import token_reuse_detected
from django_signet.tokens.access import AccessToken
from django_signet.tokens.base import MintedToken
from django_signet.tokens.refresh import RefreshToken

_GRACE_KEY = "signet:grace:{}"


@dataclass(frozen=True)
class SessionPair:
    """The result of opening or rotating a session.

    ``family`` is whatever the configured :class:`TokenStore` returns from
    ``open_family``/``consume`` - a real ``TokenFamily`` for the default
    ORM store, or a structurally-compatible stand-in for another adapter.
    ``replayed`` is ``True`` only when this pair was served from the grace
    cache rather than freshly minted.
    """

    access: MintedToken
    refresh: MintedToken
    family: Any
    replayed: bool = False


class RotationPolicy:
    """Owns the refresh path: verify, rotate, detect reuse, absorb replays.

    See the module docstring for the grace window's security contract.
    """

    grace_window = setting("GRACE_WINDOW")
    grace_cache = setting("GRACE_CACHE")
    burn_family_on_reuse: bool = True

    # A single shared instance is safe here: ORMTokenStore and
    # CacheTokenStore hold no per-request state (CacheTokenStore's
    # constructor args are fixed at construction time and never mutated
    # afterwards), every method is passed the request-specific data it
    # needs as arguments, and the correctness of consume() comes from the
    # database/cache's own atomic primitives rather than from anything
    # held on `self`. Concurrent RotationPolicy instances - and therefore
    # concurrent requests - sharing this one store is exactly the
    # scenario consume() is built to serialize correctly.
    store: TokenStore = ORMTokenStore()
    access_token_class = AccessToken
    refresh_token_class = RefreshToken

    # ---------------------------------------------------------------- public

    def open_session(
        self,
        user: Any,
        *,
        extra: dict[str, Any] | None = None,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> SessionPair:
        """Begin a new login session.

        The family is created before either token is minted: a refresh
        token embeds its family id in the ``sid`` claim, so the id has to
        exist first. The access token carries ``sid`` too, so a
        ``Strict*`` authentication class can check the family is still
        live without ever consulting a refresh token.
        """
        expires_at = timezone.now() + self.refresh_token_class().lifetime
        family = self.store.open_family(
            user, expires_at, user_agent=user_agent, ip_address=ip_address
        )
        return self._mint_into(family, subject=str(user.pk), extra=extra)

    def rotate(
        self, raw_refresh: str, *, extra: dict[str, Any] | None = None
    ) -> SessionPair:
        """Redeem a refresh token for a new pair.

        Verification happens before the store is ever touched: an
        unauthenticated digest lookup would be an oracle for guessing
        live tokens.
        """
        claims = self.refresh_token_class().verify(raw_refresh)
        digest = token_digest(raw_refresh)
        result = self.store.consume(digest)
        return self._handle_consume_result(
            result, digest, subject=claims["sub"], extra=extra
        )

    def on_reuse_detected(self, family: Any) -> None:
        """Hook, called after the family is burned and before ``TokenReused``
        is raised.

        A no-op by default. Deliberately an *event* hook, not a decision
        point: it reports that an incident happened and hands over the
        blast radius (the family), without requiring the caller to
        understand how detection worked. Override to alert, log, or force
        a password reset. Name and signature are frozen public API.
        """

    # --------------------------------------------------------------- private

    def _handle_consume_result(
        self,
        result: ConsumeResult,
        digest: str,
        *,
        subject: str,
        extra: dict[str, Any] | None,
    ) -> SessionPair:
        if result.outcome is Outcome.NOT_FOUND:
            raise TokenInvalid("refresh token is not recognised")
        if result.outcome is Outcome.EXPIRED:
            raise TokenExpired("refresh token has expired")
        if result.outcome is Outcome.FAMILY_REVOKED:
            raise TokenRevoked("this session has been revoked")
        if result.outcome is Outcome.ALREADY_CONSUMED:
            return self._handle_replay(digest, result.family)

        pair = self._mint_into(result.family, subject=subject, extra=extra)
        self._grace_put(digest, pair)
        return pair

    def _handle_replay(self, digest: str, family: Any) -> SessionPair:
        """A second redemption of an already-consumed token: the benign
        double-tab case inside the grace window, or theft outside it."""
        replayed = self._grace_get(digest, family)
        if replayed is not None:
            return replayed
        self._burn(family)
        raise TokenReused("refresh token replayed outside the grace window")

    def _mint_into(
        self, family: Any, *, subject: str, extra: dict[str, Any] | None
    ) -> SessionPair:
        family_id = str(family.id)
        refresh = self.refresh_token_class().mint(
            subject, family_id=family_id, extra=extra
        )
        self.store.issue(family, token_digest(refresh.value), refresh.expires_at)
        access = self.access_token_class().mint(
            subject, family_id=family_id, extra=extra
        )
        return SessionPair(access=access, refresh=refresh, family=family)

    def _burn(self, family: Any) -> None:
        if family is None:
            return
        if self.burn_family_on_reuse:
            self.store.revoke_family(family.id, RevocationReason.REUSE_DETECTED)
        token_reuse_detected.send(
            sender=type(self),
            user=getattr(family, "user", None),
            family=family,
            request=None,
        )
        self.on_reuse_detected(family)

    def _cache(self) -> Any | None:
        """The grace cache, or ``None`` if the window is disabled or
        unreachable. Every failure mode here - ``grace_cache = None``, a
        non-positive ``grace_window``, or an alias missing from
        ``settings.CACHES`` - must fall through to ``None`` so callers
        degrade to strict RFC 9700 behaviour rather than silently treating
        every replay as benign.
        """
        alias = self.grace_cache
        if alias is None or self.grace_window <= timedelta(0):
            return None
        try:
            return caches[alias]
        except InvalidCacheBackendError:
            return None

    def _grace_put(self, digest: str, pair: SessionPair) -> None:
        cache = self._cache()
        if cache is None:
            return
        # The pair itself, not a hand-picked subset of its fields: a
        # replayed caller must get back something indistinguishable from
        # what the original caller received, claims included.
        cache.set(
            _GRACE_KEY.format(digest),
            (pair.access, pair.refresh),
            int(self.grace_window.total_seconds()),
        )

    def _grace_get(self, digest: str, family: Any) -> SessionPair | None:
        cache = self._cache()
        if cache is None:
            return None
        entry = cache.get(_GRACE_KEY.format(digest))
        if entry is None:
            return None
        access, refresh = entry
        return SessionPair(access=access, refresh=refresh, family=family, replayed=True)
