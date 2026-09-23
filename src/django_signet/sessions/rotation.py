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
grace cache from being reachable - an unknown alias, or the alias raising
once it's actually asked to read or write - must make rotation *stricter*,
never more permissive. The one exception worth knowing about rather than
hitting by surprise: pointing ``GRACE_CACHE`` at Django's own
``DummyCache`` degrades the same way (it accepts writes and silently
discards them), which turns the grace window into a permanent no-op -
every benign double-tab replay burns the family exactly like theft would.
That is still the safe direction, not a hole, but it produces no error and
only confused, logged-out users.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.core.cache import InvalidCacheBackendError, caches
from django.db import transaction
from django.utils import timezone

from django_signet.conf import setting
from django_signet.exceptions import (
    SignetError,
    TokenExpired,
    TokenInvalid,
    TokenReused,
    TokenRevoked,
)
from django_signet.hashing import token_digest
from django_signet.models import RevocationReason
from django_signet.sessions.stores.base import ConsumeResult, Outcome
from django_signet.sessions.stores.factory import ConfiguredStore
from django_signet.signals import token_reuse_detected
from django_signet.tokens.access import AccessToken
from django_signet.tokens.base import MintedToken
from django_signet.tokens.claims import session_id
from django_signet.tokens.refresh import RefreshToken
from django_signet.users import get_active_user, load_user

logger = logging.getLogger(__name__)

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

    # Resolved through get_store() on every access, so rotation, the
    # Strict* liveness check and password-change revocation always agree
    # on one store. A subclass may still pin its own: `store = X()`.
    store = ConfiguredStore()
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
        # One transaction: a mint failure between creating the family and
        # issuing its first token must not leave a family row with no
        # tokens ever pointing at it.
        with transaction.atomic():
            family = self.store.open_family(
                user, expires_at, user_agent=user_agent, ip_address=ip_address
            )
            return self._mint_into(family, subject=str(user.pk), extra=extra)

    def rotate(
        self,
        raw_refresh: str,
        *,
        get_claims: Callable[[Any], dict[str, Any]] | None = None,
    ) -> SessionPair:
        """Redeem a refresh token for a new pair.

        Verification happens before the store is ever touched: an
        unauthenticated digest lookup would be an oracle for guessing
        live tokens.

        The subject is then loaded and checked (see :meth:`get_user`)
        before the token is consumed - issuing a token is exactly as much
        an authentication decision as accepting one, and a disabled
        account must not be able to mint itself a fresh access token that
        a verifier outside this library would accept (CVE-2024-22513, at
        the issuance layer). A rejected subject burns the whole family,
        not just this request, so reactivating the account later does not
        revive a session that was live when it was disabled.

        ``get_claims``, if given, is called with that freshly loaded user
        and its result is merged into both minted tokens' claims verbatim
        (see :func:`django_signet.tokens.claims.build_claims`). Once
        signed it is indistinguishable from a claim the library itself
        issued, so it must be derived from trusted server-side state - the
        user object it is handed - never forwarded from the request body.
        Re-deriving it here, at rotation time, is what keeps custom claims
        alive across refreshes and current with the user's state.
        """
        claims = self.refresh_token_class().verify(raw_refresh)
        user = self._active_user(claims)
        digest = token_digest(raw_refresh)
        result = self.store.consume(digest)
        return self._handle_consume_result(
            result, digest, user=user, get_claims=get_claims
        )

    def get_user(self, claims: dict[str, Any]) -> Any:
        """Hook: resolve a verified refresh token's subject to a user who
        may keep a session, or raise any ``SignetError`` to refuse.

        Defaults to :func:`django_signet.users.get_active_user` - the same
        function ``BaseJWTAuthentication.get_user`` uses - so the refresh
        path and every authenticated request apply one rule. Refusing
        burns the family (see :meth:`rotate`).
        """
        return get_active_user(claims.get("sub"))

    def revoke(self, raw_refresh: str, reason: str) -> None:
        """Revoke the session a refresh token belongs to - logout.

        The signature is verified first, so only a credential this library
        issued can name a family. The token need not be the family's
        current one: whoever holds an older, consumed refresh token of a
        family can already burn it by replaying it at refresh (reuse
        detection), so accepting it here grants nothing new. Idempotent -
        revoking a revoked family keeps the first reason.
        """
        claims = self.refresh_token_class().verify(raw_refresh)
        self._revoke_named_family(claims, reason)

    def revoke_all(self, raw_refresh: str, reason: str) -> None:
        """Revoke every session of the refresh token's user - logout-all.

        Deliberately stricter than :meth:`revoke`: the token's own family
        must still be live. Otherwise an old refresh token lifted from a
        log could log its user out everywhere for the rest of its
        lifetime - a far wider blast radius than replaying it, which only
        ever burns its own family. ``NotImplementedError`` from a store
        that cannot enumerate a user's families propagates to the caller.
        """
        claims = self.refresh_token_class().verify(raw_refresh)
        if not self.store.is_live(session_id(claims)):
            raise TokenRevoked("session is no longer live")
        self.store.revoke_all_for_user(load_user(claims.get("sub")), reason)

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

    def _active_user(self, claims: dict[str, Any]) -> Any:
        try:
            return self.get_user(claims)
        except SignetError:
            # RevocationReason has no "account disabled" member (spec
            # section 6 fixes the vocabulary); disabling or deleting an
            # account is an administrative act, so ADMIN is the recorded
            # cause.
            self._revoke_named_family(claims, RevocationReason.ADMIN)
            raise

    def _revoke_named_family(self, claims: dict[str, Any], reason: str) -> None:
        self.store.revoke_family(session_id(claims), reason)

    def _handle_consume_result(
        self,
        result: ConsumeResult,
        digest: str,
        *,
        user: Any,
        get_claims: Callable[[Any], dict[str, Any]] | None,
    ) -> SessionPair:
        if result.outcome is Outcome.NOT_FOUND:
            raise TokenInvalid("refresh token is not recognised")
        if result.outcome is Outcome.EXPIRED:
            raise TokenExpired("refresh token has expired")
        if result.outcome is Outcome.FAMILY_REVOKED:
            raise TokenRevoked("this session has been revoked")
        if result.outcome is Outcome.ALREADY_CONSUMED:
            return self._handle_replay(digest, result.family)

        extra = get_claims(user) if get_claims is not None else None
        pair = self._mint_into(result.family, subject=str(user.pk), extra=extra)
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
        # Issuing the successor and minting the access token as one unit:
        # if the access mint fails (e.g. a misconfigured signing backend),
        # the just-persisted IssuedToken row must not survive as an orphan
        # nobody will ever present, since the raw refresh value that would
        # redeem it was never returned to any caller.
        with transaction.atomic():
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
        try:
            # The pair itself, not a hand-picked subset of its fields: a
            # replayed caller must get back something indistinguishable
            # from what the original caller received, claims included.
            cache.set(
                _GRACE_KEY.format(digest),
                (pair.access, pair.refresh),
                int(self.grace_window.total_seconds()),
            )
        except Exception:
            # store.consume() already burned the old token and
            # store.issue() already persisted `pair`'s successor before
            # this call runs - the rotation itself has already succeeded.
            # A cache backend that is merely unreachable (a timeout, a
            # dropped connection) must not turn a completed rotation into
            # an unhandled exception the client never gets a response
            # for. The only thing lost is the idempotency guarantee for a
            # subsequent replay during this window, not the rotation.
            logger.warning(
                "signet: grace-window cache write failed; a benign "
                "replay during this window will now be treated as reuse",
                exc_info=True,
            )

    def _grace_get(self, digest: str, family: Any) -> SessionPair | None:
        cache = self._cache()
        if cache is None:
            return None
        try:
            entry = cache.get(_GRACE_KEY.format(digest))
        except Exception:
            # Same failure mode as _grace_put, the opposite direction: an
            # unreachable cache on read must degrade to strict - treat
            # this replay as reuse - never raise past the caller and
            # never silently treat it as benign.
            logger.warning(
                "signet: grace-window cache read failed; treating this replay as reuse",
                exc_info=True,
            )
            return None
        if entry is None:
            return None
        access, refresh = entry
        return SessionPair(access=access, refresh=refresh, family=family, replayed=True)
