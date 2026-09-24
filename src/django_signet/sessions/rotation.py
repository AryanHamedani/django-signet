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
from django_signet.isolation import savepoint_if_in_transaction
from django_signet.models import RevocationReason
from django_signet.sessions.stores.base import ConsumeResult, Outcome
from django_signet.sessions.stores.factory import ConfiguredStore
from django_signet.signals import send, token_reuse_detected
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
    cache rather than freshly minted. ``user`` is the user the pair was
    minted for, when the caller already loaded it (a fresh rotation);
    ``None`` otherwise, and then ``family.user`` is the way to it.
    """

    access: MintedToken
    refresh: MintedToken
    family: Any
    replayed: bool = False
    user: Any = None


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
        alive across refreshes and current with the user's state. It runs
        *before* the token is consumed: a hook that raises (a transient
        database error) must leave the token redeemable, or the client's
        retry would be indistinguishable from theft.

        For the same reason the successor pair is *signed* before the token
        is consumed, and the consume and the successor's ``issue()`` share
        one transaction. A signing failure (a verify-only deployment with
        no ``SIGNING_KEY``) or a failed ``issue()`` therefore leaves the
        token unspent, where it used to be consumed with no successor ever
        handed out - so the client's retry was burned as reuse. (A store
        outside the database, such as ``CacheTokenStore``, is not covered
        by the transaction; the signing half still is.)
        """
        claims = self.refresh_token_class().verify(raw_refresh)
        user = self._active_user(claims)
        extra = get_claims(user) if get_claims is not None else None
        access, refresh = self._sign_pair(
            str(session_id(claims)), subject=str(user.pk), extra=extra
        )
        digest = token_digest(raw_refresh)
        with transaction.atomic():
            result = self.store.consume(digest)
            if result.outcome is Outcome.LIVE:
                if result.family is None:
                    # A store breaking its own contract; refusing inside
                    # the transaction leaves the token unspent.
                    raise TokenInvalid("the store redeemed a token with no family")
                self.store.issue(
                    result.family, token_digest(refresh.value), refresh.expires_at
                )
        # Every other outcome is settled after the transaction, as in
        # _redeem, so a reuse burn is never rolled back with it.
        replayed = self._settle(result, digest)
        if replayed is not None:
            return replayed
        pair = SessionPair(
            access=access, refresh=refresh, family=result.family, user=user
        )
        self._grace_put(digest, pair)
        return pair

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

        The token is *redeemed*, exactly as at refresh (see
        :meth:`_redeem`): only the family's current token - or, inside the
        grace window, the one it just replaced - revokes it. An older,
        already-consumed one goes through the same replay handling as
        refresh - so a stolen token replayed here is burned as reuse and
        reported, not quietly recorded as an ordinary logout.
        """
        claims = self.refresh_token_class().verify(raw_refresh)
        self._redeem(raw_refresh, lambda: self._revoke_named_family(claims, reason))

    def revoke_all(self, raw_refresh: str, reason: str) -> None:
        """Revoke every session of the refresh token's user - logout-all.

        The token is redeemed first (see :meth:`_redeem`), so only a
        family's current refresh token - or, inside the grace window, the
        one it just replaced - can do this. An old one lifted from
        a log must not be able to log its user out everywhere for the rest
        of its lifetime: replayed here it is handled as at refresh, which
        at most burns its own family.

        A store that cannot enumerate a user's families is refused
        *before* the token is consumed - consuming it and then failing
        would leave the client holding a spent token whose next refresh
        looks like theft. ``NotImplementedError`` propagates to the caller.
        """
        claims = self.refresh_token_class().verify(raw_refresh)
        if not self.store.supports_revoke_all_for_user:
            raise NotImplementedError(
                f"{type(self.store).__name__} cannot revoke every session of a user"
            )
        user = load_user(claims.get("sub"))
        self._redeem(raw_refresh, lambda: self.store.revoke_all_for_user(user, reason))

    def on_reuse_detected(self, family: Any) -> None:
        """Hook, called when reuse is detected - after the family is burned,
        unless ``burn_family_on_reuse`` is off - and before ``TokenReused``
        is raised.

        A no-op by default. Deliberately an *event* hook, not a decision
        point: it reports that an incident happened and hands over the
        blast radius (the family), without requiring the caller to
        understand how detection worked. An exception it raises is logged
        at ``error`` on ``django_signet.sessions.rotation`` and ignored:
        the burn is written but not necessarily committed yet (under
        ``ATOMIC_REQUESTS`` it is not), so letting it propagate could roll
        the burn back and leave a detected theft's session live. Override
        to alert, log, or force a password reset. Public API - but, like
        every hook, not frozen until 1.0 (see CONTRIBUTING.md).
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

    def _redeem(self, raw_refresh: str, act: Callable[[], None]) -> None:
        """Consume a refresh token and run ``act`` if it redeems.

        It redeems when it is LIVE, or when it was already consumed but the
        grace window still holds the pair its rotation produced - the same
        replay refresh honours. Inside the window whoever holds the old
        token can already fetch its successor at refresh and log out with
        that, so honouring it here grants nothing new; refusing it would
        let a logout racing a tab's refresh answer "Signed out." while the
        successor stayed live. Every other outcome is settled exactly as
        at refresh, by :meth:`_settle`: an already-consumed token with no
        grace entry is burned as reuse, and the rest revoke nothing.

        The consume and a LIVE ``act`` share one transaction, so a refresh
        of the same token that arrives while this logout is in flight
        waits and then sees the family revoked, not a spent token with no
        successor. The ``family_revoked`` a LIVE logout sends from inside
        that transaction cannot roll it back: a receiver that raises is
        logged and ignored (see :mod:`django_signet.signals`). That covers
        only this ordering. The reverse - a refresh that has committed
        ``consume()`` but not yet written its grace entry - still makes
        this logout read as reuse: the family is
        burned as ``REUSE_DETECTED`` and ``token_reuse_detected`` fires, a
        false alarm. It is the same window two tabs refreshing at once
        already have, and is not closed here. The non-LIVE outcomes are
        settled after the transaction, so a reuse burn is never rolled
        back with it. A transaction the *caller* holds open still covers
        the burn - ``ATOMIC_REQUESTS``, say - which is why nothing but
        ``TokenReused`` leaves a burn: the views answer that with a
        response, so the caller's transaction commits.
        """
        digest = token_digest(raw_refresh)
        with transaction.atomic():
            result = self.store.consume(digest)
            if result.outcome is Outcome.LIVE:
                act()
                return
        if self._settle(result, digest) is not None:
            act()  # a grace-window replay: a redemption, as at refresh

    def _settle(self, result: ConsumeResult, digest: str) -> SessionPair | None:
        """Raise for every consume outcome but LIVE and ALREADY_CONSUMED.

        ALREADY_CONSUMED goes to :meth:`_handle_replay`, which either
        returns the grace-window pair or burns the family and raises.
        ``None`` means the token was LIVE.
        """
        if result.outcome is Outcome.NOT_FOUND:
            raise TokenInvalid("refresh token is not recognised")
        if result.outcome is Outcome.EXPIRED:
            raise TokenExpired("refresh token has expired")
        if result.outcome is Outcome.FAMILY_REVOKED:
            raise TokenRevoked("this session has been revoked")
        if result.outcome is Outcome.ALREADY_CONSUMED:
            return self._handle_replay(digest, result.family)
        return None

    def _handle_replay(self, digest: str, family: Any) -> SessionPair:
        """A second redemption of an already-consumed token: the benign
        double-tab case inside the grace window, or theft outside it."""
        replayed = self._grace_get(digest, family)
        if replayed is not None:
            return replayed
        self._burn(family)
        raise TokenReused("refresh token replayed outside the grace window")

    def _sign_pair(
        self, family_id: str, *, subject: str, extra: dict[str, Any] | None
    ) -> tuple[MintedToken, MintedToken]:
        """Sign an access and a refresh token for ``family_id``. Pure
        signing - it touches no store - so it can run, and fail, before
        anything is written."""
        access = self.access_token_class().mint(
            subject, family_id=family_id, extra=extra
        )
        refresh = self.refresh_token_class().mint(
            subject, family_id=family_id, extra=extra
        )
        return access, refresh

    def _mint_into(
        self, family: Any, *, subject: str, extra: dict[str, Any] | None
    ) -> SessionPair:
        # Both tokens are signed before the successor is issued, so a
        # signing failure (e.g. a misconfigured backend) leaves no
        # IssuedToken row behind that nobody will ever present.
        access, refresh = self._sign_pair(str(family.id), subject=subject, extra=extra)
        self.store.issue(family, token_digest(refresh.value), refresh.expires_at)
        return SessionPair(access=access, refresh=refresh, family=family)

    def _burn(self, family: Any) -> None:
        if family is None:
            return
        if self.burn_family_on_reuse:
            self.store.revoke_family(family.id, RevocationReason.REUSE_DETECTED)
        send(
            token_reuse_detected,
            sender=type(self),
            user=getattr(family, "user", None),
            family=family,
            request=None,
        )
        # The hook runs after the burn is written but not necessarily
        # committed: under ATOMIC_REQUESTS, or in a transaction the caller
        # opened, an exception escaping here would roll the burn back and
        # leave a detected theft's family live. So, like a signal
        # receiver's, the hook runs under its own savepoint - a database
        # write it makes that fails rolls back only the hook's writes -
        # and its exceptions are logged and the replay is refused with
        # TokenReused all the same.
        try:
            with savepoint_if_in_transaction():
                self.on_reuse_detected(family)
        except Exception:
            logger.exception(
                "signet: %s.on_reuse_detected raised; the exception was "
                "logged and ignored, and the replay is still refused",
                type(self).__qualname__,
            )

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
