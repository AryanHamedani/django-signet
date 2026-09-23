from datetime import timedelta

import pytest
from django.core.cache import cache

from django_signet.exceptions import (
    TokenInvalid,
    TokenReused,
    TokenRevoked,
)
from django_signet.hashing import token_digest
from django_signet.models import IssuedToken, RevocationReason, TokenFamily
from django_signet.sessions.rotation import RotationPolicy
from django_signet.signals import token_reuse_detected
from django_signet.tokens.access import AccessToken

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def policy():
    return RotationPolicy()


def test_open_session_creates_family_and_persists_only_the_digest(policy, user):
    pair = policy.open_session(user)
    assert TokenFamily.objects.count() == 1
    stored = IssuedToken.objects.get()
    assert stored.digest == token_digest(pair.refresh.value)
    # the raw token must appear nowhere in the database
    assert pair.refresh.value not in stored.digest


def test_access_token_carries_the_family_id(policy, user):
    pair = policy.open_session(user)
    claims = AccessToken().verify(pair.access.value)
    assert claims["sid"] == str(pair.family.id)


def test_rotate_issues_a_new_pair_and_consumes_the_old(policy, user):
    first = policy.open_session(user)
    second = policy.rotate(first.refresh.value)
    assert second.refresh.value != first.refresh.value
    assert second.replayed is False
    old = IssuedToken.objects.get(digest=token_digest(first.refresh.value))
    assert old.consumed_at is not None
    assert IssuedToken.objects.count() == 2


def test_replay_inside_the_grace_window_is_idempotent(policy, user):
    """Two tabs, or React StrictMode, refresh with the same token. The second
    caller must receive the identical pair and the family must survive."""
    first = policy.open_session(user)
    a = policy.rotate(first.refresh.value)
    b = policy.rotate(first.refresh.value)
    assert b.replayed is True
    assert b.access.value == a.access.value
    assert b.refresh.value == a.refresh.value
    first.family.refresh_from_db()
    assert first.family.is_live is True


def test_replay_outside_the_grace_window_burns_the_family(user):
    class Strict(RotationPolicy):
        grace_cache = None  # disables the window entirely

    policy = Strict()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)
    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    first.family.refresh_from_db()
    assert first.family.is_live is False
    assert first.family.revoked_reason == RevocationReason.REUSE_DETECTED


def test_reuse_fires_the_signal_and_the_hook(user):
    seen = {}

    class Watching(RotationPolicy):
        grace_cache = None

        def on_reuse_detected(self, family):
            seen["hook"] = family.id

    def receiver(sender, family, **kwargs):
        seen["signal"] = family.id

    token_reuse_detected.connect(receiver)
    try:
        policy = Watching()
        first = policy.open_session(user)
        policy.rotate(first.refresh.value)
        with pytest.raises(TokenReused):
            policy.rotate(first.refresh.value)
    finally:
        token_reuse_detected.disconnect(receiver)

    assert seen["hook"] == first.family.id
    assert seen["signal"] == first.family.id


def test_rotating_after_the_family_is_revoked_raises(policy, user):
    first = policy.open_session(user)
    first.family.revoke(RevocationReason.LOGOUT)
    with pytest.raises(TokenRevoked):
        policy.rotate(first.refresh.value)


def test_unknown_refresh_token_raises_invalid(policy, user):
    from django_signet.tokens.refresh import RefreshToken

    orphan = RefreshToken().mint(
        subject="1", family_id="00000000-0000-0000-0000-000000000000"
    )
    with pytest.raises(TokenInvalid):
        policy.rotate(orphan.value)


def test_an_access_token_cannot_be_used_to_rotate(policy, user):
    pair = policy.open_session(user)
    with pytest.raises(TokenInvalid):
        policy.rotate(pair.access.value)


def test_burn_can_be_disabled_while_still_rejecting_the_replay(user):
    class Lenient(RotationPolicy):
        grace_cache = None
        burn_family_on_reuse = False

    policy = Lenient()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)
    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    first.family.refresh_from_db()
    assert first.family.is_live is True


def test_a_misconfigured_grace_cache_degrades_to_strict(user):
    """``GRACE_CACHE`` pointing at an alias that is not in ``settings.CACHES``
    must behave exactly like ``grace_cache = None``: strict RFC 9700 reuse
    detection, never a silent pass-through. A bug here - a swallowed
    exception that accidentally makes the window permissive instead of
    absent - would be the worst possible failure mode in this library."""

    class Misconfigured(RotationPolicy):
        grace_cache = "does-not-exist"

    policy = Misconfigured()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)
    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    first.family.refresh_from_db()
    assert first.family.is_live is False
    assert first.family.revoked_reason == RevocationReason.REUSE_DETECTED


def test_replay_just_past_the_grace_window_is_rejected(user):
    """The grace entry must expire with the window rather than live forever
    (never a ``None`` cache timeout) - otherwise every replay, no matter how
    late, would be treated as the benign double-tab case."""

    class ShortGrace(RotationPolicy):
        grace_window = timedelta(seconds=0)

    policy = ShortGrace()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)
    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    first.family.refresh_from_db()
    assert first.family.is_live is False


class _RecordingCache:
    """Stands in for ``caches[alias]``: records what would be sent to
    ``set()`` instead of applying any backend-specific semantics to it.
    ``LocMemCache`` special-cases ``timeout=0`` as already-expired, which
    makes a real cache backend the wrong tool for pinning a ``<=`` versus
    ``<`` boundary bug - any such backend would make the two
    implementations behave identically from the outside."""

    def __init__(self):
        self.set_calls = []

    def set(self, key, value, timeout):
        self.set_calls.append(timeout)

    def get(self, key):
        return None


def test_a_non_positive_grace_window_never_touches_the_cache(user, monkeypatch):
    """Direct proof of the ``_cache()`` boundary, independent of any cache
    backend's own timeout=0 handling: a ``<=`` guard weakened to ``<``
    would still let ``grace_window == timedelta(0)`` reach ``caches[alias]``
    and call ``.set()`` - this fails in that case and passes against the
    shipped ``<=`` guard."""

    class ZeroGrace(RotationPolicy):
        grace_window = timedelta(seconds=0)
        grace_cache = "spy"

    spy = _RecordingCache()
    monkeypatch.setattr("django_signet.sessions.rotation.caches", {"spy": spy})

    policy = ZeroGrace()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)

    assert spy.set_calls == []


class _RaisingCache:
    """A cache backend that is present but unreachable - a dropped
    connection or a timeout, not a missing alias."""

    def set(self, key, value, timeout):
        raise ConnectionError("cache backend unreachable")

    def get(self, key):
        raise ConnectionError("cache backend unreachable")


def test_a_cache_write_failure_does_not_strand_the_rotated_pair(user, monkeypatch):
    """``store.consume()`` already burned the old token and ``store.issue()``
    already persisted the successor by the time the grace cache is written.
    A transient cache outage on that write must not turn an already-
    completed rotation into an unhandled exception - only the idempotency
    guarantee for a subsequent replay is allowed to be lost."""
    monkeypatch.setattr(
        "django_signet.sessions.rotation.caches", {"default": _RaisingCache()}
    )
    policy = RotationPolicy()
    first = policy.open_session(user)

    second = policy.rotate(first.refresh.value)  # must not raise

    assert second.replayed is False
    assert second.refresh.value != first.refresh.value
    old = IssuedToken.objects.get(digest=token_digest(first.refresh.value))
    assert old.consumed_at is not None


def test_a_cache_read_failure_degrades_to_treating_the_replay_as_reuse(
    user, monkeypatch
):
    """The read-side mirror of the write-failure case: once the cache is
    unreachable, a replay it can no longer vouch for must be treated as
    reuse, exactly like a genuine grace-window miss - never silently
    treated as benign, and never allowed to propagate the cache's own
    exception past ``rotate()``."""
    policy = RotationPolicy()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)  # writes a real grace-cache entry

    monkeypatch.setattr(
        "django_signet.sessions.rotation.caches", {"default": _RaisingCache()}
    )
    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    first.family.refresh_from_db()
    assert first.family.is_live is False


def test_a_dummy_cache_alias_makes_every_replay_look_like_reuse(user):
    """``DummyCache`` accepts writes and silently discards them, so it
    passes ``_cache()``'s checks yet never actually holds an entry - the
    grace window becomes a permanent no-op and every benign double-tab
    replay burns the family exactly like theft would. Still the safe
    direction, not a hole - but it is a footgun worth pinning down, since
    it produces no error, only logged-out users."""

    class DummyGrace(RotationPolicy):
        grace_cache = "dummy"

    policy = DummyGrace()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)
    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    first.family.refresh_from_db()
    assert first.family.is_live is False


class _ExplodingAccessToken(AccessToken):
    def mint(self, *args, **kwargs):
        raise RuntimeError("signing backend exploded")


def test_a_mint_failure_leaves_no_orphan_family_or_token(user):
    """If minting the access token fails partway through ``_mint_into()``,
    the family (for ``open_session()``) and the just-issued refresh token
    must roll back together rather than surviving as rows nothing can ever
    redeem - the raw refresh value that would redeem them was never
    returned to any caller."""

    class Exploding(RotationPolicy):
        access_token_class = _ExplodingAccessToken

    policy = Exploding()
    with pytest.raises(RuntimeError):
        policy.open_session(user)

    assert TokenFamily.objects.count() == 0
    assert IssuedToken.objects.count() == 0


# ------------------------------------------- final review, Group A: C3, I2


def test_rotate_rejects_an_inactive_user_and_revokes_the_family(policy, user):
    """C3 at the policy level, independent of any view: a direct caller of
    ``rotate()`` - the issuance layer every refresh goes through - must
    not mint for a disabled account, and must burn the family so that
    reactivation cannot revive it."""
    pair = policy.open_session(user)
    user.is_active = False
    user.save(update_fields=["is_active"])

    with pytest.raises(TokenRevoked):
        policy.rotate(pair.refresh.value)
    pair.family.refresh_from_db()
    assert pair.family.is_live is False
    assert pair.family.revoked_reason == RevocationReason.ADMIN


def test_rotate_rejects_a_deleted_user(policy, user):
    """The subject no longer resolves at all: rejected as invalid, and the
    ORM family went with the user (``on_delete=CASCADE``)."""
    pair = policy.open_session(user)
    user.delete()
    with pytest.raises(TokenInvalid):
        policy.rotate(pair.refresh.value)


def test_rotate_derives_extra_claims_from_the_user_it_loads(policy, user):
    """I2 at the policy level: ``get_claims`` is called with the user
    ``rotate()`` loaded from ``sub`` - server-side state, re-evaluated at
    rotation time - and its result lands in both minted tokens."""
    seen = []

    def get_claims(loaded):
        seen.append(loaded)
        return {"org": "acme"}

    pair = policy.rotate(policy.open_session(user).refresh.value, get_claims=get_claims)
    assert seen == [user]
    assert AccessToken().verify(pair.access.value)["org"] == "acme"
    assert pair.refresh.claims["org"] == "acme"
