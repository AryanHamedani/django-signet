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
