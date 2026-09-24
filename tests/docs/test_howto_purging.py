"""``docs/howto/purging.md``: what ``signet_purge`` deletes, what it prints,
and what it does under the cache store."""

import logging
from datetime import timedelta

import pytest
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone
from examples.purge_task import purge_expired_sessions

from django_signet.hashing import token_digest
from django_signet.models import IssuedToken, RevocationReason, TokenFamily
from django_signet.sessions.rotation import RotationPolicy

REFRESH = timedelta(days=14)  # REFRESH_TOKEN_LIFETIME's default
ACCESS = timedelta(minutes=5)  # ACCESS_TOKEN_LIFETIME's default
CACHE_STORE = {"STORE": "django_signet.sessions.stores.cache.CacheTokenStore"}


def _expire(family):
    TokenFamily.objects.filter(pk=family.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.mark.django_db
def test_the_task_purges_expired_families_and_logs_the_count(user, caplog):
    policy = RotationPolicy()
    expired = policy.open_session(user)
    policy.rotate(expired.refresh.value)  # two refresh-token rows in this family
    live = policy.open_session(user).family
    revoked = policy.open_session(user).family
    revoked.revoke(RevocationReason.LOGOUT)
    _expire(expired.family)

    with caplog.at_level(logging.INFO, logger="examples.purge_task"):
        purge_expired_sessions()

    assert [r.getMessage() for r in caplog.records] == [
        "Purged 1 expired session family."
    ]
    # Expired: gone, with every token row. Revoked but unexpired: kept.
    assert set(TokenFamily.objects.values_list("pk", flat=True)) == {
        live.pk,
        revoked.pk,
    }
    assert not IssuedToken.objects.filter(family_id=expired.family.pk).exists()


@pytest.mark.django_db
def test_a_family_expires_a_refresh_lifetime_after_login_however_often_it_refreshes(
    user,
):
    policy = RotationPolicy()
    pair = policy.open_session(user)
    opened = pair.family.expires_at
    for _ in range(3):
        pair = policy.rotate(pair.refresh.value)
    pair.family.refresh_from_db()
    assert pair.family.expires_at == opened  # rotation never extends it
    assert pair.refresh.expires_at > opened  # although the newest token outlives it


@pytest.mark.django_db
def test_under_the_cache_store_the_command_deletes_nothing(user, caplog):
    with override_settings(SIGNET=CACHE_STORE):
        policy = RotationPolicy()
        session = policy.open_session(user)
        policy.store.revoke_family(session.family.id, RevocationReason.LOGOUT)
        with caplog.at_level(logging.INFO, logger="examples.purge_task"):
            purge_expired_sessions()
    assert [r.getMessage() for r in caplog.records] == [
        "Purged 0 expired session families."
    ]
    # Every entry carries a timeout. The revocation marker's outlasts the
    # session by the refresh and access lifetimes (and LEEWAY, 0 here).
    token_key = f"signet:tok:{token_digest(session.refresh.value)}"
    revoked_key = f"signet:rev:{session.family.id}"
    assert cache.get(token_key) is not None
    assert cache.get(revoked_key) == RevocationReason.LOGOUT
    assert cache._expire_info[cache.make_and_validate_key(token_key)] is not None
    marker_expires = cache._expire_info[cache.make_and_validate_key(revoked_key)]
    bound = session.family.expires_at + REFRESH + ACCESS
    assert abs(marker_expires - bound.timestamp()) < 5
