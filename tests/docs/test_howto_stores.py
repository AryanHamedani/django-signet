"""The two pages moved under ``howto/``: ``choosing-a-store.md`` and
``migrating-from-simplejwt.md``."""

import uuid
from pathlib import Path

import pytest
from django.core.cache import cache
from django.test import override_settings
from django.utils.module_loading import import_string
from examples import cache_store_settings, simplejwt_transition_settings
from rest_framework.test import APIRequestFactory

from django_signet.authentication import CookieJWTAuthentication
from django_signet.checks import check_token_store
from django_signet.exceptions import TokenReused
from django_signet.hashing import token_digest
from django_signet.sessions.rotation import RotationPolicy
from django_signet.sessions.stores.cache import CacheTokenStore
from django_signet.sessions.stores.factory import get_store
from tests.docs.helpers import settings_of

DOCS = Path(__file__).resolve().parents[2] / "docs"


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def cache_store():
    with override_settings(**settings_of(cache_store_settings)):
        yield


# ------------------------------------------------------------ choosing a store


@pytest.mark.usefixtures("cache_store")
def test_the_setting_builds_a_denylist_cache_store():
    store = get_store()
    assert isinstance(store, CacheTokenStore)
    assert store.deny_by_default is True
    assert store.alias == "default"


@pytest.mark.usefixtures("cache_store")
def test_the_cache_store_is_warned_w007_with_a_link_to_this_page():
    [warning] = check_token_store(None)
    assert warning.id == "signet.W007"
    url = "https://django-signet.readthedocs.io/en/latest/howto/choosing-a-store.html"
    assert warning.hint.endswith(url)
    assert (DOCS / "howto" / "choosing-a-store.md").is_file()


@pytest.mark.usefixtures("cache_store")
def test_a_denylist_calls_a_family_it_never_saw_live():
    assert get_store().is_live(uuid.uuid4())


@pytest.mark.django_db
@pytest.mark.parametrize("deny_by_default", [False, True])
def test_an_evicted_consumed_marker_lets_a_spent_token_redeem(user, deny_by_default):
    """Reuse detection needs the consumed marker. Evict it and a spent
    refresh token is LIVE again: the replay forks the session instead of
    burning it, in allowlist and denylist mode alike."""
    signet = {
        **cache_store_settings.SIGNET,
        "STORE_OPTIONS": {"deny_by_default": deny_by_default},
        "GRACE_CACHE": None,
    }
    with override_settings(SIGNET=signet):
        policy = RotationPolicy()
        first = policy.open_session(user)
        policy.rotate(first.refresh.value)
        with pytest.raises(TokenReused):
            policy.rotate(first.refresh.value)  # detected while the marker lives
        assert not policy.store.is_live(first.family.id)

        again = policy.open_session(user)
        policy.rotate(again.refresh.value)
        cache.delete(f"signet:used:{token_digest(again.refresh.value)}")  # evicted
        forked = policy.rotate(again.refresh.value)  # no TokenReused
        assert forked.family.id == again.family.id
        assert policy.store.is_live(again.family.id)


# ---------------------------------------------------- migrating from Simple JWT


def test_the_transition_lists_signet_first_then_simple_jwt():
    first, second = simplejwt_transition_settings.REST_FRAMEWORK[
        "DEFAULT_AUTHENTICATION_CLASSES"
    ]
    assert import_string(first) is CookieJWTAuthentication
    assert second == "rest_framework_simplejwt.authentication.JWTAuthentication"


def test_a_request_without_a_signet_cookie_passes_to_the_next_class():
    """Absence is not failure: DRF then asks the next class in the list."""
    request = APIRequestFactory().get("/", headers={"Authorization": "Bearer legacy"})
    assert CookieJWTAuthentication().authenticate(request) is None
