"""``get_store()``: the one place a concrete ``TokenStore`` is chosen."""

from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured

from django_signet.authentication import BaseJWTAuthentication
from django_signet.sessions.rotation import RotationPolicy
from django_signet.sessions.stores.cache import CacheTokenStore
from django_signet.sessions.stores.factory import get_store
from django_signet.sessions.stores.orm import ORMTokenStore

_CACHE_STORE = "django_signet.sessions.stores.cache.CacheTokenStore"


def test_the_default_is_the_orm_store():
    assert type(get_store()) is ORMTokenStore


def test_a_dotted_path_and_options_build_the_configured_store(settings):
    settings.SIGNET = {
        "STORE": _CACHE_STORE,
        "STORE_OPTIONS": {"alias": "default", "deny_by_default": True},
    }
    store = get_store()
    assert isinstance(store, CacheTokenStore)
    assert store.deny_by_default is True


def test_a_class_is_accepted_as_well_as_a_dotted_path(settings):
    settings.SIGNET = {"STORE": CacheTokenStore}
    assert isinstance(get_store(), CacheTokenStore)


def test_an_unimportable_path_is_improperly_configured(settings):
    settings.SIGNET = {"STORE": "no.such.module.Store"}
    with pytest.raises(ImproperlyConfigured):
        get_store()


def test_something_that_is_not_a_token_store_is_improperly_configured(settings):
    settings.SIGNET = {"STORE": "collections.OrderedDict"}
    with pytest.raises(ImproperlyConfigured):
        get_store()


def test_options_the_store_does_not_accept_are_improperly_configured(settings):
    settings.SIGNET = {"STORE": _CACHE_STORE, "STORE_OPTIONS": {"nope": 1}}
    with pytest.raises(ImproperlyConfigured):
        get_store()


@pytest.mark.parametrize("owner", [RotationPolicy, BaseJWTAuthentication])
def test_every_consumer_resolves_the_configured_store(owner, settings):
    """C2: rotation and authentication each constructed their own store.
    Both now read the one setting - at access time, so override_settings
    works."""
    assert type(owner().store) is ORMTokenStore
    settings.SIGNET = {"STORE": _CACHE_STORE}
    assert isinstance(owner().store, CacheTokenStore)


def test_a_class_level_store_still_overrides_the_setting(settings):
    """Resolution order is unchanged: a literal on a subclass wins."""
    settings.SIGNET = {"STORE": _CACHE_STORE}

    class _Pinned(RotationPolicy):
        store = ORMTokenStore()

    assert type(_Pinned().store) is ORMTokenStore
