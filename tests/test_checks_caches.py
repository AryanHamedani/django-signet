"""signet.W013 and signet.W014: cache backends the library must not rely on."""

import pytest

from django_signet.checks import check_grace_cache, check_token_store

_CACHE_STORE = "django_signet.sessions.stores.cache.CacheTokenStore"
_LOCMEM = {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}


@pytest.fixture
def file_cache(tmp_path):
    return {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": str(tmp_path),
    }


DB_CACHE = {
    "BACKEND": "django.core.cache.backends.db.DatabaseCache",
    "LOCATION": "signet_cache_table",
}


@pytest.mark.parametrize("kind", ["file", "db"])
def test_a_grace_cache_that_keeps_expired_entries_warns(settings, file_cache, kind):
    """A grace entry's raw refresh token stays valid until the session
    next refreshes; these backends keep the expired entry on disk."""
    settings.CACHES = {
        "default": _LOCMEM,
        "grace": file_cache if kind == "file" else DB_CACHE,
    }
    settings.SIGNET = {"GRACE_CACHE": "grace"}

    messages = check_grace_cache(None)

    assert [m.id for m in messages] == ["signet.W013"]
    assert not messages[0].is_serious()
    assert "'grace'" in messages[0].msg


def test_a_grace_cache_that_expires_entries_itself_is_quiet(settings):
    settings.CACHES = {"default": _LOCMEM}
    settings.SIGNET = {"GRACE_CACHE": "default"}
    assert check_grace_cache(None) == []


def test_a_cache_store_on_a_file_based_cache_warns(settings, file_cache):
    """FileBasedCache.add() checks, then writes: two racing refreshes of
    one token can both win the claim."""
    settings.CACHES = {"default": _LOCMEM, "files": file_cache}
    settings.SIGNET = {"STORE": _CACHE_STORE, "STORE_OPTIONS": {"alias": "files"}}

    ids = [m.id for m in check_token_store(None)]

    assert ids == ["signet.W014", "signet.W007"]


def test_a_cache_store_on_an_atomic_cache_does_not_warn_w014(settings):
    settings.CACHES = {"default": _LOCMEM}
    settings.SIGNET = {"STORE": _CACHE_STORE}
    assert [m.id for m in check_token_store(None)] == ["signet.W007"]
