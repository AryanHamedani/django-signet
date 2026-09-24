"""Sessions in a cache, as an allowlist: the store's default mode."""

SIGNET = {
    "STORE": "django_signet.sessions.stores.cache.CacheTokenStore",
    # A cache that never evicts: see "Survive eviction" on the same page.
    "STORE_OPTIONS": {"alias": "default", "deny_by_default": False},
}
