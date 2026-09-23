"""Sessions in a cache, as a denylist."""

SIGNET = {
    "STORE": "django_signet.sessions.stores.cache.CacheTokenStore",
    "STORE_OPTIONS": {"alias": "default", "deny_by_default": True},
}
