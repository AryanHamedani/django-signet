# Choosing a store

`TokenStore` is one abstraction behind two opposite defaults. They are not
separate features: a denylist returns `True` from `is_live()` unless
something was explicitly revoked; an allowlist returns `False` unless
something was explicitly issued and is still live. `ORMTokenStore` is always
an allowlist. `CacheTokenStore(deny_by_default=...)` can be either.

| | `ORMTokenStore` (default) | `CacheTokenStore` |
|---|---|---|
| Durability | survives restarts | lost on cache flush or eviction |
| Atomicity primitive | conditional `UPDATE ... WHERE consumed_at IS NULL` | `cache.add()` compare-and-set |
| `revoke_all_for_user` | supported | **not supported - raises `NotImplementedError`** (system check `signet.W007`) |
| Cost per refresh | one DB round trip, in a transaction | one or two cache round trips |
| Mode | allowlist only | allowlist (default) or denylist (`deny_by_default=True`) |

## Configuring the store

One setting chooses the store for everything - login, refresh and logout,
the `Strict*` liveness check, and password-change revocation - so they can
never disagree about where a session lives:

```python
SIGNET = {
    "STORE": "django_signet.sessions.stores.cache.CacheTokenStore",
    "STORE_OPTIONS": {"alias": "default", "deny_by_default": True},
}
```

`STORE` is a dotted path (or a `TokenStore` subclass) and defaults to
`"django_signet.sessions.stores.orm.ORMTokenStore"`; `STORE_OPTIONS` is
passed to its constructor as keyword arguments. A path, not an instance,
because `settings.py` cannot import a module that imports models.
`manage.py check` reports `signet.E010` if the store cannot be built.

A subclass can still pin its own store - `store = CacheTokenStore()` on a
`RotationPolicy` or authentication subclass wins over the setting - but
then every component that must agree with it has to be pinned the same
way. Prefer the setting.

## Why `revoke_all_for_user` is not supported

Burning every family for a user (logout-everywhere) requires enumerating
that user's families. A cache has no query interface for this, and
`cache.keys()` / key-pattern scanning is **not** part of Django's cache API
- it doesn't exist on every backend (Memcached in particular has no way to
list its keys at all). `CacheTokenStore.revoke_all_for_user()` raises
`NotImplementedError` with a message pointing at `ORMTokenStore` rather
than silently doing nothing, or inventing a scan that would work on some
backends and not others. If your deployment needs logout-everywhere on a
cache-backed store, maintain your own application-level index of family ids
per user (outside this library) or use `ORMTokenStore`.

What that means in practice, under `CacheTokenStore`:

- **A password change revokes nothing.** The password is still saved - a
  store limitation must not break every password change - and a warning is
  logged from `django_signet.revocation`, but existing sessions stay live
  until they expire or are logged out individually.
- **`POST logout-all` returns `501 Not Implemented`.**

`manage.py check` reports both as warning `signet.W007` at startup.

## Atomicity: what `cache.add()` gives you, and what it doesn't

`cache.add()` is the only compare-and-set primitive every Django cache
backend implements - it sets a key only if that key is currently absent,
and reports whether it won. There is no cache-level transaction and no
conditional update (no cache equivalent of `UPDATE ... WHERE x IS NULL`).
`CacheTokenStore.consume()` decides `LIVE` versus `ALREADY_CONSUMED` solely
from whether its own `add()` call won - never from a prior `get()` - so two
concurrent callers racing to consume the same token can never both win.

**The one thing `cache.add()` cannot do that a single `UPDATE` can:** fold a
family's revocation state into the same atomic write as the claim.
`ORMTokenStore._claim()` re-checks `family__revoked_at__isnull=True` inside
the very statement that claims the token, so a family revoked mid-consume
(for example, a sibling token's reuse burning the family a moment before
this token is claimed) reliably yields `FAMILY_REVOKED`, never `LIVE`.

`CacheTokenStore` cannot do that in one step, because `add()` only ever
tests one key. Its approximation: after winning the `add()`, it re-reads
the revocation key and reports `FAMILY_REVOKED` instead of `LIVE` if a
revocation landed in the meantime. This **narrows** the window in which a
mid-flight revocation is missed - down to the gap between that re-check and
whatever the caller does with the result - but it does **not close** it the
way `ORMTokenStore`'s single conditional `UPDATE` does. A revocation that
lands after the re-check but before the caller acts on `Outcome.LIVE` will
still be reported as `LIVE`. If closing that window matters for your
threat model, use `ORMTokenStore`.

## Other cache-specific caveats

- `family_revoked` fires from both stores with the same arguments
  (`user`, `family`, `reason`), once, for the first revocation of a family
  the store still holds. Under `CacheTokenStore` a revocation of a family
  whose cache entry has already expired or been evicted records the
  revocation marker but fires nothing - there is no family left to report.

- Revocation markers are cached with `timeout=None` (cache forever), not
  with the family's remaining TTL, so a denylist entry cannot silently
  expire and revive a family it recorded as revoked. On a memory-bounded
  backend this means revocations accumulate for as long as the backend
  keeps them; `ORMTokenStore` has no such concern since its revocation
  state lives in the same row as the family, not a separate ever-growing
  key.
- `purge_expired()` is a no-op (returns `0`): every key this store writes
  carries its own TTL, so the cache backend already reclaims expired
  entries on its own.
- A family whose cache entry disappears - because it was actually revoked,
  or because its TTL simply lapsed, or because the backend evicted it under
  memory pressure - is indistinguishable from the outside. `consume()`
  reports all three as `FAMILY_REVOKED` rather than a false `LIVE`, since
  denying a refresh that should have worked is recoverable; silently
  reviving one that shouldn't is not.
