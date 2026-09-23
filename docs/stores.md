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
| `revoke_all_for_user` | supported | **not supported - raises `NotImplementedError`** |
| Cost per refresh | one DB round trip, in a transaction | one or two cache round trips |
| Mode | allowlist only | allowlist (default) or denylist (`deny_by_default=True`) |

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
