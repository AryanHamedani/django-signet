# Choose a token store

The token store records every session and every refresh token it has
issued. Login, refresh, logout, the `Strict*` liveness check and
password-change revocation all go through it. The library ships two:

- `ORMTokenStore`, the default, keeps them in your database.
- `CacheTokenStore` keeps them in a Django cache.

`TokenStore` is one abstraction behind two opposite defaults. An allowlist
answers `is_live()` with `False` unless it holds the session, unrevoked and
unexpired. A denylist answers `True` unless a revocation was recorded for
it. `ORMTokenStore` is always an allowlist. `CacheTokenStore` is an
allowlist by default and a denylist with `deny_by_default=True`.

| | `ORMTokenStore` (default) | `CacheTokenStore` |
|---|---|---|
| Durability | survives restarts | lost when the cache is flushed, and entry by entry when it evicts |
| Claiming a refresh token | one conditional `UPDATE ... WHERE consumed_at IS NULL`, which also rechecks that the session is unrevoked | `cache.add()`, then a second read of the revocation marker |
| Work per refresh | five queries: load the user, read the token and its session, claim it, record the session's last use, insert the successor | one query, to load the user, and six cache calls |
| Logout-all and password-change revocation | supported | **not supported**: warning `signet.W007` |
| Mode | allowlist | allowlist (default) or denylist (`deny_by_default=True`) |
| Expired rows | deleted by `signet_purge` | expire on their own, except revocation markers |

Unless the grace window is turned off, both stores' refreshes also write the
new pair to [`GRACE_CACHE`](../reference/settings.md#grace_cache).

## Configure the store

One setting chooses the store for everything, so login, refresh, logout,
the `Strict*` check, password-change revocation and `signet_purge` never
disagree about where a session lives:

```{literalinclude} ../examples/cache_store_settings.py
:language: python
:start-at: SIGNET
```

[`STORE`](../reference/settings.md#store) is a dotted path, or a
`TokenStore` subclass, and defaults to
`"django_signet.sessions.stores.orm.ORMTokenStore"`.
[`STORE_OPTIONS`](../reference/settings.md#store_options) is passed to its
constructor as keyword arguments; for `CacheTokenStore` they are `alias`,
the cache to use (`"default"`), and `deny_by_default` (`False`). A path
rather than a class, because `settings.py` cannot import a module that
imports models. `manage.py check` reports
[`signet.E010`](../reference/checks.md#signete010---the-configured-store-could-not-be-built)
if the store cannot be built.

The setting is the only supported way to choose a store. Assigning one on a
class instead, `store = CacheTokenStore()` on a `RotationPolicy` or
authentication subclass, does override the setting for that class. But
password-change revocation, `signet_purge` and the system checks build the
store from the setting and cannot be overridden that way. Sessions then
live in two stores that disagree: a password change revokes nothing in the
one you assigned, and the checks inspect the other.

To write a store of your own, subclass `TokenStore`; see
{doc}`../reference/sessions`. The port is public API, but the API is not
frozen until 1.0.

## What the cache store cannot do

### Revoke every session of a user

Logout-everywhere, and revoking sessions on a password change, need every
session of a user. Django's cache API has no way to list or search keys, so
`CacheTokenStore.revoke_all_for_user()` raises `NotImplementedError` rather
than silently doing nothing. Under `CacheTokenStore`:

- **A password change revokes nothing.** The password is still saved, and
  a warning is logged on `django_signet.revocation`, but existing sessions
  stay live until they expire or are logged out one by one.
- **`POST logout-all` answers 501** to a request whose refresh token
  verifies and passes CSRF. Without such a token it answers 401, or 403 for
  a failed CSRF check, as under any store.

`manage.py check` reports both as warning
[`signet.W007`](../reference/checks.md#signetw007---store-cannot-revoke-every-session-for-a-user).
If you need them, use `ORMTokenStore`, or keep your own index of session
ids per user outside the library.

### Fold revocation into the claim

`cache.add()` sets a key only if it is absent, and reports whether it did.
It is the only compare-and-set every Django cache backend implements. There
are no transactions and no conditional updates. `CacheTokenStore.consume()`
decides "live" or "already consumed" from whether its own `add()` won, never
from an earlier read, so two requests racing to consume the same token
cannot both win.

What `add()` cannot do is also check the session's revocation in the same
step. `ORMTokenStore` rechecks `revoked_at IS NULL` inside the `UPDATE` that
claims the token, so a session revoked a moment before the claim is always
reported revoked. `CacheTokenStore` rereads the revocation marker after its
`add()` wins. That narrows the gap but does not close it: a revocation that
lands after the reread is missed. If that gap matters to you, use
`ORMTokenStore`.

### Survive eviction

A cache with an eviction policy removes keys under memory pressure, before
their timeout. Redis under `allkeys-lru` or `volatile-lru`, Memcached, and
`LocMemCache` at `MAX_ENTRIES` all do. Two of the store's keys matter:

- **The marker that records a spent refresh token.** Reuse detection
  depends on it. If it is evicted, the spent token redeems again as if it
  were current, in either mode. A stolen token's replay is then not
  detected: it forks the session instead of burning it, and both copies
  keep refreshing. This marker carries a timeout, so `volatile-lru` can
  evict it too.
- **Revocation markers, in denylist mode.** A denylist answers "live" for
  any session it has no marker for, so an evicted marker revives the
  session for the `Strict*` authentication classes: a logged-out or burned
  session authenticates again. Refresh is not affected, because revoking a
  session also deletes its entry, and `consume()` treats a missing session
  as revoked.

If you use `CacheTokenStore`, give it a cache that never evicts, such as
Redis with `maxmemory-policy noeviction`, and size it for the load. When it
fills, such a cache refuses writes instead, and logins and refreshes fail
until it has room. If you cannot, use `ORMTokenStore`.

## Other cache-store caveats

- **Revocation markers are kept forever.** They are written with no
  timeout, so that a denylist cannot forget a revocation when a timeout
  passes. They accumulate for as long as the cache keeps them, and
  `signet_purge` does not remove them; see {doc}`purging`.
- **A vanished session reads as revoked.** Whether its entry was revoked,
  reached its timeout, or was evicted, `consume()` reports it revoked
  rather than live: refusing a refresh that should have worked can be
  recovered from; reviving one that should not cannot.
- **`family_revoked` fires only for a session the store still holds.** It
  is sent with the same arguments as under `ORMTokenStore`, `user`,
  `family` and `reason`, once, for the first revocation. Revoking a session
  whose entry has already expired or been evicted records the marker but
  sends nothing: there is no user or session left to report.
