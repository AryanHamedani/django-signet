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
| Work per refresh | five queries: load the user, then, in one transaction, read the token and its session, claim it, record the session's last use and insert the successor | one query, to load the user, and six cache calls |
| Logout-all and password-change revocation | supported | **not supported**: warning `signet.W007` |
| Mode | allowlist | allowlist (default) or denylist (`deny_by_default=True`) |
| Expired rows | deleted by `signet_purge` | expire on their own |

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
`"django_signet.sessions.stores.orm.ORMTokenStore"`. The default is a path
because `settings.py` cannot import a module that imports models.
[`STORE_OPTIONS`](../reference/settings.md#store_options) is passed to its
constructor as keyword arguments; for `CacheTokenStore` they are `alias`,
the cache to use (`"default"`), and `deny_by_default` (`False`).
`manage.py check` reports
[`signet.E010`](../reference/checks.md#signete010---the-configured-store-could-not-be-built)
if the store cannot be built.

The setting is the only supported way to choose a store. Assigning one on a
class instead, `store = CacheTokenStore()` on a `RotationPolicy` or
authentication subclass, does override the setting for that class. But
password-change revocation, `signet_purge` and the system checks build the
store from the setting and cannot be overridden that way. Sessions then
live in two stores that disagree: a password change revokes nothing in the
one you assigned, and the checks inspect the other.

The example keeps the default allowlist mode. The two modes differ for a
session the cache no longer holds, because its entry expired, was evicted
or was lost in a flush. An allowlist refuses its access tokens at the
`Strict*` classes; a denylist accepts them until they expire, unless it
holds a revocation marker for the session. Refresh fails in both modes.
Choose the denylist only if a cache flush must not end every `Strict*`
session at once - it buys at most one access-token lifetime, since refresh
fails after a flush either way - and accept that it trusts what it has
forgotten.

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
It is the store's only atomic step; there are no transactions and no
conditional updates. `CacheTokenStore.consume()` decides "live" or "already
consumed" from whether its own `add()` won, never from an earlier read, so
two requests racing to consume the same token cannot both win, provided the
backend's `add()` is atomic.

Redis, Memcached, `DatabaseCache` and, within one process, `LocMemCache`
implement `add()` atomically. `FileBasedCache` does not: it checks for the
key, then writes it, so two requests can both win. Never use it for the
store; `manage.py check` warns about it as `signet.W014`.

What `add()` cannot do is also check the session's revocation in the same
step. `ORMTokenStore` rechecks `revoked_at IS NULL` inside the `UPDATE` that
claims the token, so a session revoked a moment before the claim is always
reported revoked. `CacheTokenStore` rereads the revocation marker after its
`add()` wins. That narrows the gap but does not close it: a revocation that
lands after the reread is missed. If that gap matters to you, use
`ORMTokenStore`.

### Survive eviction

A cache with an eviction policy removes keys before their timeout. Redis
under `allkeys-lru` or `volatile-lru` does so under memory pressure, and so
does Memcached, by design, unless it runs with `-M`. `LocMemCache`,
`FileBasedCache` and `DatabaseCache` cull when they reach `MAX_ENTRIES`,
300 by default: each login writes two keys and each refresh three more
(counting the grace entry, when `GRACE_CACHE` is the same cache), so with
default options they start culling after roughly a hundred logins and
refreshes. Two of
the store's keys matter:

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
Redis with `maxmemory-policy noeviction`, and size it for the load. Every
key the store writes has a timeout, so what it holds is bounded by your
login and refresh rate over those timeouts; see the revocation markers
below. When such a cache fills, it refuses writes instead, and logins,
refreshes and logouts fail until it has room. If you cannot give it a cache
like that, use `ORMTokenStore`.

### Survive a restart or a failover

A write the cache acknowledged can still be lost. Redis restarted from an
RDB snapshot comes back without the writes made since the snapshot, and a
failover to an asynchronous replica drops the writes the replica had not
received. If a spent-token marker is lost while the token's own entry
survives, from an earlier write, the spent token redeems again: the same
failure as eviction. A revocation made since the snapshot is lost the
same way: the session's entry comes back without its marker, and a
logged-out or burned session refreshes again. Use AOF persistence
(`appendfsync always` loses nothing), and treat a failover as a gap in
both reuse detection and revocation. Clearing the store's keys afterwards
closes both gaps, at the cost of ending every session.

## Other cache-store caveats

- **Revocation markers outlive the session.** A marker lasts for the
  session's remaining lifetime plus `REFRESH_TOKEN_LIFETIME`,
  `ACCESS_TOKEN_LIFETIME` and `LEEWAY`, and at least 60 seconds. By then no
  token of the session can verify, so a denylist cannot forget a revocation
  it still needs. `signet_purge` has nothing to do with them; see
  {doc}`purging`.
- **A vanished session reads as revoked.** Whether its entry was revoked,
  reached its timeout, or was evicted, `consume()` reports it revoked
  rather than live: refusing a refresh that should have worked can be
  recovered from; reviving one that should not cannot.
- **`family_revoked` fires only for a session the store still holds.** It
  is sent with the same arguments as under `ORMTokenStore`, `user`,
  `family` and `reason`, once, for the first revocation. Revoking a session
  whose entry has already expired or been evicted records the marker but
  sends nothing: there is no user or session left to report.
