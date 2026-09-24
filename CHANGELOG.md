# Changelog

## 0.1.0 - unreleased

First release. **The public API is not frozen until 1.0**: in 0.x a hook
may still be renamed, moved or change shape in a minor release when a
design flaw demands it, and every such change is listed here.

- httpOnly cookie transport with correct `__Host-` / `__Secure-` prefixes;
  the refresh cookie is scoped to the auth mount prefix (`/api/auth/`)
- Refresh rotation with token families and RFC 9700 reuse detection
- Idempotent grace window for concurrent refreshes
- Refresh tokens stored as sha256 digests only
- Refresh re-checks the user on every rotation: a disabled account cannot
  mint new tokens, and its session is burned
- Custom claims (`get_claims`) are re-derived on every refresh
- Logout and logout-all act on the refresh credential, so they work after
  the access cookie has expired, and redeem the refresh token rather than
  merely checking its family; logout is idempotent, and a response clears
  cookies only when the request presented a credential and passed CSRF
- `TokenStore` port with ORM and cache adapters, allowlist or denylist,
  chosen by one `SIGNET["STORE"]` setting for every component
- Stateless access verification plus opt-in `Strict*` classes
- Realms: one `SignetViewMixin` subclass, turned into all five endpoints by
  `signet_urls()`; header-transport realms for mobile and service clients
- Double-submit CSRF with constant-time comparison, enforced on the
  access-token authenticator and on refresh, logout and logout-all; the CSRF
  cookie expires with the refresh cookie
- Login accepts JSON only (no form-encoded login CSRF)
- Django system checks for specific misconfigurations of the `SIGNET`
  setting and the mounted URLs: non-`Secure` cookies in production,
  JavaScript-readable auth cookies, a `__Host-` name on a path-scoped
  cookie, a missing grace cache, missing RSA keys, wrong-typed values, an
  unusable or limited token store, and auth URLs mounted outside the
  refresh cookie's path. Apart from each mounted refresh-credential view's
  `CookiePolicy` (signet.E008), they do not inspect class-level
  configuration, which is arbitrary Python.

### Changed before release

- `RotationPolicy.rotate(extra=...)` became `rotate(get_claims=...)`: the
  callable receives the user loaded from the refresh token's subject.
- `LogoutView` and `LogoutAllView` no longer authenticate via the access
  token (they are `AllowAny` and read the refresh credential); a failed
  CSRF check on them answers 403, as refresh does.
- `COOKIE_REFRESH_PATH` defaults to `/api/auth/` (was `/api/auth/refresh`).

### Fixed before release

- **Security:** a signal receiver can no longer change an authentication
  outcome. Every signal (`token_issued`, `token_refreshed`,
  `token_reuse_detected`, `family_revoked`) is now sent through
  `django_signet.signals.send`, which uses `send_robust()` and logs each
  receiver exception, with its traceback, at `error` on the
  `django_signet.signals` logger. Previously a raising `family_revoked`
  receiver rolled back a logout's revocation (logout answered 500 and the
  session stayed live), and a raising `token_issued` receiver turned a
  successful login into a 500. Inside a transaction the receivers run
  under their own savepoint, so a receiver whose database write fails
  cannot silently roll back the revocation. A failure of the dispatch
  itself (Django's failure logging raises on a callable-instance receiver)
  is logged and ignored as well. A decision that should change the
  outcome belongs in a hook such as `validate_claims` or
  `RotationPolicy.get_user`.
- **Security:** `RotationPolicy.on_reuse_detected` can no longer undo a
  reuse burn. The hook runs after the burn is written, but under
  `ATOMIC_REQUESTS` before it is committed, so a hook that raised rolled
  the burn back: the request answered 500 and the replayed family stayed
  live. Its exceptions are now logged at `error` on
  `django_signet.sessions.rotation` and ignored, and the replay is refused
  with `TokenReused` as usual.
- System check `signet.E010` now reports *any* exception raised while
  building the configured store - a store constructor rejecting its
  `STORE_OPTIONS` with `ValueError`, say - naming the exception's type and
  message. Previously only `ImportError` and `TypeError` were converted and
  anything else crashed `manage.py check`. `get_store()` itself still
  raises at runtime.
- System check `signet.E002` now checks every explicitly configured cookie
  name - `COOKIE_ACCESS_NAME`, `COOKIE_REFRESH_NAME` and `COOKIE_CSRF_NAME`,
  not only the refresh cookie's - against the browser-enforced prefix
  contract: `__Host-` requires `Secure`, `Path=/` and no `Domain`;
  `__Secure-` requires `Secure`. It now also catches a prefixed name under
  `COOKIE_SECURE=False`. Each violated requirement is its own message,
  naming the setting and the cookie. Prefixes are matched
  case-insensitively, as browsers do. A derived (`None`) name is never
  flagged.
- System check `signet.E004` no longer rejects a verify-only resource
  server. It is now raised only for an RS algorithm with no
  `VERIFYING_KEY`, which verifies nothing. An RS algorithm with no
  `SIGNING_KEY` - where `get_backend()` still verifies and only signing
  fails - is the new Warning `signet.W011`: login and refresh cannot work
  there, which is expected on a resource server that holds no private key.
- The cookie authentication classes now answer a failed CSRF check with
  **403** (`PermissionDenied`), as DRF's `SessionAuthentication` does and
  as this library's own refresh and logout views already did. It was a
  401, which told a client to refresh a session that was fine and hid the
  real fault, a missing or wrong `X-CSRF-Token` header. The body is still
  the one generic failure message.
- Logout through a realm whose transport sets no cookies (a header
  client) answers **401** to a request that presents no credential. It
  answered 200 "Signed out." while the session stayed live. A browser
  logout that presents nothing still answers 200.
- New system check `signet.W012` warns when `COOKIE_SAMESITE` is `"None"`
  and `COOKIE_SECURE` is off: Chromium-based browsers silently reject such
  a cookie.
- `django_signet.checks` is now a package (`settings`, `cookies`, `urls`).
  Every check is still importable from `django_signet.checks`.
- **Security:** a refresh that fails part-way can no longer spend its
  token. `rotate()` consumed the refresh token and only then signed and
  issued the successor, so a signing failure (a verify-only deployment
  sharing the store) or a failed `issue()` left the token spent with no
  successor handed out - and the client's retry was burned as reuse. The
  successor is now signed before the consume, and the consume and the
  issue share one transaction. (A store outside the database, such as
  `CacheTokenStore`, gets the signing half.)
- **Security:** `on_reuse_detected` now runs under its own savepoint, like
  a signal receiver. Catching its exception was not enough: a database
  write in the hook that failed had already marked the request's
  transaction for rollback under `ATOMIC_REQUESTS`, so the burn was
  silently undone while the replay still answered 401.
- `aud` and `iss` returned from `get_claims` are now dropped. They are
  verified against the `AUDIENCE` and `ISSUER` settings: an `aud` with
  `AUDIENCE` unset made every token fail verification, and an `iss` was
  signed and never checked.
- `CacheTokenStore` revocation markers now expire. They were written with
  no timeout, so under a `noeviction` policy every logout and burn added
  a key that was never removed, until the cache refused writes. A marker
  now lives for the family's remaining lifetime plus the refresh and
  access lifetimes and `LEEWAY`. After that no token of the family can
  verify, so the denylist cannot revive it.
- The `CacheTokenStore` docstring no longer claims every Django cache
  backend implements `add()` atomically: `FileBasedCache` does not, and
  must never back the store.
- Refresh loads the user once, not twice. `SessionPair` gains an optional
  `user`, which `token_refreshed` now receives without a second query.
- `CacheTokenStore`'s spent-token marker now outlives the token it marks.
  It used the same rounded-down TTL as the token's own cache entry, so it
  could expire a fraction of a second first, and in that tail a spent
  token redeemed as LIVE. It is now rounded up, plus a second.
- New system check `signet.W013` warns when `GRACE_CACHE` names a
  `DatabaseCache` or `FileBasedCache`. A grace entry holds a raw refresh
  token that stays valid until the session next refreshes, and these
  backends keep an expired entry until it is read or culled, so a copy of
  the table or directory can hold live refresh tokens long after the
  window.
- New system check `signet.W014` warns when the token store is backed by
  a `FileBasedCache`, whose `add()` checks and then writes, so reuse
  detection can miss a concurrent replay.
