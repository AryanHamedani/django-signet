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
  refresh cookie's path. They do not inspect class-level configuration,
  which is arbitrary Python.

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
  successful login into a 500. Decisions belong in hooks
  (`on_reuse_detected`, `on_authentication_failed`), which are unchanged.
