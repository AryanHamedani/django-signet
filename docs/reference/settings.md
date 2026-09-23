# Settings

Every Signet setting lives in one place: the `SIGNET` dict in your Django
project settings. There is no separate top-level `SIGNET_*` setting for
any of these - `SIGNET` is always a single dict, or absent entirely.

```python
SIGNET = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "COOKIE_SECURE": True,
    # ...
}
```

Source of truth: `src/django_signet/conf.py`, `DEFAULTS`.

## Resolution order

Every setting below is read through the `setting()` descriptor
(`django_signet.conf.setting`), used on the class that actually consumes
it - `AccessToken.lifetime`, `RotationPolicy.grace_window`,
`CookiePolicy.secure`, and so on. `setting()` resolves highest priority
first:

1. **A literal assigned on a subclass.** Setting a plain value - e.g.
   `class MyPolicy(CookiePolicy): secure = False` - shadows the
   descriptor entirely through normal Python attribute lookup, so
   `setting.__get__` never runs. This needs no special support from the
   library; it is how descriptors work.
2. **The project's `SIGNET` dict.** If the class attribute is still the
   descriptor, its value is looked up in `settings.SIGNET`.
3. **The default.** Either the `default=` argument passed to `setting()`
   for that particular attribute, or, if none was given,
   `DEFAULTS[name]` below.

Nothing is cached anywhere in this chain: every access re-reads
`settings.SIGNET`, which is what lets `django.test.override_settings`
change behaviour between tests without a process restart.

`CookiePolicy` additionally accepts every one of its settings as an
`__init__` keyword - `CookieTransport(CookiePolicy(secure=False))` - which
also becomes a plain instance attribute and wins the same way a subclass
literal does.

## Token settings

### `ACCESS_TOKEN_LIFETIME`

- **Type:** `datetime.timedelta`
- **Default:** `timedelta(minutes=5)`
- Lifetime of a minted access token, consumed as `AccessToken.lifetime`.
- Override on a class: `class MyAccessToken(AccessToken): lifetime = timedelta(minutes=2)`.

### `REFRESH_TOKEN_LIFETIME`

- **Type:** `datetime.timedelta`
- **Default:** `timedelta(days=14)`
- Lifetime of a minted refresh token, consumed as `RefreshToken.lifetime`.
  This is also the lifetime of the session family it opens: the family's
  `expires_at` is set from it at login (see `RotationPolicy.open_session`).
- Override the same way as `ACCESS_TOKEN_LIFETIME`, on a `RefreshToken` subclass.

### `ALGORITHM`

- **Type:** `str`
- **Default:** `"HS256"`
- The JWT signing algorithm. Any of `HS256`/`HS384`/`HS512` (symmetric,
  `HMACBackend`) or `RS256`/`RS384`/`RS512` (asymmetric, `RSABackend`,
  needs the `rsa` extra). Resolved fresh on every `get_backend()` call
  through a private factory (`tokens.backends._BackendFactory`), not
  exposed as an overridable class attribute the way the token lifetimes
  are - it is `SIGNET`-dict-only.
- An `RS*` algorithm with no `VERIFYING_KEY` is system check
  `signet.E004`, an error; with no `SIGNING_KEY` it is `signet.W011`, a
  warning.

### `SIGNING_KEY`

- **Type:** `str | None`
- **Default:** `None`
- For an `HS*` algorithm, `None` falls back to `settings.SECRET_KEY`; an
  explicit value overrides it. For an `RS*` algorithm this is the PEM
  private key - `SECRET_KEY` is never a valid RSA key. Without it,
  `get_backend()` still builds a backend that verifies, but signing
  raises `ImproperlyConfigured`: login and refresh fail, and access tokens
  minted elsewhere are still accepted. That is expected on a verify-only
  resource server, so it is warning `signet.W011`, not an error.

### `VERIFYING_KEY`

- **Type:** `str | None`
- **Default:** `None`
- Unused for `HS*` algorithms. For `RS*` it must be a PEM public key.
  Without it, `get_backend()` raises `ImproperlyConfigured`, so no token
  can be signed or verified: login fails with a 500, and so does every
  request that presents a token to refresh, logout, logout-all or a
  Signet-authenticated view. System check `signet.E004` reports it at
  startup.

### `AUDIENCE`

- **Type:** `str | None`
- **Default:** `None`
- When set, becomes the token's `aud` claim at mint time and is checked
  at verify time. `None` means the claim is omitted entirely, not set to
  an empty value - see `Token.audience` and `build_claims`.

### `ISSUER`

- **Type:** `str | None`
- **Default:** `None`
- Same treatment as `AUDIENCE`, for the `iss` claim.

### `LEEWAY`

- **Type:** `datetime.timedelta`
- **Default:** `timedelta(seconds=0)`
- Clock-skew tolerance applied by `SigningBackend.verify` when checking
  `exp`/`nbf`. Consumed as `Token.leeway`.

## Rotation and reuse-detection settings

### `GRACE_WINDOW`

- **Type:** `datetime.timedelta`
- **Default:** `timedelta(seconds=10)`
- How long a just-consumed refresh token's resulting pair is cached, so
  that a benign replay of the same token (two browser tabs, React
  StrictMode double-invoking an effect) is answered idempotently instead
  of being treated as theft. A `GRACE_WINDOW` of zero or less disables
  the window (see `GRACE_CACHE` below) - every replay is then strict
  reuse. Consumed as `RotationPolicy.grace_window`.

### `GRACE_CACHE`

- **Type:** `str | None`
- **Default:** `"default"`
- The Django cache alias the grace window is stored in. `None` disables
  the grace window deliberately, falling back to strict RFC 9700
  behaviour where *any* replay of a consumed refresh token burns its
  family - a legitimate choice, not a misconfiguration, so it is not
  reported by any system check. An alias that does not name a configured
  cache **is** reported, as `signet.W003`: rotation still works, but
  every double-tab replay is then indistinguishable from theft. Consumed
  as `RotationPolicy.grace_cache`.

## Token store settings

### `STORE`

- **Type:** `str` (a dotted path) or a `TokenStore` subclass
- **Default:** `"django_signet.sessions.stores.orm.ORMTokenStore"`
- Which `TokenStore` adapter backs sessions. A dotted path rather than an
  imported class by default because `settings.py` cannot import a module
  that imports models - see `django_signet.sessions.stores.factory.get_store`.
  Resolved fresh on every access (never cached), through the private
  `_StoreSettings` class.
- **`SIGNET["STORE"]` is the only supported way to choose a store.**
  Login, refresh and logout, the `Strict*` liveness check,
  password-change revocation, `manage.py signet_purge` and the system
  checks all have to agree on where sessions live, and password-change
  revocation, `signet_purge` and the checks call `get_store()` directly.
  Assigning a store on one class instead - `store = MyTokenStore()` on a
  `RotationPolicy` subclass, say - reaches only that class, and splits
  sessions across two stores: a password change revokes nothing in the
  pinned store, `Strict*` checks a different store from the one logout
  revoked in, and the checks inspect the wrong one.
- Anything that goes wrong building the store - an unimportable path, a
  constructor that rejects `STORE_OPTIONS` with any exception, or an
  object that is not a `TokenStore` - is `signet.E010`. A store whose
  `supports_revoke_all_for_user` is `False` is `signet.W007`.

### `STORE_OPTIONS`

- **Type:** `dict[str, Any]`
- **Default:** `{}`
- Keyword arguments passed to `STORE`'s constructor, the same shape as
  Django's own `CACHES[...]["OPTIONS"]`. For `CacheTokenStore`, this is
  where `alias` and `deny_by_default` are set:
  `STORE_OPTIONS = {"alias": "signet", "deny_by_default": True}`.

## Cookie settings

Every `COOKIE_*` setting below is read by `CookiePolicy`
(`src/django_signet/transport/cookie.py`), which every cookie-writing
transport (`CookieTransport`, and `HybridTransport` through its cookie
half) shares. The `__Host-`/`__Secure-` prefix rules applied to the
*derived* cookie names are browser-enforced, not stylistic:

- `__Host-` requires `Secure`, `Path=/`, and no `Domain` attribute.
- `__Secure-` requires `Secure` only.

A `__Host-` cookie that does not meet its requirements is silently
dropped by the browser - no error, the request just arrives
unauthenticated - which is why the access and CSRF cookies (root-scoped)
can use `__Host-` but the refresh cookie (scoped to `COOKIE_REFRESH_PATH`)
is confined to `__Secure-`.

**An explicit `COOKIE_ACCESS_NAME`, `COOKIE_REFRESH_NAME` or
`COOKIE_CSRF_NAME` is used verbatim and bypasses this prefixing
entirely** - `CookiePolicy.access_name` returns
`self.explicit_access_name or self.resolved_name(...)`, so setting an
explicit name opts out of automatic `__Host-`/`__Secure-` prefixing for
that cookie, even under `COOKIE_SECURE=True`. `signet.E002` still checks
every explicit name that starts with `__Host-` or `__Secure-` (matched
case-insensitively, as browsers do) against the attributes the settings
give that cookie, since the prefix is browser-interpreted regardless of
how the name was set.

### `COOKIE_PREFIX`

- **Type:** `str`
- **Default:** `"signet"`
- The base name every derived cookie name is built from:
  `{prefix}-access`, `{prefix}-refresh`, `{prefix}-csrf`, before any
  `__Host-`/`__Secure-` prefix is applied.

### `COOKIE_SAMESITE`

- **Type:** `str`
- **Default:** `"Lax"`
- Passed straight through to `response.set_cookie(samesite=...)` for
  every cookie this library sets. `"None"` with `COOKIE_SECURE` off is
  `signet.W012`: browsers reject such a cookie.

### `COOKIE_SECURE`

- **Type:** `bool`
- **Default:** `True`
- Whether cookies are marked `Secure`, and the gate on `__Host-`/`__Secure-`
  prefixing (`resolved_name` returns the base name, unprefixed, when this
  is `False`). Any false value (`False`, `0`, `None`, `""`) while
  `DEBUG=False` is `signet.E001`.

### `COOKIE_HTTPONLY`

- **Type:** `bool`
- **Default:** `True`
- Governs the **access and refresh** cookies only - the CSRF cookie is
  always JavaScript-readable by design, since the double-submit scheme
  requires the client to read and echo it back (see `issue_csrf`).
  `False` is `signet.W009`, a warning rather than an error: unlike
  `COOKIE_SECURE=False` there is no legitimate local-HTTP reason to need
  it, but it is a deliberate, settable choice.

### `COOKIE_REFRESH_PATH`

- **Type:** `str`
- **Default:** `"/api/auth/"`
- The `Path` the refresh cookie is scoped to. This is the auth mount
  prefix, not the refresh endpoint alone: logout and logout-all also
  redeem the refresh token, so the path has to reach all three
  (`refresh`, `logout`, `logout-all`). A URLconf that mounts any of them
  outside this path fails `signet.E008` at startup rather than failing
  silently at request time (a browser never sends a cookie to a path it
  isn't scoped to). Must be a `str`; a wrong-typed value is `signet.E006`
  because it is written straight into the cookie's `Path` attribute.

### `COOKIE_DOMAIN`

- **Type:** `str | None`
- **Default:** `None`
- Passed straight through to `response.set_cookie(domain=...)`. A
  non-`None` value also disqualifies the access and CSRF cookies from the
  `__Host-` prefix (`__Host-` forbids `Domain` entirely), so they fall
  back to `__Secure-` instead.

### `COOKIE_ACCESS_NAME`

- **Type:** `str | None`
- **Default:** `None` (derive the name from `COOKIE_PREFIX` and the
  prefix rules above)
- An explicit override for the access cookie's name. See the note on
  bypassing automatic prefixing above, and `signet.E002`.

### `COOKIE_REFRESH_NAME`

- **Type:** `str | None`
- **Default:** `None` (derive from `COOKIE_PREFIX`)
- An explicit override for the refresh cookie's name. See the note on
  bypassing automatic prefixing above, and `signet.E002`.

### `COOKIE_CSRF_NAME`

- **Type:** `str | None`
- **Default:** `None` (derive from `COOKIE_PREFIX`)
- An explicit override for the CSRF cookie's name. See the note on
  bypassing automatic prefixing above, and `signet.E002`.
