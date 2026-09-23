# django-signet

Polymorphic, secure-by-default JWT authentication for Django REST Framework.

Authentication stays entirely in the backend: tokens travel in httpOnly
cookies, rotate automatically, and never appear in a response body or in
JavaScript.

## Why another JWT package

`djangorestframework-simplejwt` ("Simple JWT") is the incumbent. Every claim
below is checkable against its own docs or source — see
[`docs/migrating-from-simplejwt.md`](docs/migrating-from-simplejwt.md) for
citations.

| | Simple JWT | Signet |
|---|---|---|
| httpOnly cookie transport | not built in — tokens are returned in the response body; you write the cookie code yourself | built in, with correct `__Host-`/`__Secure-` prefixes |
| Refresh rotation | opt-in (`ROTATE_REFRESH_TOKENS`) | always on |
| **Refresh reuse/theft detection** | no — `BLACKLIST_AFTER_ROTATION` blacklists the *old* token but does not treat a repeat presentation as a signal to revoke anything else | yes — replaying a consumed token burns the whole token family (RFC 9700 / BCP 240) |
| Access-token revocation | not possible — access tokens are never checked against the blacklist at all; only the refresh token is, and only when it is redeemed | opt-in per view via `Strict*` authentication classes |
| Refresh tokens at rest | `OutstandingToken.token` stores the **raw JWT as plaintext** (`models.TextField()`) | sha256 digest only; the raw token is never persisted |
| Whitelist and blacklist | blacklist only (`token_blacklist` app) | one `TokenStore` port, either mode |
| Storage backend | ORM only | ORM or cache, behind the same interface, chosen by one `SIGNET["STORE"]` setting |
| Customisation | global `SIMPLE_JWT` dict of dotted import-path strings | subclass anything, per view |

## Install

```bash
pip install django-signet
```

```python
INSTALLED_APPS = [..., "django_signet"]

urlpatterns = [path("api/auth/", include("django_signet.urls"))]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_signet.authentication.CookieJWTAuthentication",
    ],
}
```

That wires up five endpoints: `POST /api/auth/login` sets the cookies,
`POST /api/auth/refresh` rotates them, `GET /api/auth/verify` confirms the
session, `POST /api/auth/logout` revokes it, and `POST /api/auth/logout-all`
revokes every session for the user (ORM store only — see Limitations).

### Cookie-transport clients must send `X-CSRF-Token` on refresh

This is the one part of the contract that is easy to miss and produces a
silent 403 if you do. `TokenObtainView` sets three cookies on login:

- `__Host-signet-access`
- `__Secure-signet-refresh`
- `__Host-signet-csrf`

(Those are the actual names your browser's cookie jar will show, under the
library's defaults — `COOKIE_SECURE=True`. If you run with
`COOKIE_SECURE=False` for local HTTP development, both prefixes drop and
you'll see `signet-access`, `signet-refresh`, `signet-csrf` instead.)

Cookies are ambient — the browser attaches them to every matching request on
its own, which is what makes CSRF possible. So every unsafe request made
with the cookie transport (refresh included) must also echo the CSRF cookie
back as a header:

```js
await fetch("/api/auth/refresh", {
  method: "POST",
  credentials: "include",
  headers: { "X-CSRF-Token": getCookie("__Host-signet-csrf") },
});
```

A client that skips this header gets `403` on every refresh, with cookies
left untouched (not cleared — see the note in `views.py` on why a failed
CSRF check must not double as a logout oracle). This was found by the
adversarial security suite during development: `TokenRefreshView` had no
CSRF check under `COOKIE_SAMESITE="None"` (a legitimate cross-origin SPA
setup), so a cross-site POST could consume a victim's refresh token,
tripping their other tab's reuse detection and burning the whole session
family — a one-request account lockout. It's fixed; the header above is the
client-side half of that fix.

If you authenticate with a header instead (`Authorization: Bearer <token>`,
via `HeaderJWTAuthentication`), none of this applies — a header a client set
explicitly can't be forged by a cross-site page, so CSRF enforcement never
triggers for it.

## Polymorphism

Everything is a class you subclass, and DRF resolves authentication per view,
so several auth behaviours coexist in one project:

```python
# One shared policy, reused by the authentication class and the views that
# issue cookies - a custom prefix and a custom refresh path both have to
# agree everywhere, or the browser silently withholds one of the cookies.
STAFF_COOKIES = CookiePolicy(
    prefix="adm",
    samesite="Strict",
    # The refresh cookie is path-scoped (see CookiePolicy's docstring). If
    # the staff endpoints below live under a different URL prefix than the
    # library default ("/api/auth/refresh"), this must match wherever
    # StaffRefreshView is actually mounted, or a real browser will never
    # send the refresh cookie to it.
    refresh_path="/api/auth/staff/refresh",
)


class StaffAuth(StrictCookieJWTAuthentication):  # instant revocation
    transport = CookieTransport(STAFF_COOKIES)


class StaffLoginView(TokenObtainView):
    """Issues the adm-prefixed cookies StaffAuth expects."""

    transport = CookieTransport(STAFF_COOKIES)


class StaffRefreshView(TokenRefreshView):
    transport = CookieTransport(STAFF_COOKIES)


class PaymentViewSet(ModelViewSet):
    authentication_classes = [StaffAuth]


urlpatterns = [
    path("api/auth/staff/login", StaffLoginView.as_view()),
    path("api/auth/staff/refresh", StaffRefreshView.as_view()),
    path("api/payments/", PaymentViewSet.as_view({"get": "list"})),
]
```

`StaffAuth` alone only verifies cookies - something has to issue `adm-`-prefixed
cookies in the first place, or every request under `PaymentViewSet` gets a
silent 401. `StaffLoginView` and `StaffRefreshView` are that something: plain
subclasses of the same views the default `django_signet.urls` wires up,
pointed at the same `CookiePolicy` `StaffAuth` verifies against.

Token lifetime is a property of the token class a view mints, not of the
authentication class that later verifies it — so a shorter-lived access
token for one part of the API is a `RotationPolicy` override on the view,
not an attribute on `CookieJWTAuthentication`:

```python
class ShortLivedAccessToken(AccessToken):
    lifetime = timedelta(minutes=2)


class CustomerLogin(TokenObtainView):
    class _Rotation(RotationPolicy):
        access_token_class = ShortLivedAccessToken

    rotation = _Rotation()
```

Add claims, react to security events, or change the cookies by overriding a
method:

```python
class LoginView(TokenObtainView):
    def get_claims(self, user):
        return {"org": user.org_id}


class RefreshView(TokenRefreshView):
    class _Rotation(RotationPolicy):
        def on_reuse_detected(self, family):
            notify_security_team(family.user)

    rotation = _Rotation()
```

(`rotation` must be an *instance*, matching `SignetViewMixin`'s own
`rotation = RotationPolicy()` — assigning the class itself, without
instantiating it, leaves `self.rotation.rotate(...)` calling an unbound
method and raising `TypeError`.)

## Security model

- Access tokens verify statelessly: zero queries on normal traffic. The
  5-minute lifetime is the revocation window (see Limitations below —
  a non-strict access token stays valid until it expires, even after the
  session it belongs to is revoked).
- Refresh tokens are session-backed, stored only as sha256 digests, and rotate
  on every use.
- Replaying a consumed refresh token burns the entire family (RFC 9700 / BCP 240).
- A 10-second grace window makes concurrent refreshes idempotent, so two tabs
  or React StrictMode do not trigger false theft detection. Set
  `GRACE_CACHE = None` for strict behaviour (see Limitations: the grace
  cache holds the raw rendered token pair, not a digest, for that window).
- Cookie-authenticated writes require a double-submit CSRF token compared in
  constant time.

## Limitations

Stated here, not just in the migration guide — a library that hides its
trade-offs earns distrust the first time someone finds one on their own.

- **`CacheTokenStore.revoke_all_for_user()` raises `NotImplementedError`.** A
  cache backend has no way to enumerate a user's families (`cache.keys()` /
  key-pattern scanning isn't part of Django's cache API, and Memcached can't
  do it at all). So under `SIGNET["STORE"] = CacheTokenStore`,
  logout-everywhere returns 501 and **a password change revokes no
  sessions** (it is saved, and a warning is logged). `manage.py check`
  warns about this (`signet.W007`). Both need `ORMTokenStore`, the default,
  or your own application-level index of family ids per user. Details in
  [`docs/stores.md`](docs/stores.md).
- **Non-strict access tokens survive revocation until they expire.** The
  default authentication classes (`CookieJWTAuthentication`,
  `HeaderJWTAuthentication`, `HybridJWTAuthentication`) verify access tokens
  statelessly — no database or cache lookup on the hot path — so revoking a
  session (logout, reuse detection, password change) does not invalidate an
  access token already issued under it; it simply expires on its own,
  normally within 5 minutes. Use the `Strict*` variants where instant
  revocation matters more than a query-free hot path.
- **The grace cache holds a raw token for its window.** To make a benign
  double-submit (two tabs, React StrictMode) idempotent, the rendered
  access/refresh pair — not a digest — is cached under the consumed token's
  digest for `GRACE_WINDOW` (10 seconds by default). Anyone with read access
  to that cache during that window can read a live token. Set
  `GRACE_CACHE = None` to disable the window and fall back to strict RFC
  9700 behaviour, where any replay is treated as reuse.

## Licence

MIT.
