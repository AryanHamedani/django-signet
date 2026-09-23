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
| Access-token revocation | not possible — access tokens are only checked against the blacklist at refresh time, never on their own | opt-in per view via `Strict*` authentication classes |
| Refresh tokens at rest | `OutstandingToken.token` stores the **raw JWT as plaintext** (`models.TextField()`) | sha256 digest only; the raw token is never persisted |
| Whitelist and blacklist | blacklist only (`token_blacklist` app) | one `TokenStore` port, either mode |
| Storage backend | ORM only | ORM or cache, behind the same interface |
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
class CustomerAuth(CookieJWTAuthentication):
    access_lifetime = timedelta(minutes=5)


class StaffAuth(StrictCookieJWTAuthentication):  # instant revocation
    access_lifetime = timedelta(minutes=10)
    transport = CookieTransport(CookiePolicy(prefix="adm", samesite="Strict"))


class PaymentViewSet(ModelViewSet):
    authentication_classes = [StaffAuth]
```

Add claims, react to security events, or change the cookies by overriding a
method:

```python
class LoginView(TokenObtainView):
    def get_claims(self, user):
        return {"org": user.org_id}


class RefreshView(TokenRefreshView):
    class rotation(RotationPolicy):
        def on_reuse_detected(self, family):
            notify_security_team(family.user)
```

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
  do it at all). Logout-everywhere needs `ORMTokenStore`, or your own
  application-level index of family ids per user. Details in
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
