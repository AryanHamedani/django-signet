# django-signet

[![Documentation](https://readthedocs.org/projects/django-signet/badge/?version=latest)](https://django-signet.readthedocs.io/en/latest/)

Polymorphic, secure-by-default JWT authentication for Django REST Framework.

Authentication stays in the backend: both tokens travel in httpOnly
cookies, rotate on every refresh, and never appear in a response body or
in JavaScript. The server handles rotation, reuse detection and CSRF.

**Documentation: <https://django-signet.readthedocs.io>**

## Why another JWT package

`djangorestframework-simplejwt` ("Simple JWT") is the established JWT
package for Django REST Framework. Its column below is checked against the
source of Simple JWT 5.5.1; the
[full comparison](https://django-signet.readthedocs.io/en/latest/explanation/comparison.html)
names the module behind each row, and what Simple JWT does better.

| | Simple JWT 5.5.1 | Signet |
|---|---|---|
| Where tokens travel | in the response body and the `Authorization` header; no cookie support built in | in httpOnly cookies with `__Host-`/`__Secure-` prefixes and double-submit CSRF; a header realm for mobile and service clients |
| Refresh rotation | opt-in (`ROTATE_REFRESH_TOKENS`) | always on |
| Replay of a spent refresh token | refused if it was blacklisted after rotation; nothing else is revoked | after a short grace window, revokes the whole session (RFC 9700 / BCP 240) |
| Revoking access tokens | not checked against the blacklist; `CHECK_REVOKE_TOKEN` (off by default) refuses tokens minted before a password change | opt-in per view, for any revocation, through the `Strict*` authentication classes |
| Refresh tokens at rest | with the blacklist app, `OutstandingToken.token` stores the raw token in a `TextField` | SHA-256 digest only |
| Allowlist or denylist | denylist only (the blacklist app) | one `TokenStore` port, either mode |
| Storage | the database, through the blacklist app | the database or a Django cache, chosen by one `SIGNET["STORE"]` setting |
| Customisation | one `SIMPLE_JWT` dict, partly dotted import paths; `serializer_class` per view | subclassing, per realm or per view |

## Quickstart

```bash
pip install django-signet
```

In your settings:

```python
INSTALLED_APPS = [
    # ...
    "rest_framework",
    "django_signet",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_signet.authentication.CookieJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}
```

In your root URLconf:

```python
from django.urls import include, path

urlpatterns = [
    # /api/auth/ is the refresh cookie's default path, COOKIE_REFRESH_PATH.
    path("api/auth/", include("django_signet.urls")),
]
```

Then run `python manage.py migrate`. That mounts five endpoints:
`POST /api/auth/login`, `POST /api/auth/refresh`, `GET /api/auth/verify`,
`POST /api/auth/logout` and `POST /api/auth/logout-all`.

Login takes a JSON body. Every other unsafe request from the browser,
refresh and logout included, must send the CSRF cookie's value back in the
`X-CSRF-Token` header:

```js
// getCookie(name) stands for your own cookie reader.
await fetch("/api/auth/refresh", {
  method: "POST",
  credentials: "include",
  headers: { "X-CSRF-Token": getCookie("__Host-signet-csrf") },
});
```

The
[quickstart tutorial](https://django-signet.readthedocs.io/en/latest/tutorial/quickstart.html)
builds this end to end, including a browser client and local development
over plain HTTP.

## Documentation

- **How-to guides:**
  [a frontend on another subdomain](https://django-signet.readthedocs.io/en/latest/howto/spa.html),
  [mobile and service clients](https://django-signet.readthedocs.io/en/latest/howto/header-clients.html),
  [deploying](https://django-signet.readthedocs.io/en/latest/howto/deploying.html),
  [a second realm](https://django-signet.readthedocs.io/en/latest/howto/realms.html),
  [custom claims](https://django-signet.readthedocs.io/en/latest/howto/custom-claims.html),
  [alerting on token reuse](https://django-signet.readthedocs.io/en/latest/howto/reuse-detection.html),
  [RS256](https://django-signet.readthedocs.io/en/latest/howto/rs256.html),
  [purging expired sessions](https://django-signet.readthedocs.io/en/latest/howto/purging.html),
  [choosing a token store](https://django-signet.readthedocs.io/en/latest/howto/choosing-a-store.html)
  and
  [migrating from Simple JWT](https://django-signet.readthedocs.io/en/latest/howto/migrating-from-simplejwt.html).
- **Reference:**
  [settings](https://django-signet.readthedocs.io/en/latest/reference/settings.html),
  [system checks](https://django-signet.readthedocs.io/en/latest/reference/checks.html),
  [endpoints](https://django-signet.readthedocs.io/en/latest/reference/views.html)
  and the
  [full API](https://django-signet.readthedocs.io/en/latest/reference/index.html).
- **Explanation:**
  [the security model](https://django-signet.readthedocs.io/en/latest/explanation/security-model.html),
  [the architecture](https://django-signet.readthedocs.io/en/latest/explanation/architecture.html)
  and
  [limitations and trade-offs](https://django-signet.readthedocs.io/en/latest/explanation/limitations.html).
  Read the limitations before you deploy: among them, a non-strict access
  token stays valid until it expires even after its session is revoked,
  and `CacheTokenStore` cannot log a user out everywhere.

**The public API is not frozen until 1.0.** A minor release may still
rename a hook or change its signature; every such change is listed in the
[changelog](https://django-signet.readthedocs.io/en/latest/changelog.html).

## Contributing and security

See the [contributing guide](https://django-signet.readthedocs.io/en/latest/contributing.html). Report a
vulnerability privately, as the [security policy](https://django-signet.readthedocs.io/en/latest/security.html)
describes, never in a public issue.

## Licence

MIT.
