# Serve a single-page app from another origin

This guide sets up a frontend at `https://app.example.com` that calls an API
at `https://api.example.com` with the cookie transport. It starts from the
{doc}`../tutorial/quickstart`.

## Which setups work

Whether the cookie transport works depends on where the frontend is served
from, relative to the API:

| Frontend | API | Works |
|---|---|---|
| `https://example.com` | `https://example.com/api/` | Yes: this is the quickstart, with no extra settings. |
| `https://app.example.com` | `https://api.example.com` | Yes, with the settings below. |
| `https://example.net` | `https://api.example.com` | No. See [Cross-site frontends](#cross-site-frontends). |

The difference is the CSRF token. It reaches the frontend only as a cookie:
login and refresh answer `{"authenticated": true}` and nothing else. Your
JavaScript can read that cookie only if it was set for your frontend's
host, or for a domain that contains it.

## Set the cookies for the whole site

The second row works once the API sets its cookies for `example.com`, which
contains both hosts. These are the settings for the API:

```{literalinclude} ../examples/spa_settings.py
:language: python
:start-at: SIGNET
```

[`COOKIE_DOMAIN`](../reference/settings.md#cookie_domain) adds
`Domain=example.com` to all three cookies. Your frontend's JavaScript can
then read the CSRF cookie, which is never httpOnly:
[`COOKIE_HTTPONLY`](../reference/settings.md#cookie_httponly) applies to the
access and refresh cookies only.

A cookie with a `Domain` attribute cannot use the `__Host-` prefix, so
setting `COOKIE_DOMAIN` renames two of the cookies:

| Cookie | Default name | With `COOKIE_DOMAIN` |
|---|---|---|
| Access | `__Host-signet-access` | `__Secure-signet-access` |
| Refresh | `__Secure-signet-refresh` | `__Secure-signet-refresh` |
| CSRF | `__Host-signet-csrf` | `__Secure-signet-csrf` |

In the quickstart's `client.js`, change two constants:

- `API` becomes `"https://api.example.com"`.
- `CSRF_COOKIE` becomes `"__Secure-signet-csrf"`.

## Leave `SameSite` at its default

`app.example.com` and `api.example.com` are two origins but one site, because
they share the registrable domain `example.com`. A `SameSite=Lax` cookie,
the default ([`COOKIE_SAMESITE`](../reference/settings.md#cookie_samesite)),
is sent on requests between them. You do not need `SameSite=None`.

`SameSite=None` only matters for requests from another site, which the
cookie transport does not support. If you set it, browsers also require the
cookie to be `Secure`.

## Allow the frontend's origin

The browser only lets the frontend read the API's responses if the API
allows it with CORS. The `CORS_*` settings in the example belong to
[django-cors-headers](https://github.com/adamchainz/django-cors-headers), a
separate package. Install it, and add its app and middleware as its
documentation describes. Then:

- **`CORS_ALLOWED_ORIGINS`** names the frontend's origin exactly. A browser
  refuses a credentialed response whose `Access-Control-Allow-Origin` is
  `*`. Do not use `CORS_ALLOW_ALL_ORIGINS` either: with credentials allowed,
  django-cors-headers answers every origin with that origin's own name, so
  any site could make credentialed calls to your API.
- **`CORS_ALLOW_CREDENTIALS = True`** answers
  `Access-Control-Allow-Credentials: true`. Without it, every cross-origin
  `fetch()` that uses `credentials: "include"` fails its CORS check.
- **`CORS_ALLOW_HEADERS`** must list `x-csrf-token`, and `content-type` for
  the JSON login. The example replaces the package's default list. To extend
  the default instead, use `(*default_headers, "x-csrf-token")`, with
  `default_headers` imported from `corsheaders.defaults`.

## Why the CSRF header matters more here

Every host under `example.com` is part of the same site, so `SameSite=Lax`
does not separate your frontend from any other page on `example.com`. With
`COOKIE_DOMAIN` set, the browser also sends the cookies to every host under
`example.com`, and a script on any of them can read the CSRF cookie.

What still stops a page on another host from acting for the user is the
combination of two checks:

- Refresh, logout, logout-all, and every unsafe request that authenticates
  from the access cookie, require the `X-CSRF-Token` header.
- A cross-origin request with that header is preflighted, so the browser
  sends it only if the API's CORS settings allow the page's origin.

Keep `CORS_ALLOWED_ORIGINS` to the origins you serve yourself.

The domain-wide cookies also give up the protection of the `__Host-` prefix.
A `__Host-` cookie cannot be overwritten by another subdomain; a `__Secure-`
cookie with a `Domain` can. Set `COOKIE_DOMAIN` only if you control every
host under that domain.

## Cross-site frontends

A frontend on a different registrable domain, such as `example.net` calling
`api.example.com`, cannot use the cookie transport. This is a limitation of
the library:

- The frontend cannot read the API's CSRF cookie, because the cookie
  belongs to the API's site, not to `example.net`.
- So no refresh can succeed. Under the default `SameSite=Lax` the browser
  does not attach the cookies to the frontend's requests at all. Under
  `SameSite=None` it attaches them, but the frontend cannot send the
  matching header, and refresh, logout and logout-all answer 403.
- Browsers increasingly restrict cookies in cross-site requests: Safari
  blocks them by default. The cookies may not be stored at all.

For that setup, either:

- serve the API under the frontend's site, for example at
  `api.example.net`, and follow this guide with `COOKIE_DOMAIN="example.net"`;
  or
- give the frontend a header realm, as described in
  {doc}`header-clients`. The tokens are then in your JavaScript, so a script
  injected into the page can read them.
