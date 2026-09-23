# Quickstart

By the end of this page, a browser can log in to your Django REST Framework
project, refresh its session, check it and log out. Both tokens live in
httpOnly cookies that your JavaScript never reads. Every Python and
JavaScript block on this page comes from a file the test suite checks.

**Prerequisites:**

- Python 3.12 or later, Django 5.2 or later, and Django REST Framework 3.16
  or later.
- A Django project with a user you can log in as, for example one created
  with `python manage.py createsuperuser`.

```{note}
The public API is not frozen until 1.0. Until then a minor release may
rename a hook or change its signature; every such change is listed in the
[changelog](https://github.com/AryanHamedani/django-signet/blob/main/CHANGELOG.md).
```

## Step 1: Install the package

```bash
pip install django-signet
```

## Step 2: Add the settings

Add the following to your settings module:

```{literalinclude} ../examples/quickstart_settings.py
:language: python
:start-at: INSTALLED_APPS
```

A project made with `django-admin startproject` already lists the two
`django.contrib` apps. Add `rest_framework` and `django_signet` to the list.

- `django_signet` in `INSTALLED_APPS` registers the library's
  [system checks](../reference/checks.md) and its session models.
- `DEFAULT_AUTHENTICATION_CLASSES` makes your own DRF views authenticate
  from the access cookie. The library's five endpoints set their own
  authentication and do not depend on this setting.

The session models need their tables, so run the migrations:

```bash
python manage.py migrate
```

## Step 3: Mount the URLs

Add the endpoints to your root URLconf:

```{literalinclude} ../examples/quickstart_urls.py
:language: python
:start-at: from django.urls
```

This mounts five endpoints:

| Method and path | What it does |
|---|---|
| `POST /api/auth/login` | Checks a username and password and sets the cookies |
| `POST /api/auth/refresh` | Rotates both tokens |
| `GET /api/auth/verify` | Answers 200 while the access token is valid |
| `POST /api/auth/logout` | Revokes this session and clears the cookies |
| `POST /api/auth/logout-all` | Revokes every session of the user |

Mount them at `api/auth/` unless you have a reason not to. The refresh
cookie is scoped to the path `/api/auth/` by default
([`COOKIE_REFRESH_PATH`](../reference/settings.md#cookie_refresh_path)), and
refresh, logout and logout-all all read it. A browser sends a cookie only to
URLs under its path. If you mount the endpoints somewhere else, change
`COOKIE_REFRESH_PATH` to match: {doc}`../howto/deploying` shows how.

Run the system checks:

```bash
python manage.py check
```

If the mount and the cookie path disagree, the check fails with
[`signet.E008`](../reference/checks.md#signete008---refresh-credential-endpoint-outside-the-cookies-path).

## Step 4: Develop over plain HTTP

By default every cookie is marked `Secure`, and browsers ignore a `Secure`
cookie in a response served over plain `http://`. Some browsers make an
exception for `http://localhost`, but not all of them do. To develop over
plain HTTP, add this to your local settings only:

```{literalinclude} ../examples/local_settings.py
:language: python
:start-at: DEBUG
```

With `COOKIE_SECURE` set to `False`:

- The cookies lose the `Secure` flag.
- The cookie names lose their `__Host-` and `__Secure-` prefixes, which
  browsers accept only on `Secure` cookies. The names become
  `signet-access`, `signet-refresh` and `signet-csrf`.
- `python manage.py check` reports
  [`signet.E001`](../reference/checks.md#signete001---insecure-cookies-outside-debug)
  for it whenever `DEBUG` is `False`.

The simplest local setup serves the page and the API from one origin, for
example through your frontend dev server's proxy. Serving them from two
origins needs CORS; see {doc}`../howto/spa`.

## Step 5: Call the API from the browser

This module is the browser side. Each function is one call to the API:

```{literalinclude} ../examples/client.js
:language: javascript
```

Every call passes `credentials: "include"`, so the browser attaches the
cookies to requests your page sends to another origin too.

### Log in

`login()` posts the username and password as JSON. The login endpoint
accepts JSON only and answers 415 to a form-encoded body. Wrong credentials
answer 400.

A successful login answers `{"authenticated": true}`. The tokens are not in
the body. They arrive as three cookies:

| Cookie | Path | httpOnly | Expires with |
|---|---|---|---|
| `__Host-signet-access` | `/` | yes | the access token (5 minutes) |
| `__Secure-signet-refresh` | `/api/auth/` | yes | the refresh token (14 days) |
| `__Host-signet-csrf` | `/` | no | the refresh token (14 days) |

The lifetimes are the defaults of
[`ACCESS_TOKEN_LIFETIME`](../reference/settings.md#access_token_lifetime) and
[`REFRESH_TOKEN_LIFETIME`](../reference/settings.md#refresh_token_lifetime).
The refresh cookie cannot use the `__Host-` prefix, because browsers accept
that prefix only on a cookie with `Path=/`.

### Refresh

`refresh()` reads the CSRF cookie and sends its value back in the
`X-CSRF-Token` header. The endpoint compares the two and refuses the request
if they differ:

- **200**: both tokens were rotated and new cookies are set, including a new
  CSRF cookie. Read the CSRF cookie again before each request rather than
  keeping its value.
- **401**: the refresh token is missing or no longer valid, so the session
  is over. Log in again.
- **403**: the CSRF header was missing or did not match. The refresh token
  was not used and the cookies are left as they were.

The header is what protects the session from cross-site request forgery.
The browser attaches cookies to a request on its own, so a cookie alone does
not prove that your page sent the request. Only a script that can read the
CSRF cookie can send the matching header.

### Verify

`verify()` sends a `GET`, which needs no CSRF header. It answers 200 while
the access token is valid. It does not check that the session is still
live: after logout it keeps answering 200 until the old access token
expires. To make it a liveness check, see
[Making verify a liveness check](../reference/views.md#making-verify-a-liveness-check).

### Log out

`logout()` sends the CSRF header, as refresh does. Without it the endpoint
answers 403 and revokes nothing. With it, logout revokes the session, clears
the three cookies and answers 200 `{"detail": "Signed out."}`.

Logout is idempotent for a browser. With no refresh cookie, or with a valid
CSRF header and a refresh cookie that no longer works, it still answers 200.

Logout-all needs the CSRF header too, and revokes every session of the
user. It is not idempotent: a refresh token that no longer works answers
401. Under a token store that cannot revoke by user, a request whose
refresh token verifies answers 501; the default ORM store can. See
{doc}`../stores`.

### Call your own views

`api()` calls your own DRF views. With the `DEFAULT_AUTHENTICATION_CLASSES`
from step 2, a view authenticates from the access cookie:

- `GET`, `HEAD`, `OPTIONS` and `TRACE` need only the cookie.
- Every other method also needs the `X-CSRF-Token` header. Without it your
  view answers 401 with the same generic message as an expired token, not
  the 403 that refresh and logout use.

`api()` sends the header on every unsafe method, so a 401 means the access
token is missing or was rejected, usually because it expired. `api()` then
refreshes once and retries.

## What you built

- Tokens that live in httpOnly cookies, out of reach of your page's
  JavaScript.
- A session that rotates on every refresh.
- CSRF protection on every request that changes state.

## Next steps

- {doc}`../howto/spa`: the frontend on another origin.
- {doc}`../howto/header-clients`: mobile apps and services that cannot use
  cookies.
- {doc}`../howto/deploying`: HTTPS, the cookie domain and the mount path in
  production.
- {doc}`../reference/settings`: every setting and its default.
