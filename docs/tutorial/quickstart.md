# Quickstart

By the end of this page, a browser logs in to your Django REST Framework
project, calls a protected view, refreshes its session and logs out. Both
tokens live in httpOnly cookies that your JavaScript never reads.

Every Python and JavaScript block on this page comes from a file the test
suite runs. The Python examples run under Django's test client. `client.js`
and the console session in step 8 run under Node against a live server.

**Prerequisites:**

- Python 3.12 or later, Django 5.2 or later, and Django REST Framework 3.16
  or later.
- A Django project created with `django-admin startproject`.

```{note}
The public API is not frozen until 1.0. Until then a minor release may
rename a hook or change its signature; every such change is listed in the
[changelog](../changelog.md).
```

## Step 1: Install the package

```bash
pip install django-signet
```

## Step 2: Create an app

Create an app to hold your API view and the browser client:

```bash
python manage.py startapp notes
```

## Step 3: Add the settings

Add the highlighted lines to your settings module:

```{literalinclude} ../examples/quickstart_settings.py
:language: python
:start-at: INSTALLED_APPS
:emphasize-lines: 7-9,12-19
```

- `django_signet` registers the library's
  [system checks](../reference/checks.md) and its session models.
- `DEFAULT_AUTHENTICATION_CLASSES` makes your views authenticate from the
  access cookie.
- `DEFAULT_PERMISSION_CLASSES` makes them refuse anyone who is not logged
  in. DRF's own default allows everyone, so without this line a view you
  forget to protect answers anonymous requests.

The permission default does not lock anyone out of logging in. The five
endpoints of the library set their own permissions: login, refresh, logout
and logout-all allow anonymous requests, and verify requires a logged-in
user.

The session models need their tables, so run the migrations:

```bash
python manage.py migrate
```

## Step 4: Write a view

Replace the contents of `notes/views.py`:

```{literalinclude} ../examples/notes/views.py
:language: python
:start-at: from rest_framework
```

## Step 5: Mount the URLs

Add the highlighted lines to your root URLconf. Note the added `include`
import:

```{literalinclude} ../examples/quickstart_urls.py
:language: python
:start-at: from django.urls
:emphasize-lines: 1-2,6-8
```

This mounts the library's five endpoints under `/api/auth/`:

| Method and path | What it does |
|---|---|
| `POST /api/auth/login` | Checks a username and password and sets the cookies |
| `POST /api/auth/refresh` | Rotates both tokens |
| `GET /api/auth/verify` | Answers 200 while the access token is valid |
| `POST /api/auth/logout` | Revokes this session and clears the cookies |
| `POST /api/auth/logout-all` | Revokes every session of the user |

Keep them at `api/auth/`. Refresh, logout and logout-all read the refresh
cookie, and a browser sends that cookie only to URLs under its path, which
is `/api/auth/` by default
([`COOKIE_REFRESH_PATH`](../reference/settings.md#cookie_refresh_path)). To
mount them elsewhere, see {doc}`../howto/deploying`.

Run the system checks:

```bash
python manage.py check
```

If the mount and the cookie path disagree, the check fails with
[`signet.E008`](../reference/checks.md#signete008---refresh-credential-endpoint-outside-the-cookies-path).

## Step 6: Develop over plain HTTP

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
  `signet-access`, `signet-refresh` and `signet-csrf`. You need the last
  one in step 7.
- `python manage.py check` reports
  [`signet.E001`](../reference/checks.md#signete001---insecure-cookies-outside-debug)
  for it whenever `DEBUG` is `False`.

If your frontend has its own dev server, for example at
`http://localhost:5173`, it can still call the API at
`http://localhost:8000`. Browsers do not separate cookies by port, so the
page can read the CSRF cookie the API sets, and the two are the same site.
You need only CORS: set up django-cors-headers as
[the SPA guide describes](../howto/spa.md#allow-the-frontends-origin), with
`CORS_ALLOWED_ORIGINS = ["http://localhost:5173"]`, and set `API` in
`client.js` to `"http://localhost:8000"`. You do not need `COOKIE_DOMAIN`.

## Step 7: Add the browser client

Save this module as `notes/static/client.js`:

```{literalinclude} ../examples/client.js
:language: javascript
```

Then set `CSRF_COOKIE` to the name of the CSRF cookie your server sets:

- Over plain HTTP, with the settings from step 6:
  `const CSRF_COOKIE = "signet-csrf";`
- Over HTTPS, with the default settings, leave it as it is.

If the name is wrong, the page sends the wrong CSRF header, so refresh,
logout and every write to your views answer 403.

## Step 8: Try it

Create a user and start the server:

```bash
python manage.py createsuperuser --username alice
python manage.py runserver
```

Open <http://localhost:8000/static/client.js> in your browser. The page
only shows the file; opening it puts the browser's console on the API's
origin. `runserver` serves the files in `notes/static/` because
`DEBUG` is `True` and `django.contrib.staticfiles` is installed.

Open the browser's developer console and run these lines one at a time,
with your own password. Each comment shows the result to expect:

```{literalinclude} ../examples/try_it.js
:language: javascript
```

In order, the lines:

1. Import the client.
2. Log in. The browser now holds the three cookies described
   [below](#the-cookies).
3. Check the access token.
4. Read your view. A `GET` needs only the cookies.
5. Write to your view. `api()` sends the `X-CSRF-Token` header.
6. Rotate both tokens. New cookies replace the old ones.
7. Log out. The session is revoked and the cookies are cleared.
8. Check again. With the access cookie gone, verify answers 401 and
   `verify()` returns `false`.

## How it works

### The cookies

Login answers `{"authenticated": true}`. The tokens are not in the body.
They arrive as cookies, shown here with their HTTPS names:

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

### The CSRF header

The browser attaches cookies to a request on its own, so a cookie alone
does not prove that your page sent the request. Only a script that can read
the CSRF cookie can send the matching `X-CSRF-Token` header. The server
requires it on refresh, logout, logout-all, and every request to your views
other than `GET`, `HEAD`, `OPTIONS` and `TRACE`.

Every refresh sets a new CSRF cookie, so `client.js` reads the cookie again
for each request rather than keeping its value.

### Verify

Verify checks the access token only. It does not check that the session is
still live. If the session is revoked elsewhere, by logout-all from another
device or by reuse detection, an access cookie this browser still holds
keeps answering 200 until it expires (5 minutes by default). To check the
session as well, see
[Making verify a liveness check](../reference/views.md#making-verify-a-liveness-check).

### When a call answers 401

`api()` sends the CSRF header on every unsafe method. A 401 from one of
your views means that the access token is missing or expired; `api()`
then refreshes once and retries. A failed CSRF check is a 403 instead -
usually because the CSRF cookie `client.js` reads is not the one the
server set - and `api()` does not refresh for it, since the session is
fine. A call that needs a
refresh while another is in flight waits for that one instead of starting
its own.

A 401 from refresh means the session is over: log in again. For the other
responses the endpoints give, see {doc}`../reference/views`. If two
tabs refresh at once, the second is answered from the grace cache; see
[Share the grace cache between processes](../howto/deploying.md#share-the-grace-cache-between-processes).

## What you built

- Tokens that live in httpOnly cookies, out of reach of your page's
  JavaScript.
- A session that rotates on every refresh.
- A view that refuses anonymous requests.
- CSRF protection on every cookie-authenticated request that changes state.
  Login accepts JSON only, so a plain HTML form on another site cannot log
  a browser in.

## Next steps

- {doc}`../howto/spa`: the frontend on another origin.
- {doc}`../howto/header-clients`: mobile apps and services that cannot use
  cookies.
- {doc}`../howto/deploying`: HTTPS, the cookie domain and the mount path in
  production.
- {doc}`../reference/settings`: every setting and its default.
