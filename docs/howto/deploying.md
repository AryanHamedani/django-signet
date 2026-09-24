# Deploy to production

This guide covers the settings that decide whether the cookies work in
production: HTTPS, the mount path, the cookie domain and the grace cache.

## Serve everything over HTTPS

HTTPS is a requirement, not an option. By default
([`COOKIE_SECURE`](../reference/settings.md#cookie_secure)) every cookie is
marked `Secure`, so browsers send it only over HTTPS and ignore it when it
arrives in a plain `http://` response. The `__Host-` and `__Secure-` name
prefixes need `Secure` as well.

Do not carry `"COOKIE_SECURE": False` from your local settings into
production.
[`signet.E001`](../reference/checks.md#signete001---insecure-cookies-outside-debug)
reports it whenever `DEBUG` is `False`.

System checks run with management commands such as `check` and `migrate`,
not when a WSGI or ASGI server starts. Run them in your deploy pipeline:

```bash
python manage.py check --deploy
```

`--deploy` adds Django's own deployment checks; the library's checks run
with or without it.

## Match the refresh cookie's path to the mount

Refresh, logout and logout-all read the refresh cookie, and a browser sends
that cookie only to URLs under its path. The path is
[`COOKIE_REFRESH_PATH`](../reference/settings.md#cookie_refresh_path),
`/api/auth/` by default.

To mount the endpoints anywhere else, set the path to the mount prefix. This
URLconf mounts them at `/auth/`:

```{literalinclude} ../examples/deploy_urls.py
:language: python
:start-at: from django.urls
```

and these settings match it:

```{literalinclude} ../examples/deploy_settings.py
:language: python
:start-at: SIGNET
```

If the two disagree,
[`signet.E008`](../reference/checks.md#signete008---refresh-credential-endpoint-outside-the-cookies-path)
names every refresh, logout and logout-all view that the cookie cannot
reach. It walks your `ROOT_URLCONF`, so it also checks realms mounted with
`signet_urls()` against their own `CookiePolicy`.

## Mount nothing else under the refresh path

Do not put your own views under the refresh cookie's path. The browser sends
the refresh cookie to every URL under that path, not only to refresh, logout
and logout-all. A view of yours mounted there receives the refresh token,
which lasts 14 days by default, in every request. Anything that records
request cookies there, such as an error reporter or a request log, records
the refresh token too.

This is why the default path is the auth prefix `/api/auth/` rather than
`/`, and why the library's own views are the only ones the example mounts
under `/auth/`.

## Leave `COOKIE_DOMAIN` unset unless you need it

By default every cookie is host-only: the browser returns it only to the
host that set it. [`COOKIE_DOMAIN`](../reference/settings.md#cookie_domain)
sets them for a whole domain instead. You need it only when the frontend is
served from a sibling host, as in {doc}`spa`.

Setting it has two effects:

- **The access and CSRF cookies lose the `__Host-` prefix.** `__Host-`
  forbids a `Domain` attribute, so the names become
  `__Secure-signet-access` and `__Secure-signet-csrf`. The refresh cookie is
  `__Secure-signet-refresh` either way. The rename also means the cookies
  browsers already hold under the old names are no longer read.
- **The cookies lose the protection `__Host-` gives.** A page served over
  HTTPS from any other host under the domain can set a `__Secure-` cookie of
  the same name for the whole domain, and the browser then sends it to your
  API. A `__Host-` cookie cannot be set that way. Without `COOKIE_DOMAIN`
  only the refresh cookie is exposed to this, because its path rules out
  `__Host-`. Set a domain only if you control every host under it.

## Share the grace cache between processes

Two tabs that refresh at the same moment present the same refresh token
twice. For [`GRACE_WINDOW`](../reference/settings.md#grace_window) (10
seconds by default), the library answers the second request with the pair it
gave the first, from the cache that
[`GRACE_CACHE`](../reference/settings.md#grace_cache) names (`"default"`).

If that cache is local to one process, such as Django's local-memory cache,
which is also what you get with no `CACHES` setting, a second request that
another worker process handles finds nothing. It is then treated as theft,
and the session is revoked. With more than one process, point `GRACE_CACHE`
at a cache they all share.

The entry holds the raw token pair, and anyone who reads it gets a refresh
token that stays valid until the session next refreshes. The entry's
timeout is the window, but `DatabaseCache` and `FileBasedCache` keep
expired entries until they are read or culled, so there a copy of the
table or directory can hold live refresh tokens long after the window.
Use a cache that expires entries itself, such as Redis or Memcached, or set
`GRACE_CACHE` to `None`, and limit who can read it. `manage.py check`
warns about the two backends as `signet.W013`.

## Purge expired sessions

Nothing removes expired sessions from the default ORM store on its own. Run
[`signet_purge`](../reference/commands.md) on a schedule; see {doc}`purging`.

## Pin the version

The public API is not frozen until 1.0. Until then a minor release may
rename a hook or change its signature. Pin the version you deploy, and read
the
[changelog](../changelog.md)
before you upgrade.
