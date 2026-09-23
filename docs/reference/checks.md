# System checks

Signet registers nine `manage.py check` functions under the `signet` tag,
reporting ten distinct message IDs between them. Source of truth:
`src/django_signet/checks.py`.

## Two design rules

**A check never raises.** Whatever a misconfigured project actually put
in `SIGNET` - the wrong shape entirely, or a field of the wrong type -
the outcome is a reported message, not an unhandled traceback from
`manage.py check`. `checks._signet()` degrades a non-dict `SIGNET` to
`{}` so every check below it stays quiet rather than crashing, and
`checks._as_str()` gives individual wrong-typed fields the same
treatment inside the checks that read them as strings.

**Checks read the `SIGNET` settings dict - not class-level overrides.**
A `CookiePolicy(secure=False)` constructed in a subclass, a `store = X()`
pinned on one class, or any hook override is arbitrary Python that cannot
be exhaustively introspected. A clean `manage.py check` means the
*settings* are coherent, not that every class-level override is. Only
`signet.E008` looks past the settings dict at all, and even then only at
the real URLconf - never at class attributes.

## `signet.E001` - insecure cookies outside DEBUG

- **Level:** Error
- **Triggers when:** `SIGNET["COOKIE_SECURE"]` is `False` and
  `settings.DEBUG` is `False`.
- **Why it matters:** authentication cookies must only travel over HTTPS
  in production; `DEBUG=True` is exempted so local HTTP development keeps
  working.
- **Fix:** remove `COOKIE_SECURE: False` from `SIGNET` (or leave DEBUG on
  only for local development).

## `signet.E002` - `__Host-` cookie with an incompatible scope

- **Level:** Error
- **Triggers when:** the refresh cookie's resolved name starts with
  `__Host-` (only possible via an explicit `COOKIE_REFRESH_NAME`, since
  the library's own default resolves the path-scoped refresh cookie to
  `__Secure-`) and either `COOKIE_REFRESH_PATH` is not `"/"` or
  `COOKIE_DOMAIN` is set.
- **Why it matters:** `__Host-` requires `Path=/` and no `Domain`
  attribute; a browser silently drops a `__Host-` cookie that violates
  either, so requests arrive unauthenticated with no error anywhere.
- **Fix:** use the `__Secure-` prefix instead for a path-scoped cookie,
  or scope `COOKIE_REFRESH_PATH` to `/` and drop `COOKIE_DOMAIN` if
  `__Host-` is genuinely wanted.

## `signet.E004` - RSA algorithm missing its keys

- **Level:** Error
- **Triggers when:** `ALGORITHM` starts with `RS` and `SIGNING_KEY` or
  `VERIFYING_KEY` (or both) are not set.
- **Why it matters:** RSA algorithms need an explicit PEM private key
  (`SIGNING_KEY`) and public key (`VERIFYING_KEY`); `SECRET_KEY` is not a
  valid RSA key for either role. `get_backend()` raises
  `ImproperlyConfigured` for either being missing, so every request would
  fail - a deployment that cannot verify a single token, not a style
  concern.
- **Fix:** set both `SIGNING_KEY` (PEM private key) and `VERIFYING_KEY`
  (PEM public key) in `SIGNET`.

## `signet.E005` - `SIGNET` is not a dict

- **Level:** Error
- **Triggers when:** `settings.SIGNET` exists and is not a `dict`.
- **Why it matters:** every other check (and every `setting()` lookup at
  runtime) treats a non-dict `SIGNET` as `{}` and falls back to library
  defaults silently. This is the one check that names the real problem
  instead of letting the project run on defaults nobody chose.
- **Fix:** set `SIGNET = {...}` as a dict, or remove it entirely to use
  the library defaults.

## `signet.E006` - a setting has the wrong type

- **Level:** Error
- **Triggers when:** `ALGORITHM` or `COOKIE_REFRESH_PATH` is present in
  `SIGNET` and is not a `str`, or `COOKIE_REFRESH_NAME` /
  `COOKIE_ACCESS_NAME` / `COOKIE_CSRF_NAME` is present and is neither a
  `str` nor `None`.
- **Why it matters:** the functions that read these settings
  (`check_cookie_prefix`, `check_signing_key`, and the runtime code
  itself) already guard themselves so they never crash on a wrong type -
  but silently falling back to a default is not the same as a passing
  configuration. `ALGORITHM=123` or `COOKIE_REFRESH_NAME=999` both pass
  every other check cleanly and both fail at request time instead
  (`get_backend()` rejects a non-string algorithm; a non-string cookie
  name can never be set on a response). This is the check that reports
  it at startup.
- **Fix:** fix the type of the named setting in `SIGNET`.

## `signet.E008` - refresh-credential endpoint outside the cookie's path

- **Level:** Error
- **Triggers when:** a mounted, named, class-based view that subclasses
  `RefreshCredentialView` (refresh, logout, or logout-all - including
  every realm built with `signet_urls()`) sits at a URL not covered by
  its own `CookiePolicy.refresh_path`, per RFC 6265 path-matching (`/`
  boundaries, not string prefixes). Skipped for a view using a header
  transport (no cookie to scope) or a route that needs URL arguments (no
  single reversible URL).
- **Why it matters:** a browser only sends a cookie to URLs under its
  `Path`. Mounted outside it, refresh, logout and logout-all never
  receive the refresh cookie: refresh fails and logout cannot revoke,
  silently. Walks the real URLconf rather than trusting the default
  mount point, so mounting `django_signet.urls` (or a realm) at the wrong
  prefix is caught at startup.
- **Fix:** set `COOKIE_REFRESH_PATH` (or the realm's `CookiePolicy`
  `refresh_path`) to the prefix the auth URLs are actually mounted at.

## `signet.E010` - the configured store could not be built

- **Level:** Error
- **Triggers when:** `get_store()` raises `ImproperlyConfigured` while
  importing or constructing `SIGNET["STORE"]` with `STORE_OPTIONS`.
- **Why it matters:** every code path that needs a store - login,
  refresh, the `Strict*` liveness check, password-change revocation -
  fails immediately if this does.
- **Fix:** point `SIGNET["STORE"]` at a `TokenStore` subclass, by dotted
  path, and make `STORE_OPTIONS` match its constructor.

## `signet.W003` - grace cache not configured

- **Level:** Warning
- **Triggers when:** `GRACE_CACHE` names a cache alias that is not
  configured (or is unhashable, which can never name a real cache
  either). Not triggered by `GRACE_CACHE: None` - that is a deliberate,
  silent opt-out into strict RFC 9700 behaviour.
- **Why it matters:** without a working cache the grace window cannot
  function, so a benign replay from two tabs is treated as token theft
  and burns the session.
- **Fix:** configure the named cache, or set `GRACE_CACHE: None` to
  choose strict behaviour deliberately.

## `signet.W007` - store cannot revoke every session for a user

- **Level:** Warning
- **Triggers when:** the configured store's `supports_revoke_all_for_user`
  is `False` (true today only of `CacheTokenStore`, which cannot
  enumerate a user's families).
- **Why it matters:** under such a store, a password change is saved but
  revokes nothing (existing sessions stay live until they expire), and
  `POST logout-all` answers `501`. A deployment should learn this from
  `manage.py check`, not from an incident.
- **Fix:** switch to `ORMTokenStore` if logout-everywhere or
  password-change revocation matter; otherwise the warning documents an
  accepted trade-off.

## `signet.W009` - access/refresh cookies not `httponly`

- **Level:** Warning
- **Triggers when:** `COOKIE_HTTPONLY` is `False`. Governs the access and
  refresh cookies only - the CSRF cookie is always JavaScript-readable by
  design, so this flag does not apply to it.
- **Why it matters:** any script on the page can then read the tokens; a
  single XSS exfiltrates a refresh token that can live for weeks - the
  exact exposure `httponly` cookies exist to prevent. A warning, not an
  error, because unlike `COOKIE_SECURE=False` there is no legitimate
  local-HTTP reason to need it, but it is a deliberate, settable choice.
- **Fix:** remove `COOKIE_HTTPONLY: False` from `SIGNET`.
