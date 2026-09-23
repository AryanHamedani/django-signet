# System checks

Signet registers nine `manage.py check` functions under the `signet` tag,
reporting eleven distinct message IDs between them. Source of truth:
`src/django_signet/checks.py`.

## Two design rules

**The checks report; they do not raise.** Whatever a misconfigured
project put in `SIGNET` - the wrong shape entirely, or a field of the
wrong type - and whatever goes wrong building the configured store, the
outcome is a reported message, not an unhandled traceback from
`manage.py check`. `checks._signet()` degrades a non-dict `SIGNET` to
`{}` for the checks that read it, the two checks that read the raw
setting (`check_token_store` and `check_refresh_cookie_path`) return
nothing for a non-dict `SIGNET`, and `checks._as_str()` treats a
wrong-typed field as absent inside the checks that read it as a string.

The exceptions are two misconfigurations outside `SIGNET` that Django's
own checks crash on too: an unimportable `ROOT_URLCONF`
(`check_refresh_cookie_path` walks the URLconf, as Django's URL checks
do), and a cache whose `KEY_FUNCTION` cannot be imported
(`check_grace_cache` builds the grace cache, as Django's cache checks
do).

**Checks read the `SIGNET` settings dict - class-level overrides only
where `signet.E008` needs them.** `signet.E008` also walks the real
URLconf and reads the `CookiePolicy` of each mounted refresh-credential
view's transport (see below). Nothing else looks at class attributes: a
`CookiePolicy(secure=False)` constructed in a subclass, a store assigned
on one class, or any hook override is arbitrary Python that cannot be
exhaustively introspected. A clean `manage.py check` means the
*settings* are coherent, not that every class-level override is.

## `signet.E001` - insecure cookies outside DEBUG

- **Level:** Error
- **Triggers when:** `SIGNET["COOKIE_SECURE"]` is any false value
  (`False`, `0`, `None`, `""`) and `settings.DEBUG` is `False`.
- **Why it matters:** authentication cookies must only travel over HTTPS
  in production; `DEBUG=True` is exempted so local HTTP development keeps
  working.
- **Fix:** remove `COOKIE_SECURE` from `SIGNET` (or leave DEBUG on only
  for local development).

## `signet.E002` - an explicit cookie name breaks its prefix's rules

- **Level:** Error
- **Triggers when:** an explicit `COOKIE_ACCESS_NAME`,
  `COOKIE_REFRESH_NAME` or `COOKIE_CSRF_NAME` starts with `__Host-` or
  `__Secure-` - matched case-insensitively, as browsers do, so
  `__host-` counts - and the settings give that cookie an attribute the
  prefix forbids:
  - either prefix, with `COOKIE_SECURE` false: both require `Secure`;
  - `__Host-` on the refresh cookie, with `COOKIE_REFRESH_PATH` other
    than `"/"`: `__Host-` requires `Path=/` (the access and CSRF cookies
    are always set at `/`);
  - `__Host-` with `COOKIE_DOMAIN` set: `__Host-` forbids `Domain`.

  One message per broken requirement, naming the setting and the cookie.
  A name left `None` is derived by `CookiePolicy`, which only chooses a
  prefix the cookie's attributes satisfy, so a derived name is never
  flagged.
- **Why it matters:** a browser silently drops a cookie that breaks its
  name prefix's rules, so requests arrive unauthenticated with no error
  anywhere.
- **Fix:** fix the attribute, or choose a name the cookie can keep:
  `__Secure-` for a path-scoped or `Domain`-scoped cookie, or leave the
  name unset (`None`) to have it derived.

## `signet.E004` - RSA algorithm with no verifying key

- **Level:** Error
- **Triggers when:** `ALGORITHM` starts with `RS` and `VERIFYING_KEY` is
  not set.
- **Why it matters:** without the PEM public key, `get_backend()` raises
  `ImproperlyConfigured`, so no token can be signed or verified. Login
  fails, and so does every request that presents a token to refresh,
  logout, logout-all or a Signet-authenticated view. `SECRET_KEY` is not
  a valid RSA key.
- **Fix:** set `VERIFYING_KEY` to the PEM public key.

## `signet.E005` - `SIGNET` is not a dict

- **Level:** Error
- **Triggers when:** `settings.SIGNET` exists and is not a `dict`.
- **Why it matters:** the rest of the library assumes a dict, and what
  it does with anything else is undefined. At runtime, `setting()` tests
  `name in SIGNET` and then reads `SIGNET[name]`. Depending on the value,
  that raises `TypeError` (`SIGNET = 5`, or a list that contains the
  setting's name) or silently falls back to the library defaults (any
  false value, or a list that does not contain the name). The other
  checks read a non-dict `SIGNET` as empty or skip it, so this is the
  one check that names the problem.
- **Fix:** set `SIGNET = {...}` as a dict, or remove it entirely to use
  the library defaults.

## `signet.E006` - a setting has the wrong type

- **Level:** Error
- **Triggers when:** `ALGORITHM` or `COOKIE_REFRESH_PATH` is present in
  `SIGNET` and is not a `str`, or `COOKIE_REFRESH_NAME` /
  `COOKIE_ACCESS_NAME` / `COOKIE_CSRF_NAME` is present and is neither a
  `str` nor `None`.
- **Why it matters:** the checks that read these settings
  (`check_cookie_prefix`, `check_signing_key`) treat a wrong-typed value
  as absent, so they stay quiet - but the runtime does not guard against
  wrong types at all. `ALGORITHM=123` passes every other check and then
  raises `AttributeError` in `get_backend()` on the first token;
  `COOKIE_REFRESH_NAME=999` makes login fail setting the cookie; a
  wrong-typed `COOKIE_REFRESH_PATH` is written straight into the refresh
  cookie's `Path`. This is the check that reports it at startup.
- **Fix:** fix the type of the named setting in `SIGNET`.

## `signet.E008` - refresh-credential endpoint outside the cookie's path

- **Level:** Error
- **Triggers when:** a mounted, named, class-based view that subclasses
  `RefreshCredentialView` (refresh, logout, or logout-all - including
  every realm built with `signet_urls()`) sits at a URL not covered by
  the `refresh_path` of its own transport's `CookiePolicy`, per RFC 6265
  path-matching (`/` boundaries, not string prefixes). That policy is
  read from the view class, so a realm's own `CookiePolicy` is checked,
  not only `COOKIE_REFRESH_PATH`. Skipped for a view whose transport has
  no cookie policy (a header transport), a `refresh_path` that is not a
  string (`signet.E006` reports that), and a route that needs URL
  arguments (no single reversible URL).
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
- **Triggers when:** building `SIGNET["STORE"]` with `STORE_OPTIONS`
  fails in any way: an unimportable path, a constructor that does not
  accept the options, a constructor that rejects them with any other
  exception (`ValueError`, say), or an object that is not a `TokenStore`.
  The message says which, naming the exception's type and text when
  there is one. Skipped when `SIGNET` is not a dict (`signet.E005`
  reports that).
- **Why it matters:** only the check swallows the failure.
  `get_store()` still raises at runtime, so every code path that needs a
  store - login, refresh, logout, the `Strict*` liveness check,
  password-change revocation, `signet_purge` - fails when it runs.
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
  `POST logout-all` answers `501` to a request whose refresh token
  verifies. Without a refresh token that verifies it answers `401`, and
  `403` for a failed CSRF check, as under any store. A deployment should
  learn this from `manage.py check`, not from an incident.
- **Fix:** switch to `ORMTokenStore` if logout-everywhere or
  password-change revocation matter; otherwise the warning documents an
  accepted trade-off.

## `signet.W009` - access/refresh cookies not `httponly`

- **Level:** Warning
- **Triggers when:** `COOKIE_HTTPONLY` is false. Governs the access and
  refresh cookies only - the CSRF cookie is always JavaScript-readable by
  design, so this flag does not apply to it.
- **Why it matters:** any script on the page can then read the tokens; a
  single XSS exfiltrates a refresh token that can live for weeks - the
  exact exposure `httponly` cookies exist to prevent. A warning, not an
  error, because unlike `COOKIE_SECURE=False` there is no legitimate
  local-HTTP reason to need it, but it is a deliberate, settable choice.
- **Fix:** remove `COOKIE_HTTPONLY: False` from `SIGNET`.

## `signet.W011` - RSA algorithm with no signing key

- **Level:** Warning
- **Triggers when:** `ALGORITHM` starts with `RS` and `SIGNING_KEY` is
  not set.
- **Why it matters:** `get_backend()` still builds a backend that
  verifies; only signing raises `ImproperlyConfigured`. Login and refresh
  fail, and access tokens minted elsewhere are still accepted. That is
  exactly a verify-only resource server, which holds no private key, so
  it is a warning rather than an error. Anywhere that serves login or
  refresh, it is a deployment that cannot mint tokens.
- **Fix:** on a deployment that serves login or refresh, set
  `SIGNING_KEY` to the PEM private key. On a verify-only resource server,
  the warning is expected; silence it with
  `SILENCED_SYSTEM_CHECKS = ["signet.W011"]` if you want a clean
  `manage.py check`.
