# Security model

This page explains what the library defends against and how. Each section
names the module that implements it, under `src/django_signet/`. For the
exact behaviour of every class, see the {doc}`../reference/index`; for what
the library does not defend against, see {doc}`limitations`.

## The threat model

The library issues two JSON Web Tokens per login session:

- an **access token**, which authenticates requests to your views and lives
  five minutes by default
  ([`ACCESS_TOKEN_LIFETIME`](../reference/settings.md#access_token_lifetime));
- a **refresh token**, which is presented only to refresh, logout and
  logout-all, and lives 14 days by default
  ([`REFRESH_TOKEN_LIFETIME`](../reference/settings.md#refresh_token_lifetime)).

It is built against these attackers:

- **A script injected into your page (XSS).** With the default cookie
  transport, both tokens travel in `HttpOnly` cookies, so no script can
  read them. See [What httpOnly cookies do and do not
  protect](#what-httponly-cookies-do-and-do-not-protect).
- **Another site the user visits (CSRF).** Cookies are ambient: the browser
  attaches them on its own. Every unsafe cookie-authenticated request must
  also carry a header that only your own page can set. See
  [Double-submit CSRF](#double-submit-csrf).
- **Someone who copies a refresh token**, from a log, a proxy or a device.
  Every refresh spends the token it presents, and a spent token presented
  again, after a short grace window, revokes the whole session. See [Reuse detection](#reuse-detection).
- **Someone who reads your database.** Refresh tokens are stored only as
  SHA-256 digests. Access tokens are not stored at all. See
  [Digest-only storage](#digest-only-storage).
- **A hostile host under your domain.** The cookie names carry the
  `__Host-` and `__Secure-` prefixes, which browsers enforce. See
  [Cookie prefixes](#cookie-prefixes).

Two properties hold throughout. Verification passes exactly one algorithm
to PyJWT, so a token's own `alg` header is never trusted
(`tokens/backends.py`). And every token carries a `typ` claim that is
checked on decode, so a refresh token cannot be used as an access token
(`tokens/base.py`).

## What httpOnly cookies do and do not protect

The access and refresh cookies are set with `HttpOnly`
([`COOKIE_HTTPONLY`](../reference/settings.md#cookie_httponly), `True` by
default), and login and refresh answer `{"authenticated": true}` with no
token in the body (`views.py`, `transport/cookie.py`). A script running in
your page therefore cannot read either token, so it cannot send them to an
attacker's server to be used later, from elsewhere.

That is the whole of the protection. An injected script runs in your
page's origin, so:

- it can send requests to your API, and the browser attaches the cookies
  to them;
- it can read the CSRF cookie, which is deliberately not `HttpOnly`, and
  send the matching header.

So it can act as the user for as long as the page is open. httpOnly cookies
limit an XSS to the session it runs in; preventing the XSS is still your
job, with output escaping and a Content Security Policy.

A header realm ({doc}`../howto/header-clients`) gives up this protection:
its tokens are in the response body, where your JavaScript, and any
script injected beside it, can read them.

## Token families

A **family** is one login session (`sessions/models.py`, `TokenFamily`).
Login opens a family and issues its first refresh token. Every refresh
consumes the token presented and issues its successor into the same
family. Both tokens carry the family's id in their `sid` claim
(`sessions/rotation.py`, `RotationPolicy.open_session`).

A family expires `REFRESH_TOKEN_LIFETIME` after login, however often it
refreshes: its expiry is fixed when it is opened. Revoking a family
(logout, logout-all, reuse detection, a password change) ends every
refresh token in it at once, and records the first reason given; a later
revocation cannot overwrite it (`TokenFamily.revoke`).

Before a refresh consumes anything, `RotationPolicy.rotate`:

1. verifies the token's signature and expiry, so an unauthenticated
   request never reaches the store;
2. loads the user from the token's `sub` claim and refuses an inactive
   one, which also revokes the family, so reactivating the account does
   not revive the session (`users.py`);
3. calls `get_claims`, and signs the successor pair.

Only then is the token consumed. A failure in step 3, a database error in
`get_claims` or a server that cannot sign, leaves the token unspent, so the
client's retry is not mistaken for theft.

## The atomic consume

Reuse detection works only if exactly one request can spend a given token.
Each store makes the decision in a single atomic step:

- `ORMTokenStore` runs one conditional
  `UPDATE ... WHERE consumed_at IS NULL`, which also requires the family to
  be unrevoked. The database decides which of two racing requests wins,
  without row locks (`sessions/stores/orm.py`).
- `CacheTokenStore` calls `cache.add()`, which sets a key only if it is
  absent, and decides from whether its own call won
  (`sessions/stores/cache.py`). This needs a backend whose `add()` is
  atomic; see {doc}`../howto/choosing-a-store`.

The consume and the successor's `issue()` run in one database transaction
(`RotationPolicy.rotate`), so an `issue()` that fails rolls the consume back
with it. A store outside the database, such as `CacheTokenStore`, is not
covered by that transaction.

## Reuse detection

Rotation means that a copied refresh token and its owner cannot both keep
refreshing: whichever presents it second presents a spent token. RFC 9700,
the OAuth 2.0 Security Best Current Practice (BCP 240), section 4.14, says
that the server should then invalidate the tokens issued from it.

Signet does this per family. When `consume()` reports a token as already
consumed and the grace window (below) holds nothing for it,
`RotationPolicy` revokes the family with the reason `reuse_detected`, sends
`token_reuse_detected`, calls `on_reuse_detected`, and refuses the request
(`RotationPolicy._handle_replay` and `_burn`). Whoever holds the current
token, the user or the thief, can no longer refresh. (A subclass can set
`burn_family_on_reuse = False` to detect without revoking.)

Logout and logout-all redeem their token the same way refresh does
(`RotationPolicy.revoke`, `revoke_all`), so a stolen token replayed there
is also burned and reported, rather than recorded as an ordinary logout.
To act on a detection, see {doc}`../howto/reuse-detection`.

Access tokens already issued in a burned family keep working until they
expire, unless the view uses a `Strict*` authentication class; see
{doc}`limitations`.

## The grace window

Some replays are not theft. Two tabs refresh at the same moment; React
StrictMode runs an effect twice; a mobile client loses the response and
retries. Each presents the same refresh token twice, and strict rotation
would burn the session for it.

So a successful refresh caches the pair it minted, for
[`GRACE_WINDOW`](../reference/settings.md#grace_window) (10 seconds by
default), in the cache that
[`GRACE_CACHE`](../reference/settings.md#grace_cache) names, keyed by the
digest of the token it consumed. A second presentation of that token
inside the window gets the same pair back and burns nothing
(`RotationPolicy._grace_put`, `_grace_get`). The cache entry's timeout is
the window itself.

This has two costs, which you should weigh:

- **The grace cache is the only place a raw token sits outside the
  client.** The store sees digests only, but a replay has to receive the
  exact bytes the first caller received, so the entry holds the rendered
  access and refresh tokens. Anyone who can read that cache during the
  window can read a live pair.
- **Inside the window, a replay is indistinguishable from a retry.** A
  thief who presents a token within the window after its owner refreshed
  receives the same pair, and nothing is detected.

Every failure of the grace cache makes rotation stricter, never more
permissive (`RotationPolicy._cache`): an alias missing from `CACHES`, a
cache that fails to read or write, or `GRACE_CACHE = None` all turn a
replay into reuse. Set `GRACE_CACHE` to `None` for strict RFC 9700
behaviour, where every replay burns its family.

## Double-submit CSRF

The CSRF defence is a double-submit token (`csrf.py`):

- Login and every refresh set a new random token (`secrets.token_urlsafe`)
  in the CSRF cookie. That cookie is readable by JavaScript, set at `/`,
  and expires with the refresh cookie, so a session survives a browser
  restart for as long as its refresh token does.
- Every unsafe request that authenticates from a cookie must echo the
  cookie's value in the `X-CSRF-Token` header. `GET`, `HEAD`, `OPTIONS`
  and `TRACE` are exempt.
- The two values are compared with `hmac.compare_digest`, which takes the
  same time wherever the strings differ.

A page on another site cannot read your cookies, so it cannot set the
header. The check applies to the cookie authentication classes, on unsafe
methods, and to refresh, logout and logout-all whenever their refresh
credential arrived as a cookie. A header credential needs none: a
cross-site page cannot make the browser send one.

A failed check answers 403, from the cookie authentication classes and
from refresh, logout and logout-all alike. Refresh, logout and logout-all
run it before the token is used for anything
(`RefreshCredentialView.read_refresh_credential`, `views.py`). A forged
request does not need to read the refresh token to misuse it: it only has
to make the browser send it. Without the check, a cross-site POST to logout
that carried the cookies, as one does under `SameSite=None`, would revoke
the user's session, and a forged refresh would spend their token or trigger
reuse detection against it.

Login takes no CSRF header: there is no session yet to protect. It accepts
JSON only, and answers a form-encoded body with 415. A cross-site page can
submit an HTML form without a CORS preflight, but cannot send
`application/json` without one, so a form cannot sign a victim's browser
in to the attacker's account (login CSRF).

## Proof of origin before deleting cookies

A response deletes cookies only once the request has proved it came from
your own origin: it presented a refresh credential, and, if the credential
arrived as a cookie, passed the CSRF check (`SignetViewMixin.clear_cookies`
and `RefreshCredentialView.read_refresh_credential`, `views.py`).

The reason is that the browser honours `Set-Cookie` deletions on any
response. Under `SameSite=Lax`, a cross-site top-level form POST to logout
carries none of the user's cookies, yet deletions in its response would
still apply. Without this rule, one forged POST would sign anyone out. So:

- a browser logout with no credential answers 200 and deletes nothing;
- a failed CSRF check answers 403 and deletes nothing, because a missing
  header says nothing about whether the credential is still good;
- a credential your own page sent that no longer works is deleted, so a
  dead session does not loop.

## Cookie prefixes

Browsers enforce two cookie-name prefixes:

- `__Host-` requires `Secure`, `Path=/` and no `Domain`. Such a cookie can
  be set only by the host itself, never by a sibling host under the same
  domain.
- `__Secure-` requires `Secure` only.

`CookiePolicy` applies them from the cookie's path and domain
(`transport/cookie.py`):

| Cookie | Path | Name by default |
|---|---|---|
| Access | `/` | `__Host-signet-access` |
| Refresh | [`COOKIE_REFRESH_PATH`](../reference/settings.md#cookie_refresh_path) (`/api/auth/`) | `__Secure-signet-refresh` |
| CSRF | `/` | `__Host-signet-csrf` |

The refresh cookie is scoped to the auth endpoints so that it is not sent
on every API call, and that path rules out `__Host-`. Setting
[`COOKIE_DOMAIN`](../reference/settings.md#cookie_domain) turns every name
into `__Secure-`, and `COOKIE_SECURE = False` drops the prefixes
altogether. The CSRF cookie is prefixed too: an unprefixed double-submit
cookie could be overwritten by a sibling host, which would defeat the
check. System check
[`signet.E002`](../reference/checks.md#signete002---an-explicit-cookie-name-breaks-its-prefixs-rules)
reports an explicit cookie name that breaks its prefix's rules.

## Digest-only storage

The token store never receives a raw refresh token. `issue()` and
`consume()` take its SHA-256 hex digest (`hashing.py`), and no store method
takes the token itself (`sessions/stores/base.py`). `IssuedToken.digest` is the only column
that identifies a token (`sessions/models.py`). The store only ever needs
to answer "is this the token I issued?", so a one-way digest is enough, and
there is no key to leak or rotate. A copy of the database yields no
refresh token that can be presented.

Access tokens are not stored anywhere. They are verified by signature, and
the `Strict*` classes look up only their family (`authentication.py`).

## Signals and hooks cannot change an outcome

Signals are for observability. A receiver runs inside the request that
sent it, and often inside a transaction the library or your project
(`ATOMIC_REQUESTS`) has open. Before 0.1.0 was released, a receiver could
change the result: a `family_revoked` receiver that raised rolled back a
logout's revocation, so logout answered 500 and the session stayed live.

Two things are needed to stop that, and the fixes arrived in that order:

1. **Catch the exception.** Every signal is sent through
   `django_signet.signals.send`, which uses `send_robust()` and logs each
   receiver's exception at `error` on the `django_signet.signals` logger
   (`signals.py`).
2. **Isolate the database work.** Catching is not enough on its own. A
   database query that fails inside a transaction has already marked that
   transaction for rollback, so the revocation or burn written just before
   it would be undone when the transaction ends, exception caught or not.
   Inside a transaction, receivers therefore run under a savepoint of their
   own, and a failure rolls back only their writes (`isolation.py`,
   `savepoint_if_in_transaction`).

Pull request [#8](https://github.com/AryanHamedani/django-signet/pull/8)
did both for signal receivers. The same flaw was then found in
`on_reuse_detected`, which runs after a reuse burn is written but, under
`ATOMIC_REQUESTS`, before it is committed:
[#9](https://github.com/AryanHamedani/django-signet/pull/9) caught its
exceptions, and [#11](https://github.com/AryanHamedani/django-signet/pull/11)
ran it under a savepoint too, because a failed query in the hook still
undid the burn. Its exceptions are logged on
`django_signet.sessions.rotation`, and the replay is refused as usual
(`RotationPolicy._burn`).

A decision that should change the outcome belongs in a hook that is meant
for it, such as `BaseJWTAuthentication.validate_claims` or
`RotationPolicy.get_user`, not in a receiver. For how far receiver
isolation goes, see
[A receiver cannot change the outcome](../reference/signals.md#a-receiver-cannot-change-the-outcome).

The public API, hooks and signals included, is not frozen until 1.0.
