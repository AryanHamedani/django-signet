# Limitations and trade-offs

Every item here is true of the current release. Some are trade-offs chosen
on purpose, some are gaps. Each says what to do about it.

## The public API is not frozen until 1.0

This is 0.x. A hook, a signal or a port may still be renamed, moved or
change shape in a minor release when a design flaw demands it; 0.1.0 itself
replaced `RotationPolicy.rotate(extra=...)` with `rotate(get_claims=...)`.
Every such change is listed in the {doc}`../changelog`. Pin the version you
deploy; see [Pin the version](../howto/deploying.md#pin-the-version).

## Access tokens

### A non-strict access token lives until it expires

`CookieJWTAuthentication`, `HeaderJWTAuthentication` and
`HybridJWTAuthentication` verify an access token by its signature and
expiry alone, with no store lookup. Revoking its session, by logout,
logout-all, reuse detection or a password change, therefore does not stop
an access token already issued: it keeps authenticating until it expires,
five minutes after it was minted by default
([`ACCESS_TOKEN_LIFETIME`](../reference/settings.md#access_token_lifetime)).
A browser logout deletes the access cookie, but a copy of the token taken
earlier still works. The stock verify endpoint behaves the same way.

Where revocation has to take effect at once, use the `Strict*` classes:
they add one store lookup per request to check that the token's family is
still live. See {doc}`../reference/authentication` and
[Making verify a liveness check](../reference/views.md#making-verify-a-liveness-check).

### Every authenticated request loads the user

Every authentication class loads the user named by the token's `sub`
claim, so that a deactivated account is refused on its next request
(`authentication.py`, `users.py`). That is one database query per
authenticated request under the non-strict classes, and two under the
`Strict*` classes with `ORMTokenStore`. There is no built-in
authentication class that trusts the claims without loading the user.

## Sessions and rotation

### The grace cache holds a raw token pair

For [`GRACE_WINDOW`](../reference/settings.md#grace_window) after each
refresh, 10 seconds by default, the cache that
[`GRACE_CACHE`](../reference/settings.md#grace_cache) names holds the
access and refresh tokens the refresh minted, not a digest of them, so
that a benign double refresh gets the same pair back. Anyone who can read
that cache during the window can read a live pair. Inside the window, a
replay of the spent token is also answered with that pair, not detected.

Limit who can read the cache. To turn the window off, set `GRACE_CACHE` to
`None`: every replay of a spent token then burns its family, including two
tabs refreshing at once. See [The grace window](security-model.md#the-grace-window).

### Two racing requests can raise a false theft alarm

A refresh consumes its token, commits, and only then writes the grace
entry (`RotationPolicy.rotate`). A second request with the same token that
arrives in between, another tab's refresh or a logout, finds the token
spent and no pair to return. It is treated as reuse: the family is burned
with the reason `reuse_detected`, and `token_reuse_detected` fires. The
race is documented in `RotationPolicy._redeem` and is not closed. Treat a
reuse alert as a reason to look, not as proof; see
[Expect some false alarms](../howto/reuse-detection.md#expect-some-false-alarms).

## `CacheTokenStore`

### It cannot log out everywhere

Django's cache API has no way to list or search keys, so `CacheTokenStore`
cannot find every session of a user, and its `revoke_all_for_user()` raises
`NotImplementedError`. Under it:

- logout-all answers 501;
- a password change revokes no session: the password is saved, and a
  warning is logged.

`manage.py check` reports this as
[`signet.W007`](../reference/checks.md#signetw007---store-cannot-revoke-every-session-for-a-user).
If you need either, use `ORMTokenStore`, the default. See
[Revoke every session of a user](../howto/choosing-a-store.md#revoke-every-session-of-a-user).

### A lost spent-token marker fails open

`CacheTokenStore` records a spent refresh token as a cache key. If that key
is evicted, or lost in a restart or a failover, while the token's own
entry survives, the spent token redeems again as if it were current. A
stolen token's replay is then not detected, and both copies keep
refreshing. This holds in allowlist and denylist mode alike. Give the store
a cache that never evicts and does not lose acknowledged writes; see
[Survive eviction](../howto/choosing-a-store.md#survive-eviction).

## Browsers and cookies

### Cross-site frontends cannot use the cookie transport

A frontend on another registrable domain, such as `example.net` calling
`api.example.com`, cannot read the API's CSRF cookie, so it cannot send
the header that refresh, logout and logout-all require. Serve the API
under the frontend's site, or give that frontend a header realm and accept
that its tokens are readable by its JavaScript. See
[Cross-site frontends](../howto/spa.md#cross-site-frontends).

### A sibling host can plant a refresh cookie

The refresh cookie is scoped to the auth endpoints' path, which rules out
the `__Host-` prefix, so it is `__Secure-`. A `__Secure-` cookie may carry a
`Domain` attribute, so a page served over HTTPS from another host under
your domain can set a cookie of the same name for the whole domain, and
the browser sends it to your auth endpoints. A hostile host could plant
its own session's refresh token that way (session fixation). The access
and CSRF cookies are `__Host-` and cannot be planted, unless you set
[`COOKIE_DOMAIN`](../reference/settings.md#cookie_domain), which makes
them `__Secure-` too. Keep untrusted content off every host under your
registrable domain; see
[Leave `COOKIE_DOMAIN` unset unless you need it](../howto/deploying.md#leave-cookie_domain-unset-unless-you-need-it).

## Realms

### A realm is not an authorization boundary by itself

A realm decides which cookies or header its endpoints read and write.
Any user can log in at any realm's login endpoint, and every realm signs
with the same key and shares one token store, so a token from one realm
authenticates at another. A permission class on each view decides who gets
in. See
[What does and does not keep realms apart](../howto/realms.md#what-does-and-does-not-keep-realms-apart).

### There is no per-realm audience

[`AUDIENCE`](../reference/settings.md#audience) is one project setting, so
every realm mints and checks the same `aud` claim. To tie a session to the
realm that opened it, stamp the tokens with a claim of your own; see
[Bind a session to its realm](../howto/realms.md#bind-a-session-to-its-realm).

## Configuration and signals

### System checks see settings, not code

`manage.py check` reads the `SIGNET` dict and the mounted URLs. The one
class-level value it inspects is the `CookiePolicy` of each mounted
refresh, logout and logout-all view, for
[`signet.E008`](../reference/checks.md#signete008---refresh-credential-endpoint-outside-the-cookies-path).
Anything else written as Python on a class, such as
`CookiePolicy(secure=False, httponly=False)` in a subclass or a store
assigned on one class, is not checked (`checks/__init__.py`). A clean check
means the settings are coherent, not that every override is.

### A callable-instance receiver can stop a signal's other receivers

Django's `Signal.send_robust()` names a failing receiver by its
`__qualname__` when it logs the failure. A callable instance or a
`functools.partial` has none, so Django's own logging raises. The library
catches that too, and the login, refresh or logout completes as usual,
but the receivers after the failing one in that dispatch do not run, and
the failure is logged naming only the signal (`signals.py`). Connect plain
functions or methods. See
[A receiver cannot change the outcome](../reference/signals.md#a-receiver-cannot-change-the-outcome).
