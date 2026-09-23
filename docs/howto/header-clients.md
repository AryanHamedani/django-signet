# Authenticate mobile and service clients with headers

A mobile app or another service has no browser cookie jar to hold httpOnly
cookies. This guide gives such clients their own *realm*: the same five
endpoints, with tokens in the response body and in the `Authorization`
header. Browsers keep using the cookie endpoints beside it.

## Add a header realm

A realm is a `SignetViewMixin` subclass. `signet_urls()` turns it into the
five endpoints, all using the realm's transport:

```{literalinclude} ../examples/header_urls.py
:language: python
:start-at: from django.urls
```

`MobileRealm` uses `HeaderTransport`, which reads tokens from
`Authorization: Bearer <token>` and writes them into the response body. The
browser never attaches that header on its own, so no CSRF check applies and
no CSRF cookie is issued.

`MeView` stands for one of your own views: `HeaderJWTAuthentication`
authenticates it from a bearer access token. To have it also reject a
revoked session straight away, use `StrictHeaderJWTAuthentication`; see
{doc}`../reference/authentication`.

The mount path of a header realm does not have to match
`COOKIE_REFRESH_PATH`. It sets no cookies, and
[`signet.E008`](../reference/checks.md#signete008---refresh-credential-endpoint-outside-the-cookies-path)
skips views whose transport has no cookie policy.

## Log in

Post the credentials as JSON to `/api/mobile/auth/login`. The response
carries both tokens in the body:

```json
{"authenticated": true, "access": "<access token>", "refresh": "<refresh token>"}
```

No cookies are set. Keep both tokens in the platform's secure storage.

## Call your API

Send the access token on every call:

```text
Authorization: Bearer <access token>
```

`GET /api/mobile/auth/verify` with the same header answers 200 while the
access token is valid.

## Refresh

Post to `/api/mobile/auth/refresh` with the **refresh** token in the
header:

```text
Authorization: Bearer <refresh token>
```

The response carries a new pair in the same shape as login. The refresh
token you sent is now spent: store the new pair and discard the old one.

If the response is lost, retry with the same refresh token within
[`GRACE_WINDOW`](../reference/settings.md#grace_window) (10 seconds by
default). The retry answers with the same pair, as long as the grace cache
is reachable (see {doc}`deploying`). After the window, a second use of a
spent refresh token counts as theft: the session is revoked, so no refresh
token in it works again. Access tokens already issued keep working until
they expire, unless your views use a `Strict*` authentication class.

## Log out

Post to `/api/mobile/auth/logout` with the **refresh** token in the header.
It revokes the session and answers 200 `{"detail": "Signed out."}`.

A repeat answers 401, not 200. A header client has no cookies for logout to
clear, so a refresh token that does not redeem, a repeat included, answers
401 rather than reporting a sign-out. So does a request with no
`Authorization` header at all. This differs from the browser endpoints,
where logout answers 200 to a dead refresh cookie sent with the CSRF
header.

`/api/mobile/auth/logout-all` takes the refresh token the same way and
revokes every session of the user. It needs a token store that can revoke
by user; see {doc}`choosing-a-store`.

## Handle a 401

A 401 from refresh, logout or logout-all means the refresh token was
missing or no longer works. Drop both tokens and log in again.

A 401 from one of your own views means the access token was missing or
rejected, usually because it expired. Refresh once and retry. If the refresh
also answers 401, drop both tokens.

## Do not use `HybridTransport` for these clients

`HybridTransport` looks like it serves both kinds of client, but it does
not serve header clients. It reads the cookie first and falls back to the
`Authorization` header, but it writes only cookies.

A header client that refreshes through it spends its refresh token and
gets `{"authenticated": true}` back, with the new pair only in
`Set-Cookie`, which the client never reads. The session is lost. Give
header clients a `HeaderTransport` realm, as above.
