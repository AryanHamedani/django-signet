# Migrate from Simple JWT

This guide moves a project from `djangorestframework-simplejwt` ("Simple
JWT") to Signet. What it says about Simple JWT is checked against Simple JWT
5.5.1.

## Map the settings

Signet does not read `SIMPLE_JWT`. Copy each setting you rely on into
`SIGNET`, or into the class the table names:

| Simple JWT (default) | Signet (default) |
|---|---|
| `ACCESS_TOKEN_LIFETIME` (5 minutes) | [`ACCESS_TOKEN_LIFETIME`](../reference/settings.md#access_token_lifetime) (5 minutes) |
| `REFRESH_TOKEN_LIFETIME` (1 day) | [`REFRESH_TOKEN_LIFETIME`](../reference/settings.md#refresh_token_lifetime) (**14 days**), measured from login; see below |
| `ROTATE_REFRESH_TOKENS` (`False`) | always on |
| `BLACKLIST_AFTER_ROTATION` (`False`) | always on, and a spent token presented again after the grace window burns the session; see {doc}`reuse-detection` |
| `ALGORITHM`, `SIGNING_KEY`, `VERIFYING_KEY`, `AUDIENCE`, `ISSUER`, `LEEWAY` | the same names in `SIGNET`. Only `HS256`/`HS384`/`HS512` and `RS256`/`RS384`/`RS512` are supported, and `LEEWAY` is a `timedelta`. See {doc}`rs256`. |
| `AUTH_HEADER_TYPES` (`("Bearer",)`), `AUTH_HEADER_NAME` | `HeaderTransport(header="HTTP_AUTHORIZATION", keyword="Bearer")`: one keyword per transport |
| `USER_ID_FIELD`, `USER_ID_CLAIM` (`"id"`, `"user_id"`) | none: `sub` always holds the user's primary key, as a string |
| `TOKEN_OBTAIN_SERIALIZER` | `serializer_class` on a realm, which login uses. Its `validate()` must return `{"user": user}`, so a Simple JWT obtain serializer cannot be reused as it is. |
| extra claims from `get_token()` on the obtain serializer | `get_claims()` on a realm; see {doc}`custom-claims` |
| `USER_AUTHENTICATION_RULE`, applied at login and at refresh | at login, the login serializer's `validate()`; at refresh, `RotationPolicy.get_user()`. Both refuse an inactive user by default. |
| `CHECK_USER_IS_ACTIVE` (`True`) | always on: the authentication classes refuse an inactive user on every request |
| `CHECK_REVOKE_TOKEN` (`False`) | a password change revokes every session under `ORMTokenStore`, so refresh stops at once. Access tokens already issued stay valid until they expire, unless the view uses a `Strict*` class. With `CHECK_REVOKE_TOKEN` on, Simple JWT refused them as soon as the password changed. |
| `UPDATE_LAST_LOGIN` (`False`) | none: Signet never writes `last_login`. Update it from a `token_issued` receiver; see below. |

### Sessions no longer slide

With `ROTATE_REFRESH_TOKENS`, Simple JWT gives each new refresh token a
fresh expiry, so a session that keeps refreshing never has to log in again.
In Signet the session itself expires `REFRESH_TOKEN_LIFETIME` after login,
however often it refreshes, and the user then logs in again. Choose the
lifetime with that in mind.

## Accept both kinds of token during the cutover

A Simple JWT token does not authenticate with Signet. Signet requires a
`typ` claim and checks it first; Simple JWT names that claim `token_type`
(`TOKEN_TYPE_CLAIM`), and its user claim `user_id`, where Signet reads
`sub`. A Simple JWT refresh token cannot be redeemed either: Signet's store
never recorded it.

So list both authentication classes while existing sessions end:

```{literalinclude} ../examples/simplejwt_transition_settings.py
:language: python
:start-at: REST_FRAMEWORK
```

DRF tries them in order. A request with no Signet access cookie is not
Signet's to judge: `CookieJWTAuthentication` passes it on, and Simple JWT's
class reads its `Authorization` header. Only absence is passed on. A
request whose Signet cookie fails is refused, with 401, or 403 for a failed
CSRF check, whatever else it carries.

This works only because the two classes read different credentials.

### Header clients need a keyword of their own

`HeaderJWTAuthentication` and Simple JWT's `JWTAuthentication` both read
`Authorization: Bearer`. Listed together, neither passes the other's token
on: each claims every `Bearer` header and refuses a token it cannot verify,
Signet's for the missing `typ` claim and Simple JWT's with "Token has no
type". No order of the two classes works.

Give the Signet header realm, and the class your views use, a keyword Simple
JWT does not know:

```{literalinclude} ../examples/simplejwt_header_cutover.py
:language: python
:start-at: from django.urls
```

Signet's clients then send `Authorization: Signet <token>`. Simple JWT's
class returns `None` for a header type it does not know, and Signet's class
does the same for `Bearer`, so DRF moves on to the next class either way.
List `SignetHeaderAuthentication` and `JWTAuthentication` in your views'
authentication classes, in either order. The keyword stays after the
cutover unless you change it again, and so do the clients.

Point your login at Signet first, so every new session is a Signet session.
Then decide how long existing Simple JWT sessions may last:

- While Simple JWT's `TokenRefreshView` stays mounted, its clients keep
  getting new access tokens. With `ROTATE_REFRESH_TOKENS` that can go on
  indefinitely.
- Once you remove it, no new Simple JWT access token is issued. Remove
  `JWTAuthentication` one Simple JWT `ACCESS_TOKEN_LIFETIME` later, when the
  last one has expired. Its clients then log in again, through Signet.

## Record `last_login`

Simple JWT's login set `last_login` when `UPDATE_LAST_LOGIN` was on.
Signet's never does. To keep it current, connect a `token_issued`
receiver, which runs after every successful login:

```{literalinclude} ../examples/last_login.py
:language: python
:pyobject: record_last_login
```

## Drop the old token tables

Do not migrate `OutstandingToken`. It stores each refresh token as the raw
string (`OutstandingToken.token` is a `TextField`), which is the practice
Signet exists to avoid: Signet stores only a SHA-256 digest.

Once no Simple JWT token can still be used, drop the blacklist app's tables
and remove it:

```console
$ python manage.py migrate token_blacklist zero
```

then take `rest_framework_simplejwt.token_blacklist` out of
`INSTALLED_APPS`.

## Change the clients

With the default cookie transport, login answers `{"authenticated": true}`
and sets httpOnly cookies. No token appears in a response body, so:

- **Delete the code that stores tokens.** There is nothing to store.
- **Send cookies.** Use `credentials: "include"` with `fetch`, or
  `withCredentials: true` with axios.
- **Send the CSRF header on unsafe requests.** Every unsafe request except
  login carries `X-CSRF-Token`, set to the value of the CSRF cookie. That
  includes refresh and logout, which take no body: the refresh cookie is the
  credential.

{doc}`../tutorial/quickstart` builds such a client, and {doc}`spa` covers a
frontend on another origin.

To keep tokens in response bodies instead, for a mobile client or to change
less client code at once, add a header realm; see {doc}`header-clients`.
During the cutover, give it its own keyword, as above.
Its login returns `access` and `refresh` in the body, as Simple JWT's does,
with `"authenticated": true` beside them. Two things differ from Simple JWT:

- **Refresh takes the refresh token in `Authorization: Bearer`**, not in a
  JSON body as `{"refresh": ...}`, and always answers with both tokens.
- **Logout takes it the same way**, where Simple JWT's `TokenBlacklistView`
  takes it in the body.
