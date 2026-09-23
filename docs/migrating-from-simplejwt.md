# Migrating from djangorestframework-simplejwt

Signet does not read `SIMPLE_JWT`. Map settings across explicitly.

| Simple JWT | Signet |
|---|---|
| `ACCESS_TOKEN_LIFETIME` | `SIGNET["ACCESS_TOKEN_LIFETIME"]` |
| `REFRESH_TOKEN_LIFETIME` | `SIGNET["REFRESH_TOKEN_LIFETIME"]` |
| `ROTATE_REFRESH_TOKENS` | always on |
| `BLACKLIST_AFTER_ROTATION` | always on, plus reuse detection |
| `TOKEN_OBTAIN_SERIALIZER` | subclass `TokenObtainView.serializer_class` |
| `USER_AUTHENTICATION_RULE` | override `get_user()` on your auth class |
| `AUTH_HEADER_TYPES` | `HeaderTransport(keyword=...)` |

## Cutover

Existing Simple JWT tokens are not portable: Signet requires a `sid` claim
naming a token family that does not exist for them. Run both authentication
classes during the transition:

```python
authentication_classes = [CookieJWTAuthentication, LegacySimpleJWTAuthentication]
```

DRF tries each in order, so old tokens keep working until they expire while
every new login issues a Signet session. Remove the legacy class once the
longest old refresh token has expired.

## Data

Do not migrate `OutstandingToken`. It stores raw token strings
(`OutstandingToken.token = models.TextField()`, unhashed), which is the
practice Signet exists to avoid. Let the old rows expire and delete the table.

## What actually changes for API consumers

Simple JWT returns `access` and `refresh` in the response body by default;
a consumer typically stores them in `localStorage` and sends
`Authorization: Bearer <access>` on every request. Signet's cookie transport
returns neither token in the body — `POST /api/auth/login` responds with
`{"authenticated": true}` and the cookies are set for you. That means:

- Delete any client-side code that reads `response.data.access` /
  `response.data.refresh` and stores them — there is nothing to store.
- Add `credentials: "include"` (fetch) or `withCredentials: true` (axios) so
  the browser sends the cookies at all.
- Add the `X-CSRF-Token` header on every unsafe request, read from the CSRF
  cookie the login response set. See the main README's "Cookie-transport
  clients must send `X-CSRF-Token`" section for the exact mechanics and why
  it exists.

If you'd rather keep bearer tokens in the response body (e.g. for a mobile
client, or to change as little client code as possible during migration),
use `HeaderJWTAuthentication` with `HeaderTransport` instead of the cookie
classes — CSRF enforcement never applies to it, matching Simple JWT's own
header-only default.
