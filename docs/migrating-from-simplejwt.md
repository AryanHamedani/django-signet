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

Existing Simple JWT tokens are not portable, and the reason is a claim-schema
mismatch, not a missing session id. Simple JWT's defaults are
`USER_ID_CLAIM = "user_id"` and `TOKEN_TYPE_CLAIM = "token_type"`; Signet's
`Token.verify()` (`src/django_signet/tokens/base.py`) requires `typ` and
`sub` instead, and checks `typ` first:

```python
def verify(self, raw: str) -> dict[str, Any]:
    claims = self.get_backend().verify(...)
    if claims.get("typ") != self.typ:
        raise TokenInvalid(f"expected typ={self.typ!r}, got {claims.get('typ')!r}")
    if "sub" not in claims or "jti" not in claims:
        raise TokenInvalid("token is missing required claims")
    return claims
```

A stock Simple JWT token has no `typ` claim at all (it has `token_type`), so
`claims.get("typ")` is `None` and the very first check fails immediately —
long before `sub`, `jti`, or any `sid`/family concept is ever considered.
Run both authentication classes during the transition:

```python
from rest_framework_simplejwt.authentication import JWTAuthentication

authentication_classes = [CookieJWTAuthentication, JWTAuthentication]
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
use a header realm - every endpoint, login included, built from one
`HeaderTransport` - with `HeaderJWTAuthentication` on your API views. CSRF
enforcement never applies to it, matching Simple JWT's own header-only
default:

```python
from django_signet.transport.header import HeaderTransport
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin


class ApiRealm(SignetViewMixin):
    transport = HeaderTransport()


urlpatterns = [path("api/auth/", include(signet_urls(ApiRealm)))]
```

Login returns `access` and `refresh` in the body, as Simple JWT does.
Refresh takes `Authorization: Bearer <refresh>` and returns the successor
pair in the body; logout takes `Authorization: Bearer <refresh>` too.
