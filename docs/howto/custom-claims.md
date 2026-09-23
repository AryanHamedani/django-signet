# Add custom claims to the tokens

`get_claims(user)` on a realm returns extra claims for both tokens. The
library calls it at login, and again at every refresh with the user loaded
afresh from the refresh token's subject. A change to the user's state
therefore shows up in the tokens at the next refresh.

`get_claims` is public API, but the API is not frozen until 1.0; see
[Pin the version](deploying.md#pin-the-version).

## Define `get_claims` on a realm

```{literalinclude} ../examples/claims_urls.py
:language: python
:start-at: from django.urls
```

`signet_urls(AppRealm)` builds the same five endpoints as
`include("django_signet.urls")`, in the same `django_signet` namespace, so
`reverse("django_signet:login")` still works. Mount it at the path
[`COOKIE_REFRESH_PATH`](../reference/settings.md#cookie_refresh_path)
names, `/api/auth/` by default.

Define `get_claims` on the realm, not on one view. Login and refresh are
separate views, and a realm is how they share one `get_claims`. If only the
login view had it, the claim would vanish at the first refresh.

In your own views, the Signet authentication classes put the access token's
verified claims in `request.auth`. `GroupsView` reads `groups` from there,
with a default for tokens minted before `AppRealm` was deployed.

## When a change shows up

After you add the user to a group:

- **Access tokens already issued keep the old value** until they expire,
  [`ACCESS_TOKEN_LIFETIME`](../reference/settings.md#access_token_lifetime)
  after they were minted (5 minutes by default).
- **The next refresh derives the claims again**, from the user as the
  database has them then. Both new tokens carry the new value.
- **A retry inside the grace window gets the first refresh's pair back**,
  claims included. It is the same pair, not a new one; see
  [`GRACE_WINDOW`](../reference/settings.md#grace_window).

For a decision that must be current on every request, read `request.user`
instead. The authentication classes load it from the database on every
request. Claims suit readers that do not have your database, such as
another service that verifies the token (see {doc}`rs256`).

## Keep claims small and public

- **Claims are signed, not encrypted.** Anyone who holds a token can decode
  its claims. A browser's JavaScript cannot read the httpOnly cookies, but
  a header client holds its tokens in the clear, and so does anything that
  logs them. Put nothing secret in a claim.
- **The cookies carry every claim.** RFC 6265 asks browsers to support at
  least 4096 bytes per cookie, counting its name, value and attributes. A
  browser may ignore a larger one, and the requests that needed it then
  arrive unauthenticated.

## Reserved claims

The library sets these itself. A key of the same name that `get_claims`
returns is dropped, whatever its value:

| Claim | Holds |
|---|---|
| `sub` | the user's primary key, as a string |
| `typ` | `"access"` or `"refresh"` |
| `jti` | a fresh UUID for each token |
| `iat`, `nbf` | the time the token was minted |
| `exp` | its expiry |
| `sid` | the session (token family) id, in both tokens |

Two more are reserved only when their setting is set:

| Claim | Reserved when | Otherwise |
|---|---|---|
| `aud` | [`AUDIENCE`](../reference/settings.md#audience) is set | a `get_claims` value is signed in, and then **every token fails verification**: the verifier expects no audience, so it refuses a token that has one. Login still answers 200, and every request that presents one of its tokens is refused. |
| `iss` | [`ISSUER`](../reference/settings.md#issuer) is set | a `get_claims` value is signed in as given, and nothing checks it. |

Return neither from `get_claims`. Set `AUDIENCE` and `ISSUER` instead.

## Derive claims from server-side state

Build every claim from the user object and your database, never from the
request. `get_claims` is a method of the view, so `self.request` is within
reach, and at a refresh it is the refresh request. Resist it.

Once signed, a claim is indistinguishable from one the library issued.
Every view and every service that trusts the token trusts the claim. A claim
copied from a request body or header is one the client chose, so a
`get_claims` that returned `{"role": self.request.data["role"]}` would let
any client mint itself any role.

If `get_claims` raises during a refresh, a database error say, it does so
before the refresh token is consumed. The client gets a server error, but
its token stays redeemable, so it can retry with the same one.
