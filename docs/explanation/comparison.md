# Comparison with Simple JWT

`djangorestframework-simplejwt` ("Simple JWT") is the established JWT
package for Django REST Framework. This page compares it with Signet so you
can choose between them. What it says about Simple JWT is checked against
the source of Simple JWT 5.5.1; the module named in each row is in its
`rest_framework_simplejwt` package. To move a project from one to the
other, see {doc}`../howto/migrating-from-simplejwt`.

## Side by side

| | Simple JWT 5.5.1 | Signet |
|---|---|---|
| Where tokens travel | in the response body, and back in the `Authorization` header (`views.py`, `authentication.py`). It has no cookie code. | in httpOnly cookies by default, with double-submit CSRF; a header realm returns them in the body instead ({doc}`../howto/header-clients`) |
| Refresh rotation | opt-in, `ROTATE_REFRESH_TOKENS`, off by default (`settings.py`). Without `BLACKLIST_AFTER_ROTATION`, the old refresh token stays valid until it expires (`serializers.py`, `TokenRefreshSerializer`). | always on: every refresh spends its token |
| Session lifetime under rotation | slides: each new refresh token gets a fresh expiry (`TokenRefreshSerializer` calls `set_exp()`) | fixed: the session ends `REFRESH_TOKEN_LIFETIME` after login |
| Replay of a spent refresh token | a token blacklisted after rotation is refused as "Token is blacklisted"; nothing else is revoked (`tokens.py`, `BlacklistMixin`) | after a short grace window, revokes the whole session and fires `token_reuse_detected`, per RFC 9700 (see [Reuse detection](security-model.md#reuse-detection)) |
| Revoking access tokens | `AccessToken` is never checked against the blacklist (`tokens.py`). With `CHECK_REVOKE_TOKEN`, off by default, tokens minted before a password change are refused (`authentication.py`). | the `Strict*` authentication classes refuse an access token as soon as its session is revoked, for any reason |
| Logout | `TokenBlacklistView`, which needs the blacklist app; without the app it answers 200 to a valid token and revokes nothing (`serializers.py`, `TokenBlacklistSerializer`) | logout and logout-all are among the five endpoints |
| Refresh tokens at rest | nothing is stored without the blacklist app. With it, `OutstandingToken.token` holds each refresh token as the raw string, in a `TextField` (`token_blacklist/models.py`). | a SHA-256 digest only |
| Allowlist or denylist | denylist only, the blacklist app | one `TokenStore` port, in either mode |
| Storage | the database, through the blacklist app | the database or a Django cache, chosen by `SIGNET["STORE"]` |
| Loading the user | `JWTAuthentication` loads it on every request; `JWTStatelessUserAuthentication` builds a user from the claims with no query (`authentication.py`) | every authentication class loads it on every request |
| Signing algorithms | `HS256`-`HS512`, `RS256`-`RS512`, `ES256`-`ES512`, and every other algorithm PyJWT implements with `cryptography` (`backends.py`) | `HS256`-`HS512` and `RS256`-`RS512` |
| Verifying keys from a JWKS URL | yes, `JWK_URL` (`backends.py`) | no |
| Sliding tokens | yes, `SlidingToken` (`tokens.py`) | no |
| Configuration | one `SIMPLE_JWT` dict, several of whose entries are dotted import paths (`settings.py`); a view's `serializer_class` overrides its serializer (`views.py`) | the `SIGNET` dict, plus overrides per realm or per class by subclassing: the transport, the cookie policy, the rotation policy, the token classes and the hooks ({doc}`architecture`) |
| Signals | none | `token_issued`, `token_refreshed`, `token_reuse_detected`, `family_revoked` |
| Django admin | the blacklist app registers its two models (`token_blacklist/admin.py`) | none |
| Translations | error messages in 23 locales (`locale/`) | English only |
| System checks | none | {doc}`../reference/checks` |

Both refuse an inactive user at login and at refresh by default:
Simple JWT through `USER_AUTHENTICATION_RULE` (`serializers.py`), Signet
through `RotationPolicy.get_user`.

## What Simple JWT does well

- **It is simple to adopt for any client.** Tokens in the response body
  work the same for a browser, a mobile app and another service, with no
  cookie, CORS-credential or CSRF setup.
- **It supports more of the JWT ecosystem.** ECDSA, RSA-PSS and EdDSA
  keys, verification against a JWKS endpoint, and sliding tokens.
- **It can authenticate with no database query**, through
  `JWTStatelessUserAuthentication`, which Signet has no counterpart for.
- **It is past 1.0.** It is at version 5.5.1; Signet's public API is not
  frozen until 1.0.
- **Its messages are translated**, and its blacklist tables appear in the
  Django admin.

## Where Signet differs

Signet is narrower and stricter. It exists for browser-facing APIs that
want the tokens kept out of JavaScript, and it builds in the parts that
setup otherwise leaves to you: the cookies and their prefixes, CSRF,
rotation on every refresh, reuse detection, digest-only storage, and
revocation that takes effect at once where you ask for it. See
{doc}`security-model` for how each works and {doc}`limitations` for what
it costs.

Choose Simple JWT if your clients hold their tokens themselves and you
want its algorithms, JWKS support or stateless user. Choose Signet if a
browser holds the session and you want the server to manage it.
