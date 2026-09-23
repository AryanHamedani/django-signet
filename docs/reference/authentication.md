# Authentication classes

Six DRF authentication classes, all built from one template method. Source:
`src/django_signet/authentication.py`.

`BaseJWTAuthentication.authenticate()` owns a fixed sequence - extract,
verify, (maybe) CSRF, (maybe) family liveness, application claims, user
lookup - and every failure inside it collapses to the same
`AuthenticationFailed("Invalid or expired credentials.")`, regardless of
cause. The distinct exception types (`TokenExpired`, `TokenRevoked`,
`CSRFFailed`, ...) exist for `on_authentication_failed` and the signal
layer, never for the client, so a response can never be used to enumerate
*why* a credential failed.

The five concrete classes differ on exactly two axes:

- **Transport** - which of `HeaderTransport`, `CookieTransport` or
  `HybridTransport` supplies the token (see {doc}`transport`).
- **Strictness** - whether authenticating also confirms the session
  family named by the token's `sid` claim is still live
  (`Strict*` classes), at the cost of one store lookup per request, or
  trusts a structurally valid, unexpired access token on its own.

```{eval-rst}
.. autoclass:: django_signet.authentication.BaseJWTAuthentication
   :members:

.. autoclass:: django_signet.authentication.HeaderJWTAuthentication

.. autoclass:: django_signet.authentication.CookieJWTAuthentication

.. autoclass:: django_signet.authentication.HybridJWTAuthentication

.. autoclass:: django_signet.authentication.StrictHeaderJWTAuthentication

.. autoclass:: django_signet.authentication.StrictCookieJWTAuthentication

.. autoclass:: django_signet.authentication.StrictHybridJWTAuthentication

.. autodata:: django_signet.authentication.GENERIC_FAILURE
```
