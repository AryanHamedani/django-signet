# Authentication classes

Six concrete DRF authentication classes, plus the `BaseJWTAuthentication`
base they share, all built from one template method. Source:
`src/django_signet/authentication.py`.

`BaseJWTAuthentication.authenticate()` owns a fixed sequence - extract,
verify, (maybe) CSRF, (maybe) family liveness, application claims, user
lookup. A request that carries no credential for the class's transport
gets `None`, so DRF can try the next authenticator. Every `SignetError`
after that collapses to the same
`AuthenticationFailed("Invalid or expired credentials.")`, regardless of
cause. The distinct exception types (`TokenExpired`, `TokenRevoked`,
`CSRFFailed`, ...) reach only the `on_authentication_failed` hook, never
the client, so a response can never be used to enumerate *why* a
credential failed. No signal is sent on an authentication failure;
override `on_authentication_failed` to react to one.

The six concrete classes differ on exactly two axes:

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
