# Exceptions

Signet's internal failure taxonomy. Source: `src/django_signet/exceptions.py`.

None of these ever reaches a client directly. `BaseJWTAuthentication.authenticate`
catches every `SignetError` and raises a single generic
`rest_framework.exceptions.AuthenticationFailed` instead, so no response
discloses *which* check failed - a bad signature, an expired token, a
revoked session and a failed CSRF check are all indistinguishable from
the outside. The distinct types below exist for `on_authentication_failed`
and the signal layer, which can react to *why* authentication failed
without that information ever reaching the wire.

```{eval-rst}
.. autoexception:: django_signet.exceptions.SignetError

.. autoexception:: django_signet.exceptions.TokenInvalid

.. autoexception:: django_signet.exceptions.TokenExpired

.. autoexception:: django_signet.exceptions.TokenRevoked

.. autoexception:: django_signet.exceptions.TokenReused

.. autoexception:: django_signet.exceptions.CSRFFailed

.. autoexception:: django_signet.exceptions.TransportError
```
