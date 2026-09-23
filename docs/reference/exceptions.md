# Exceptions

Signet's internal failure taxonomy. Source: `src/django_signet/exceptions.py`.

None of these reaches a client as itself. What the client sees depends
on where the failure happens.

**On an authenticated request.** `BaseJWTAuthentication.authenticate`
catches every `SignetError` and raises a single generic
`rest_framework.exceptions.AuthenticationFailed` instead, so the response
does not disclose *which* check failed - a bad signature, an expired
token, a revoked session and a failed CSRF check all get the same
status (401, when a Signet class is the view's first authenticator) and
the same body. The distinct types reach only the
`on_authentication_failed` hook, which can react to *why* authentication
failed without that information reaching the wire. No signal is sent on
an authentication failure.

**At refresh, logout and logout-all.** These views read the refresh
credential themselves, and answer a failed CSRF check differently from a
bad credential, on purpose:

| Endpoint | CSRF check fails | No credential | Invalid credential |
|---|---|---|---|
| refresh | 403 | 401 | 401 |
| logout | 403 | 200 | 200 for a cookie credential, 401 for a header one |
| logout-all | 403 | 401 | 401 |

The 403 and the 401 carry the same generic body, so the status code says
only that a write was blocked by the CSRF check, not what else is wrong.
A 403 deliberately clears no cookies: the credential may still be good.
Logout answers 200 for a cookie credential it cannot revoke because it
clears the cookies anyway, which signs the browser out; a header client
has no cookies to clear, so it is not told it signed out. See
{doc}`views`.

```{eval-rst}
.. autoexception:: django_signet.exceptions.SignetError

.. autoexception:: django_signet.exceptions.TokenInvalid

.. autoexception:: django_signet.exceptions.TokenExpired

.. autoexception:: django_signet.exceptions.TokenRevoked

.. autoexception:: django_signet.exceptions.TokenReused

.. autoexception:: django_signet.exceptions.CSRFFailed

.. autoexception:: django_signet.exceptions.TransportError
```
