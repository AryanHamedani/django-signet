# Signals

Four `django.dispatch.Signal` instances, sent for observability only -
logging, metrics, alerting. Source: `src/django_signet/signals.py`.

## A receiver cannot change the outcome

Every signal is sent through `django_signet.signals.send`, never
`Signal.send()`, and `send` uses `Signal.send_robust()`:

- A receiver that raises an `Exception` is logged and skipped. The other
  receivers still run - unless the failing receiver has no `__qualname__`
  (a callable instance or a `functools.partial`): Django's own failure
  logging then raises, and the rest of that dispatch is abandoned and
  logged as a dispatch failure naming only the signal. Connect plain
  functions or methods. Either way the login, refresh, logout or revocation that
  sent the signal completes as it would with no receiver connected. A
  `BaseException` such as `SystemExit` is not caught, as it is not by any
  `except Exception`.
- Inside a transaction - `family_revoked` at logout is sent from inside
  the transaction that consumes the refresh token - the receivers run
  under a savepoint of their own. A receiver whose database write fails
  rolls back only the receivers' writes, never the revocation.
- A failure of the dispatch itself is caught and logged too.
- Return values are discarded.

A decision that *should* change the outcome belongs in a hook such as
`BaseJWTAuthentication.on_authentication_failed`, not a receiver.
`RotationPolicy.on_reuse_detected` is contained like a receiver: its
exceptions are logged and ignored, because it runs after a reuse burn
that an escaping exception could roll back (under `ATOMIC_REQUESTS`).

## Receivers run synchronously

`send` returns only after every receiver has run, so the request that
sent the signal waits for all of them. Django runs an `async def`
receiver through `async_to_sync`, after the synchronous ones; the request
waits for it as well. Keep receivers fast, or hand slow work to a task
queue.

## Logging

Each receiver failure is logged at `error` on the `django_signet.signals`
logger, naming the signal and the receiver, with the traceback attached
(for a receiver with no `__qualname__`, see above: one record naming only
the signal).
Django also logs the same failure on `django.dispatch`, without the
signal's name. For a single record per failure, filter out
`django.dispatch`.

## Arguments

Every signal is sent with keyword arguments, and not all four carry the
same ones:

| Signal | `user` | `family` | `request` | `reason` |
|---|---|---|---|---|
| `token_issued` | yes | yes | the login request | - |
| `token_refreshed` | yes | yes | the refresh request | - |
| `token_reuse_detected` | yes | yes | always `None` | - |
| `family_revoked` | yes | yes | **not sent** | yes |

`family_revoked` is sent by the store layer - `TokenFamily.revoke()` and
`CacheTokenStore.revoke_family()` - not by a view, so it has no `request`
argument at all. A receiver written as `def receiver(sender, request, **kwargs)`
raises `TypeError` every time `family_revoked` is sent (logged and
skipped, as above).
Accept `**kwargs` and read what you need from it. This receiver works for
all four signals:

```python
from django.dispatch import receiver

from django_signet.signals import (
    family_revoked,
    token_issued,
    token_refreshed,
    token_reuse_detected,
)


@receiver([token_issued, token_refreshed, token_reuse_detected, family_revoked])
def audit(sender, signal, **kwargs):
    user = kwargs["user"]
    request = kwargs.get("request")  # None for reuse, absent for family_revoked
    reason = kwargs.get("reason")  # family_revoked only
```

`family` is whatever the configured store holds: a `TokenFamily` under
`ORMTokenStore`, and the cache store's own record under `CacheTokenStore`.

`token_reuse_detected` is sent whether or not
`RotationPolicy.burn_family_on_reuse` burns the family.

Under `CacheTokenStore`, revoking a family whose cache entry has already
expired or been evicted sends no `family_revoked`: the store records the
revocation, but has no user or family left to report.

```{eval-rst}
.. autodata:: django_signet.signals.token_issued

.. autodata:: django_signet.signals.token_refreshed

.. autodata:: django_signet.signals.token_reuse_detected

.. autodata:: django_signet.signals.family_revoked

.. autofunction:: django_signet.signals.send
```
