# Signals

Four `django.dispatch.Signal` instances, sent for observability only -
logging, metrics, alerting. None is awaited and no receiver's return
value is used; a receiver that raises does not stop the request that
triggered it. Source: `src/django_signet/signals.py`.

`token_reuse_detected` is the one signal whose `request` argument is
always `None`: reuse is detected inside `RotationPolicy`, which rotates
and revokes purely from a raw token string and never sees the HTTP
request that carried it. Every other signal is sent from a view, with the
real `request`.

```{eval-rst}
.. autodata:: django_signet.signals.token_issued

.. autodata:: django_signet.signals.token_refreshed

.. autodata:: django_signet.signals.token_reuse_detected

.. autodata:: django_signet.signals.family_revoked
```
