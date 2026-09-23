# Management commands

## `signet_purge`

Deletes expired session families, and their refresh-token digests, from
the configured token store. Nothing else in the library ever calls
`TokenStore.purge_expired()`, so without running this on a schedule (cron,
a Celery beat task, a platform scheduler), the ORM store keeps every
expired family and its tokens forever.

```console
$ python manage.py signet_purge
Purged 3 expired session families.
```

Source: `src/django_signet/management/commands/signet_purge.py`.

```{eval-rst}
.. autoclass:: django_signet.management.commands.signet_purge.Command
   :members:
```
