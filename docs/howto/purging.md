# Purge expired sessions

The default store keeps a row for every session, and a row for every refresh
token each session was issued. Nothing deletes them when they expire, so
they accumulate until you run `signet_purge`. This guide covers what it
deletes and how to schedule it.

## What `signet_purge` deletes

Under the default `ORMTokenStore`, it deletes every session (a
`TokenFamily` row) whose expiry has passed, and with each one every refresh
token row (`IssuedToken`) it holds:

- **A session expires `REFRESH_TOKEN_LIFETIME` after login**, 14 days by
  default, however often it refreshes. Refreshing never extends it, even
  though each new refresh token carries an expiry of its own that can fall
  later. See
  [`REFRESH_TOKEN_LIFETIME`](../reference/settings.md#refresh_token_lifetime).
- **Revoked sessions are kept until they expire.** A session that was logged
  out, or burned for reuse, stays in the table with its `revoked_reason`
  until its expiry passes. Then it is purged like any other.
- **Live sessions are never touched.**

It prints how many sessions it deleted:

```console
$ python manage.py signet_purge
Purged 3 expired session families.
```

For one, it says `Purged 1 expired session family.`

Purging sends none of the library's signals. It is safe to run while you
serve traffic: a session it deletes had already expired, and its refresh
tokens were refused before the purge as they are after it.

## Schedule it

Expired rows do nothing but take space, so how often you purge is a
question of table size. Once a day suits most deployments. Run
`python manage.py signet_purge` from whatever scheduler you already have,
for example:

- a cron entry;
- a Kubernetes CronJob;
- Celery beat, running a task that calls the command.

For a scheduler that runs a Python function, call the command and log its
report:

```{literalinclude} ../examples/purge_task.py
:language: python
:start-at: import logging
```

## Under the cache store

`CacheTokenStore` has nothing for the command to delete. It prints
`Purged 0 expired session families.` every time, whatever the cache holds.

Most of what the store writes expires on its own. Session entries, refresh
token entries and the markers that record a spent token all carry a
timeout, and the cache discards them when it passes. **Revocation markers
do not.** They are written with no timeout, so that a revoked session cannot
come back to life when its marker expires, and neither the command nor a
timeout removes them. They stay until the cache evicts them.

That has two consequences, both covered in {doc}`choosing-a-store`:

- revocation markers accumulate for as long as the cache keeps them;
- in denylist mode, a marker the cache evicts revives its session for the
  `Strict*` authentication classes.

Scheduling `signet_purge` under the cache store is harmless, and does
nothing.
