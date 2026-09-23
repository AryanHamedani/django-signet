# Alert on refresh-token reuse

Every refresh consumes the refresh token it presents and issues a new one.
When a consumed token is presented again after the grace window, the library
treats it as theft: either the token was copied, or the copy was used first.
It revokes the whole session, which it calls *burning the family*, refuses
the request, and reports it. This guide turns the report into an alert.

The hook and the signal used here are public API, but the API is not frozen
until 1.0; see [Pin the version](deploying.md#pin-the-version).

## How reuse is detected

Refresh, logout and logout-all all redeem the refresh token they are given,
so reuse is detected at all three. When a consumed token arrives:

- **Inside [`GRACE_WINDOW`](../reference/settings.md#grace_window)** (10
  seconds by default), it is taken for a retry, such as two tabs refreshing
  at once. Refresh answers with the pair it gave the first request, and
  logout and logout-all act on it as they would on the current token.
  Nothing is burned or reported.
- **After the window**, or whenever the grace cache holds no pair for it,
  it is reuse. The family is revoked with the reason
  `reuse_detected`, so no refresh token in it works again. Refresh and
  logout-all answer 401. Logout answers 200 to a cookie client, which it
  signs out whatever the state of its token, and 401 to a header client.

Access tokens already issued in the burned session keep working until they
expire, unless your views use a `Strict*` authentication class; see
{doc}`../reference/authentication`.

The grace window needs the cache that
[`GRACE_CACHE`](../reference/settings.md#grace_cache) names. See
[Share the grace cache between processes](deploying.md#share-the-grace-cache-between-processes).

## Alert from the hook

`RotationPolicy.on_reuse_detected(family)` is called each time reuse is
detected. Override it on a subclass, and give a realm that policy:

```{literalinclude} ../examples/reuse_detection.py
:language: python
:start-at: import logging
:end-before: def alert_on_reuse
```

`signet_urls(AppRealm)` mounts the same five endpoints as
`include("django_signet.urls")`, with the same URL names, so it replaces that
line in your URLconf.

The hook runs after the family is revoked and after the signal below is
sent. Then the request is refused. The `family` it receives is the record
read before the revocation, so its `revoked_at` is still `None`; ask the
store if you need to know. It carries the `user`, and the `ip_address` and
`user_agent` recorded at login.

The example logs at `CRITICAL` on a `security` logger, which your logging
configuration can route to whatever pages your on-call.

## A failing alert cannot undo the burn

If the hook raises, say a paging API times out, the exception is logged at
`error` on the `django_signet.sessions.rotation` logger, with its traceback,
and ignored. The family stays revoked and the replay is refused as usual.
That holds under `ATOMIC_REQUESTS` too.

```{warning}
One failure does undo it. Under `ATOMIC_REQUESTS`, a hook whose **database
write** fails marks the request's transaction for rollback. The exception
is still caught and the replay still refused, but the revocation is rolled
back with the transaction, and the session stays live.

Keep database writes out of the hook. Do them in a `token_reuse_detected`
receiver: inside a transaction, receivers run under a savepoint of their
own, so a failed write there rolls back only the receivers' work.
```

## Or alert from the signal

`token_reuse_detected` is sent just before the hook runs, with `user` and
`family`. The same alert as a receiver:

```{literalinclude} ../examples/reuse_detection.py
:language: python
:pyobject: alert_on_reuse
```

Connect it once, in your app's `AppConfig.ready()`, with
`token_reuse_detected.connect(alert_on_reuse)`.

A receiver cannot change the outcome either: its exceptions are logged and
ignored. See
[A receiver cannot change the outcome](../reference/signals.md#a-receiver-cannot-change-the-outcome)
for how receivers are isolated, and where that isolation stops. Its
`request` argument is always `None`, because reuse is detected below the
views.

### Which to use

- **Use the signal** to alert on every realm, the stock endpoints included,
  without changing your URLconf; to write to the database; or to have
  several independent receivers.
- **Use the hook** when the alert belongs to one realm's policy, a staff
  realm that pages someone, say, and you already have a realm to put it on.

## Detect without burning: `burn_family_on_reuse`

Set `burn_family_on_reuse = False` on a `RotationPolicy` subclass to detect
reuse without revoking the session:

- the replay is still refused;
- the signal is still sent and the hook still runs;
- the family stays live, and its current refresh token keeps refreshing.

That last point cuts both ways. If the token was stolen and the thief
refreshed first, the thief keeps the session. Leave it `True` unless you
have a reason, such as measuring how often reuse fires before you enforce
it.

## Expect some false alarms

A detection is a reason to look, not proof of theft. These fire it without
any theft:

- **Two requests racing.** Between the moment one refresh consumes a token
  and the moment it records the new pair in the grace cache, a second
  request with the same token finds it consumed and no pair to return. That
  second request can be another tab's refresh, or a logout. It is burned as
  reuse.
- **A grace cache the request cannot use.** A cache local to one process,
  with several processes serving; a cache that fails to read or write; or
  Django's `DummyCache`, which stores nothing. Each makes a benign retry
  look like reuse. An alias missing from `CACHES` is warning
  [`signet.W003`](../reference/checks.md#signetw003---grace-cache-not-configured).

Record the IP address and user agent, as the example does, so whoever
receives the alert can tell a user's second tab from someone else.
