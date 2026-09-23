# Sessions and token storage

Session lifecycle (login, rotation, reuse detection, revocation) and
where sessions are persisted. Source: `src/django_signet/sessions/`.

```{note}
`django_signet.models` re-exports `TokenFamily`, `IssuedToken` and
`RevocationReason` for Django's model discovery. They are documented here,
at their implementation module `django_signet.sessions.models`, which is
the canonical import path for anything beyond `INSTALLED_APPS` discovery.
```

## Rotation

`RotationPolicy` is the security-critical heart of the library: every
refresh cycles through `rotate()`, and every reuse decision is made here.
See its module docstring (rendered below, on `RotationPolicy`) for the
full security contract of the grace window - in short, the *only* place a
raw refresh token exists outside the client is the grace cache, keyed by
the digest of the token that produced it, so that a benign replay (two
tabs, a double-invoked effect) gets back the exact pair the first caller
already received instead of being burned as theft.

```{eval-rst}
.. automodule:: django_signet.sessions.rotation
   :members:
```

## The `TokenStore` port

`TokenStore` is a single abstraction behind both allowlist and denylist
semantics - not two separate features. `get_store()` is the one place a
concrete adapter is chosen, resolved from the `STORE` / `STORE_OPTIONS`
settings (see {doc}`settings`). Every other part of the library that
needs a store reaches it one of two ways, and both resolve
`SIGNET["STORE"]`:

- through the `ConfiguredStore()` descriptor, which calls `get_store()`
  on every access: `RotationPolicy.store` and
  `BaseJWTAuthentication.store` (the `Strict*` liveness check);
- by calling `get_store()` directly: password-change revocation,
  `manage.py signet_purge`, and system checks `signet.E010` and
  `signet.W007`.

Allowlist and denylist stores answer `is_live()` differently for a family
they do not hold, and `revoke_family()` has to account for that - see
both methods below. A denylist adapter must record a revocation even for
a family it does not hold, or `Strict*` keeps accepting the revoked
session.

```{eval-rst}
.. autoclass:: django_signet.sessions.stores.base.TokenStore
   :members:

.. autoclass:: django_signet.sessions.stores.base.FamilyLike
   :members:

.. autoclass:: django_signet.sessions.stores.base.TokenLike
   :members:

.. autoclass:: django_signet.sessions.stores.base.Outcome
   :members:

.. autoclass:: django_signet.sessions.stores.base.ConsumeResult
   :members:

.. autofunction:: django_signet.sessions.stores.factory.get_store

.. autoclass:: django_signet.sessions.stores.factory.ConfiguredStore
   :members:
```

## Adapters

```{eval-rst}
.. autoclass:: django_signet.sessions.stores.orm.ORMTokenStore
   :members:

.. autoclass:: django_signet.sessions.stores.cache.CacheTokenStore
   :members:
```

## Models

The models backing `ORMTokenStore`. `IssuedToken.digest` is a SHA-256 hex
digest (`django_signet.hashing.token_digest`) - there is nowhere in this
model that a live credential is written.

```{eval-rst}
.. autoclass:: django_signet.sessions.models.RevocationReason
   :members:

.. autoclass:: django_signet.sessions.models.TokenFamily
   :members:

.. autoclass:: django_signet.sessions.models.IssuedToken
   :members:
```
