# Architecture

This page explains how the package is divided, how configuration is
resolved, and how you change behaviour: by subclassing, not by adding
settings. For the classes themselves, see the {doc}`../reference/index`.

## The layers

The package, `src/django_signet/`, is split by responsibility:

| Layer | Modules | Responsibility |
|---|---|---|
| Foundation | `conf`, `exceptions`, `hashing`, `isolation`, `signals`, `users` | settings resolution, the exception types, the token digest, savepoints for callbacks, the four signals, loading a user |
| Tokens | `tokens` | building, signing and verifying JWTs |
| Transport | `transport` | reading tokens off a request and writing them onto a response |
| Sessions | `sessions` | token families, the token stores, rotation and reuse detection |
| HTTP | `csrf`, `authentication`, `serializers`, `views`, `urls` | DRF authentication classes, the five endpoints, and the CSRF check between them |

Around them sit the Django integration modules: `apps` (registers the
system checks and the password-change receiver), `checks`, `revocation`
(password-change revocation), `models` (re-exports the session models for
Django's model discovery), `migrations` and `management`.

A token does not know where it is stored or how it travels; a transport
moves strings and never sees a session; the session layer never touches
the wire. That is what lets each be replaced alone: a new signing backend,
a new transport or a new store is a subclass, with no change to the others.

### The contracts

The boundaries are enforced, not only described. `pyproject.toml` declares
five [import-linter](https://import-linter.readthedocs.io/) contracts, and
`lint-imports` fails CI when one is broken. Their names are quoted
exactly; module names are shown without the `django_signet.` prefix.

| Contract | Type | Applies to | Forbidden, or allowed |
|---|---|---|---|
| tokens is a leaf - it knows nothing about storage, wire or DRF | forbidden | `tokens` | may not import `sessions`, `transport`, `csrf`, `authentication`, `serializers`, `views` |
| transport moves bytes - it knows nothing about storage or auth | forbidden | `transport` | may not import `sessions`, `authentication`, `serializers`, `views` |
| sessions persists and rotates - it never touches the wire | forbidden | `sessions` | may not import `transport`, `csrf`, `authentication`, `serializers`, `views` |
| foundation modules depend on nothing above them | forbidden | `conf`, `exceptions`, `hashing`, `isolation`, `signals`, `users` | may not import `tokens`, `sessions`, `transport`, `csrf`, `authentication`, `serializers`, `views` |
| only the store factory chooses a concrete store | protected | `sessions.stores.orm`, `sessions.stores.cache` | only `sessions.stores.factory` may import them |

`transport` may import `conf` and `exceptions`, and `csrf` may import
`transport`: the contracts forbid only what the table lists. The test
suite checks that this table names every contract in `pyproject.toml`.

## Configuration: the `setting()` descriptor

The library's classes read every key of `DEFAULTS` through a class
attribute declared with `setting(name)`, from `conf.py`, on the class that
uses it:
`AccessToken.lifetime = setting("ACCESS_TOKEN_LIFETIME")`,
`RotationPolicy.grace_window = setting("GRACE_WINDOW")`,
`CookiePolicy.secure = setting("COOKIE_SECURE")`, and so on. Reading the
attribute resolves it, highest priority first:

1. **A value assigned on a subclass**, or on an instance. `setting` is a
   non-data descriptor, so an ordinary attribute of the same name shadows
   it through Python's normal lookup, and the descriptor never runs.
   `CookiePolicy(secure=False)` works this way: each keyword becomes an
   instance attribute.
2. **The project's `SIGNET` dict**, if it has the key.
3. **The default**: the `default` passed to `setting()`, else
   `DEFAULTS[name]` in `conf.py`.

Nothing is cached. Every read goes back to `settings.SIGNET`, which is why
`override_settings` works in tests. The same shadowing rule applies to
`ConfiguredStore` below. See
[Resolution order](../reference/settings.md#resolution-order) for the
reference.

So a setting and a subclass are two routes to the same value. Use `SIGNET`
for what should hold across the project, and a subclass for what should
hold for one realm or one view.

## The `TokenStore` port

`TokenStore`, in `sessions/stores/base.py`, is the port every session
operation goes through: `open_family`, `issue`, `consume`, `is_live`,
`revoke_family`, `revoke_all_for_user` and `purge_expired`. The library
ships two adapters, `ORMTokenStore` and `CacheTokenStore`; see
{doc}`../howto/choosing-a-store`.

Allowlist and denylist are not two features but one port with two
defaults. An allowlist's `is_live()` answers `False` unless the store holds
the family, live; a denylist's answers `True` unless a revocation was
recorded for it.

The port returns structural types, not models. `FamilyLike` and
`TokenLike` are `typing.Protocol` classes naming only the attributes some
caller reads, such as `id`, `user`, `expires_at`, `revoked_at` and
`is_live` on a family. `ORMTokenStore` returns its Django models,
`TokenFamily` and `IssuedToken`; `CacheTokenStore` returns plain
dataclasses. Both satisfy the protocols without either knowing the other
exists, and `RotationPolicy` works with whichever it is given.

`consume()` returns a `ConsumeResult`, whose `outcome` is one of five
`Outcome` values. The store only reports what it found. What to do about
each outcome, redeem, answer from the grace window, burn the family or
refuse, is decided in one place, `RotationPolicy`. See
[The `TokenStore` port](../reference/sessions.md#the-tokenstore-port).

### One factory, `get_store()`

Login, refresh and logout, the `Strict*` liveness check, password-change
revocation, `signet_purge` and two system checks all need a store, and
they must agree on which. Each once constructed its own, and one hardcoded
`ORMTokenStore()`: under a cache store, a password change then revoked
nothing, and a `Strict*` class read a different store from the one login
wrote (`sessions/stores/factory.py`).

Now every one of them resolves the store through `get_store()`, which
builds the class that
[`STORE`](../reference/settings.md#store) names with
[`STORE_OPTIONS`](../reference/settings.md#store_options). `RotationPolicy`
and `BaseJWTAuthentication` reach it through the `ConfiguredStore`
descriptor, which calls `get_store()` on every access. The fifth contract
above makes `sessions.stores.factory` the only module that may import a
concrete adapter, so a new construction site fails CI.

## Polymorphism by subclassing

The library adds behaviour through classes you subclass, not through
settings flags. DRF chooses authentication per view, and Django routes
per URL, so several configurations can run side by side in one project.

### Realms

A **realm** is one subclass of `SignetViewMixin` (`views.py`). Its class
attributes, `transport` and `rotation`, and its hooks, such as
`get_claims`, configure all five endpoints at once: `signet_urls(realm)`
(`urls.py`) builds each endpoint as a new class with the realm mixed in
ahead of the stock view, so everything the realm declares overrides the
view's defaults. Login, refresh, verify and logout cannot disagree about
which cookies they read or which claims they mint. See
{doc}`../howto/realms`.

### Hooks

The classes expose methods meant to be overridden, among them:

- on a realm, `get_claims(user)`, called at login and at every refresh
  ({doc}`../howto/custom-claims`), and `get_response_data`;
- on `RotationPolicy`, `get_user(claims)`, which decides who may keep a
  session, and `on_reuse_detected(family)` ({doc}`../howto/reuse-detection`);
- on `BaseJWTAuthentication`, `validate_claims(claims)`, `get_user(claims)`
  and `on_authentication_failed(exc)`.

Some choices are class attributes rather than methods. A token's lifetime
belongs to the token class that mints it, so a realm with shorter-lived
access tokens gives its rotation policy another `access_token_class`:

```{literalinclude} ../examples/short_access_urls.py
:language: python
:start-at: class ShortLivedAccessToken
```

The stock authentication classes verify these tokens unchanged, because
they check the expiry the token carries. `rotation` must be an instance,
as it is on `SignetViewMixin`: assigning the class itself leaves
`self.rotation.open_session(...)` unbound, and login raises `TypeError`.

### Template methods

Two classes fix an algorithm and leave its steps to subclasses:

- `BaseJWTAuthentication.authenticate()` always runs extract, verify,
  CSRF (for an ambient credential), family liveness (for a `Strict*`
  class), `validate_claims` and `get_user`, in that order, and gives
  every failure the same response body. The six concrete classes only
  choose a `transport` and set `strict`. Override the hooks, not
  `authenticate()`. See {doc}`../reference/authentication`.
- `RefreshCredentialView` gives refresh, logout and logout-all one
  `read_refresh_credential()`, which reads the credential through the
  view's transport and checks CSRF when it arrived as a cookie. Each view
  adds only what it does with the token.

The same pattern runs below them. `Transport` declares `is_ambient` and
`cookie_policy`, and the CSRF check reads `is_ambient` rather than a class
name, so a new transport decides for itself whether CSRF applies. The one
special case is `HybridTransport`, which can take either path: for it, the
check asks whether this request's credential came from the cookie. `SigningBackend` has an HMAC and an RSA implementation behind one
`sign` and `verify`.

The public API, these hooks and ports included, is not frozen until 1.0.
