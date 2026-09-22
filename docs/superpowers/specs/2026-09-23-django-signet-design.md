# django-signet — Design Specification

- **Date:** 2026-09-23
- **Status:** Approved for v1 implementation planning
- **Distribution name:** `django-signet`
- **Import / app name:** `django_signet`
- **License:** MIT

---

## 1. Purpose

A JWT authentication library for Django REST Framework that is **polymorphic by
subclassing**, **secure by default**, and **complete enough to be the last JWT
package a project needs to install**.

The thesis is not "JWT in cookies." It is: *authentication should be fully
encapsulated in the backend, and every decision the library makes should be
overridable by subclassing a class — the same way Django and DRF already work.*

---

## 2. Prior art and the gaps we exist to close

`djangorestframework-simplejwt` is the incumbent. Its extension model is a global
settings dictionary of dotted string paths (`TOKEN_OBTAIN_SERIALIZER`,
`USER_AUTHENTICATION_RULE`, `AUTH_TOKEN_CLASSES`, `ON_LOGIN_SUCCESS`). That yields
exactly one implementation per Django project, selected globally, with no
per-view, per-user-type or per-tenant variation. That is configuration, not
polymorphism.

Confirmed functional gaps:

| Gap | State of the art today |
|---|---|
| Cookie transport | Unsupported. Open since jazzband/djangorestframework-simplejwt#71. Hand-rolled in forks and blog posts. |
| Access-token revocation | Impossible; the blacklist covers refresh tokens only (#218). |
| Reuse detection / token families | Absent. `BLACKLIST_AFTER_ROTATION` invalidates the old token but never detects replay of a stolen one. |
| Raw token storage | `OutstandingToken` persists the **full token string**. A database read yields working credentials. |
| Whitelist mode | Not offered. |
| Storage backend | Hardcoded to Django ORM models; no cache/Redis port. |
| Security record | CVE-2024-22513 — disabled users retained access due to a missing user check. |

### Standard we build to

RFC 9700 / BCP 240 (January 2025) requires that refresh tokens for public clients
be **either** sender-constrained **or** rotated with reuse detection, where
replaying a consumed token burns the entire token family. v1 implements the
latter path properly, which makes it standards-defensible without DPoP.

---

## 3. Scope

### In scope for v1

- Token layer: mint/verify, HS256 + RS256, `aud` / `iss` / `leeway`, custom claims hook
- Cookie transport: `HttpOnly`, `Secure`, `SameSite`, `__Host-` / `__Secure-` prefixes, refresh cookie path-scoped to the refresh endpoint
- CSRF: double-submit cookie with constant-time comparison on cookie-authenticated unsafe methods
- Views: login, refresh, verify, logout, logout-all
- Authentication classes: cookie / header / hybrid, each with a `Strict` sibling
- Token families: hashed storage, rotation, reuse detection with grace window
- Store port: ORM adapter (default) + cache adapter
- Revocation: by family, by user, and on password change
- Settings resolution where class attributes take precedence over project settings
- Django system checks for insecure or incoherent configuration
- Full test suite, type hints, CI matrix

### Explicitly deferred (v2+)

Sliding tokens · DPoP / mTLS sender-constraining · JWKS endpoint and key-rotation
tooling · device binding · step-up / MFA claims · session admin UI · Django Ninja
support · Rust signing backend (see §14).

---

## 4. Architecture

```
src/django_signet/          # src layout: must be installed to be importable
├── conf.py              # setting() descriptor: class attr > project settings > default
├── exceptions.py        # internal taxonomy, all surfaced as 401
├── checks.py            # Django system checks
├── tokens/
│   ├── base.py          # Token ABC
│   ├── access.py        # AccessToken
│   ├── refresh.py       # RefreshToken
│   ├── backends.py      # SigningBackend port: HS*, RS*  (Rust seam)
│   └── claims.py        # claim builders and validators
├── sessions/
│   ├── models.py        # TokenFamily, IssuedToken
│   ├── stores/
│   │   ├── base.py      # TokenStore ABC  <- the port
│   │   ├── orm.py       # default
│   │   └── cache.py     # Redis / LocMem
│   └── rotation.py      # RotationPolicy: rotate, detect reuse, grace window
├── transport/
│   ├── base.py          # Transport ABC
│   ├── cookie.py        # CookieTransport + CookiePolicy
│   └── header.py        # HeaderTransport
├── csrf.py              # double-submit issue/validate
├── authentication.py    # DRF surface
├── serializers.py       # DRF surface
├── views.py             # DRF surface
└── urls.py
```

Layering rule: `authentication` / `serializers` / `views` are the only modules a
user is expected to import. They delegate downward and never reach across layers.

### 4.1 The polymorphism mechanism

Every configurable value is declared with a `setting()` descriptor:

```python
class BaseJWTAuthentication(BaseAuthentication):
    access_lifetime = setting("ACCESS_TOKEN_LIFETIME", default=timedelta(minutes=5))
    algorithm       = setting("ALGORITHM", default="HS256")
    store           = setting("STORE", default=ORMTokenStore)
```

Resolution order, highest wins:

1. A literal assigned on the subclass
2. The project's `SIGNET` settings dict
3. The library default

One mechanism delivers both convenient global configuration and per-class
polymorphism, with no forked code paths. Because DRF resolves
`authentication_classes` **per view**, several auth behaviours coexist in one
project for free:

```python
class CustomerJWTAuthentication(CookieJWTAuthentication):
    cookie_policy = CookiePolicy(prefix="shop", samesite="Lax")

class StaffJWTAuthentication(StrictCookieJWTAuthentication):
    cookie_policy = CookiePolicy(prefix="adm", samesite="Strict")
    access_lifetime = timedelta(minutes=10)
```

### 4.2 Design principle: complete defaults

Every base class ships a working, secure default. Overriding is always optional
refinement, never required assembly. If a user must override three methods to get
a functioning login endpoint, the design has failed.

---

## 5. State model

Asymmetric cost, matching asymmetric risk:

- **Access tokens — stateless verification.** Signature, `exp`, `aud`, `iss` only.
  Zero queries on normal API traffic. The 5-minute default lifetime *is* the
  revocation window.
- **Refresh tokens — always session-backed.** Persisted as SHA-256 digests, never
  raw. Every login opens a family; every refresh rotates within it.
- **Opt-in strictness per view.** `StrictCookieJWTAuthentication` additionally
  asserts the family is live, costing one cached lookup, for endpoints where
  instant revocation outranks latency.

Rationale: revocation latency is a dial, not a boolean. Exposing it as two sibling
classes lets one application hold both positions — something a global settings
dict cannot express.

---

## 6. Data model

```python
class TokenFamily(models.Model):
    id            = UUIDField(primary_key=True, default=uuid4)
    user          = ForeignKey(AUTH_USER_MODEL, related_name="signet_families",
                               on_delete=CASCADE)
    created_at    = DateTimeField(auto_now_add=True)
    last_used_at  = DateTimeField(null=True)
    expires_at    = DateTimeField(db_index=True)
    revoked_at    = DateTimeField(null=True, db_index=True)
    revoked_reason= CharField(max_length=32, null=True, choices=RevocationReason)
    user_agent    = CharField(max_length=256, blank=True)
    ip_address    = GenericIPAddressField(null=True)

class IssuedToken(models.Model):
    id          = UUIDField(primary_key=True, default=uuid4)   # == the jti claim
    family      = ForeignKey(TokenFamily, related_name="tokens", on_delete=CASCADE)
    digest      = CharField(max_length=64, unique=True, db_index=True)  # sha256 hex
    issued_at   = DateTimeField(auto_now_add=True)
    expires_at  = DateTimeField(db_index=True)
    consumed_at = DateTimeField(null=True)
```

**Never store the raw token.** We only ever need to answer "is the token just
presented the one I issued?" — a comparison, not a retrieval. A one-way digest
suffices, and there is no key to leak or rotate. Same reasoning Django applies to
passwords.

`RevocationReason` ∈ `{logout, logout_all, reuse_detected, password_change,
expired, admin}` — recorded so operators can distinguish routine logout from a
security event.

---

## 7. The store port

`TokenStore` is the single abstraction behind both whitelist and blacklist
semantics. They are not separate features; they are two implementations of one
interface with opposite defaults.

```python
class TokenStore(ABC):
    @abstractmethod
    def open_family(self, user, digest, expires_at, meta) -> TokenFamily: ...
    @abstractmethod
    def consume(self, digest) -> ConsumeResult: ...   # MUST be atomic
    @abstractmethod
    def is_live(self, family_id) -> bool: ...
    @abstractmethod
    def revoke_family(self, family_id, reason) -> None: ...
    @abstractmethod
    def revoke_all_for_user(self, user, reason) -> None: ...
    @abstractmethod
    def purge_expired(self) -> int: ...
```

- **Denylist semantics:** `is_live` returns `True` unless explicitly revoked.
- **Allowlist semantics:** `is_live` returns `False` unless explicitly issued.

`ConsumeResult` is a frozen value object with three fields: `outcome`, `family`
(the `TokenFamily` row, or `None`), and `issued_token` (the matched `IssuedToken`
row, or `None`). `outcome ∈ {NOT_FOUND, LIVE, ALREADY_CONSUMED, EXPIRED,
FAMILY_REVOKED}`.

**Atomicity requirement.** `consume()` must mark the token consumed and report its
prior state in a single atomic operation — `SELECT … FOR UPDATE` in the ORM
adapter, an atomic compare-and-set in the cache adapter. A non-atomic
implementation makes reuse detection racy and therefore useless.

---

## 8. Rotation and reuse detection

`RotationPolicy` owns the security-critical path.

```python
class RotationPolicy:
    grace_window = timedelta(seconds=10)
    grace_cache  = "default"       # Django cache alias; None disables grace
    burn_family_on_reuse = True
```

### Refresh algorithm

1. Extract the refresh token via the transport.
2. Verify signature, `exp`, `aud`, `iss`.
3. `digest = sha256(token)`; call `store.consume(digest)` **atomically**.
4. Branch on outcome:
   - `NOT_FOUND` / `EXPIRED` / `FAMILY_REVOKED` → 401, clear cookies.
   - `LIVE` → rotate: mint a new pair, persist the successor digest, then cache
     the **rendered outcome** (the new access token, the new refresh token, and
     the CSRF value) under key `digest` for `grace_window`; attach cookies and
     rotate the CSRF token.
   - `ALREADY_CONSUMED` → check the grace cache:
     - **hit** → re-attach the cached pair and return the identical response
       (idempotent replay). This is the only point at which a raw token is held
       outside the client, and only for `grace_window` seconds.
     - **miss** → treat as theft: `store.revoke_family(..., reason=reuse_detected)`,
       fire the `token_reuse_detected` signal, call `on_reuse_detected(family)`,
       return 401 and clear cookies.

### Why the grace window exists

A React app in StrictMode, or two open tabs, can fire `/refresh` twice with the
same token milliseconds apart. Under strict RFC 9700 logic the second request
looks exactly like theft and logs a legitimate user out everywhere. Most
implementations ship this bug.

The grace window makes replay **idempotent**: within the window, the same
successor pair the legitimate client already received is returned again. The
exposure is narrow — a token already in flight to the rightful owner — and the
alternative (minting a second live refresh token per family) is strictly worse.

Setting `grace_cache = None` restores strict RFC 9700 behaviour in one attribute.

**Degradation rule:** if `grace_window` is non-zero but no usable cache is
configured, a Django system check raises a warning and the policy degrades to
strict rather than silently failing open.

---

## 9. Transport layer

```python
class CookiePolicy:
    prefix        = "signet"
    access_name   = "__Host-signet-access"     # Path=/, so __Host- is valid
    refresh_name  = "__Secure-signet-refresh"  # path-scoped, so __Host- is NOT
    csrf_name     = "signet-csrf"      # deliberately readable by JS
    samesite      = "Lax"
    secure        = True
    httponly      = True
    refresh_path  = "/api/auth/refresh"   # path-scoped: not sent on every request
    domain        = None
```

Decisions:

- The refresh cookie is **path-scoped to the refresh endpoint**, so it is not
  transmitted on ordinary API calls, shrinking its exposure surface.
- **Prefix selection is constrained by path scoping.** `__Host-` requires
  `Path=/`, `Secure`, and no `Domain`. The access cookie satisfies all three, so
  it uses `__Host-` and gains protection against subdomain cookie injection. The
  refresh cookie is deliberately path-scoped, which is incompatible with
  `__Host-`; it therefore uses `__Secure-`, which still guarantees an HTTPS-only
  origin. A `__Host-` prefixed cookie with a non-root path is silently rejected by
  browsers, so a system check errors if a user configures that combination.
- Both prefixes are dropped automatically when `secure=False` (and `__Host-` also
  when `domain` is set), each with a system check warning.
- `secure=True` by default. A system check errors if `DEBUG=False` and
  `secure=False`.
- `HeaderTransport` remains available for mobile and service-to-service clients;
  `HybridTransport` prefers the cookie and falls back to the header.

---

## 10. CSRF

Cookie-borne credentials are automatically attached by the browser, so cookie
authentication reintroduces CSRF risk that header authentication does not have.

- On login and on every rotation, issue a random CSRF token in a **readable**
  (non-`HttpOnly`) cookie.
- For unsafe methods (`POST`/`PUT`/`PATCH`/`DELETE`) authenticated **via cookie**,
  require the value echoed in the `X-CSRF-Token` header and compare with
  `hmac.compare_digest`.
- Requests authenticated via the `Authorization` header skip this check — they
  are not subject to ambient credential attachment.
- `SameSite=Lax` is defence in depth, never the sole control.

---

## 11. DRF surface

### Authentication classes

```
BaseJWTAuthentication
├── HeaderJWTAuthentication          └── StrictHeaderJWTAuthentication
├── CookieJWTAuthentication          └── StrictCookieJWTAuthentication
└── HybridJWTAuthentication          └── StrictHybridJWTAuthentication
```

Overridable hooks: `get_token(request)`, `get_user(claims)`,
`validate_claims(claims)`, `on_authentication_failed(exc)`.

### Views

`TokenObtainView` · `TokenRefreshView` · `TokenVerifyView` · `LogoutView` ·
`LogoutAllView`, wired by `django_signet.urls`.

Template Method throughout: `post()` owns the invariant sequence; subclasses
override only the decisions.

```python
class LoginView(TokenObtainView):
    serializer_class = MyLoginSerializer

    def get_claims(self, user):
        return {"org": user.org_id}

    def set_cookies(self, response, pair):
        super().set_cookies(response, pair)
        response.set_cookie("tenant", user.tenant_id)


class RefreshView(TokenRefreshView):
    def on_reuse_detected(self, family):
        notify_security_team(family.user)
```

Hook names are a frozen API contract from v1 onward. `on_reuse_detected(family)`
is deliberately an *event* hook — it reports that an incident occurred and hands
over the blast radius, without requiring the caller to understand detection.

---

## 12. Error handling

Internal taxonomy: `TokenExpired`, `TokenInvalid`, `TokenRevoked`, `TokenReused`,
`CSRFFailed`, `TransportError`.

**Every one surfaces to the client as a generic DRF `AuthenticationFailed` (401).**
The response never discloses whether the user was unknown, the password wrong, the
token expired, or the family revoked. The internal types exist only for logging,
hooks and signals.

The refresh endpoint clears auth cookies on any 401 so a dead session cannot loop.

Signals: `token_issued`, `token_refreshed`, `token_reuse_detected`,
`family_revoked`.

---

## 13. Testing strategy

pytest + pytest-django. Unit tests per component against a faked store;
integration tests through the real DRF request cycle.

A dedicated **security suite** is mandatory and gates release:

- Algorithm confusion: `alg: none`, HS/RS substitution, key confusion
- Signature tampering, truncation, and claim injection
- Expired / not-yet-valid / wrong-`aud` / wrong-`iss` tokens
- Cookie flag assertions (`HttpOnly`, `Secure`, `SameSite`, `__Host-`, path scope)
- CSRF: missing header, wrong value, header-auth bypass attempt
- Reuse detection: replay outside the grace window burns the family
- Concurrent refresh: two simultaneous requests inside the window both succeed
  and do **not** burn the family
- Disabled-user regression, pinning CVE-2024-22513
- Revocation on password change

Matrix, via nox (Django 4.2 LTS reached end of life in April 2026 and is
excluded):

| | Django 5.2 LTS | Django 6.0 | Django 6.1 |
|---|---|---|---|
| Python 3.12 | yes | yes | yes |
| Python 3.13 | yes | yes | yes |
| Python 3.14 | no (unsupported by 5.2) | yes | yes |

DRF 3.16+.

---

## 14. Packaging, and the Rust question

Build backend: hatchling, `src/` layout. Typed (`py.typed`, PEP 561).

Quality gates, all enforced in CI and pre-commit:

| Gate | Tool |
|---|---|
| Lint and format | `ruff check` + `ruff format --check` |
| Types | `mypy --strict` |
| **Architecture fitness** | `import-linter` contracts |
| Complexity ceiling | ruff `C90`, max 8 |
| Security static analysis | ruff `S` (bandit rules) + CodeQL |
| Tests | pytest across the 8-cell matrix |
| Adversarial suite | `tests/security/` as a separate blocking job |

Coupling is enforced rather than documented. Four `import-linter` contracts
encode the layering in §4: `tokens` is a leaf; `transport` knows nothing about
storage or authentication; `sessions` never touches the wire; and `conf`,
`exceptions`, `hashing` and `signals` depend on nothing above them. Crossing a
boundary fails CI, so a coupling regression cannot land quietly.

Release runs through GitHub Actions with PyPI Trusted Publishing (OIDC), so no
API token exists in the repository or on any developer machine.

**Rust is deferred, on measured evidence.** Benchmarked on this machine
(PyJWT 2.10.1, HS256, 324-byte token):

```
full decode+verify        27.30 µs
  raw HMAC (OpenSSL/C)     3.38 µs
  b64 + json.loads (C)     6.82 µs
  pure-Python glue        17.10 µs   <- the only part Rust could win
```

A perfect Rust rewrite saves ≈22 µs. The `User.objects.get()` that follows costs
200–500 µs against Postgres. Against that, the costs are:

1. `cryptography` (PyJWT's asymmetric dependency) already ships Rust internals.
2. Distribution: 30+ wheels per release, and sdist installs fail without a Rust
   toolchain — a serious adoption barrier for a library deployed to arbitrary
   infrastructure.
3. **Decisive:** a Rust fast path plus a Python fallback means two implementations
   of signature verification. Divergence between them — over `alg: none`, audience
   validation, leeway — is an authentication bypass. Doubling the audit surface to
   reclaim ~1% of a request is a bad trade for a security library.

`tokens/backends.py` defines the `SigningBackend` port anyway, so a Rust backend
later is a purely additive `django-signet[rust]` change. v1 ships a `benchmarks/`
harness. **Revisit trigger:** real-deployment profiling showing verification above
5% of request time.

The genuinely promising future target is not the verify path but an in-process
Bloom/cuckoo filter of revoked `jti`s, eliminating the Redis round-trip for
`Strict*` authentication — a 200–500 µs saving, roughly 20× larger. Deferred to v3.

---

## 15. Success criteria for v1

1. A working, secure cookie-based login → refresh → logout flow in under 15 lines
   of user code.
2. Every behavioural decision overridable by subclassing, with no settings changes
   required.
3. The security suite in §13 passing on every supported matrix cell.
4. No raw token persisted anywhere, at any time, except the grace cache within its
   window.
5. Published to PyPI with documentation covering migration from
   `djangorestframework-simplejwt`.
6. Every quality gate in §14 green on `main`, and the repository carrying the
   governance an open-source security library is expected to have: MIT licence,
   a `SECURITY.md` with a private disclosure channel and stated response
   targets, a code of conduct, a contributing guide that states the
   architecture rules, issue and pull-request templates, CODEOWNERS, and
   automated dependency updates.
