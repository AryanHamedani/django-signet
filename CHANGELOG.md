# Changelog

## 0.1.0 - unreleased

First release.

- httpOnly cookie transport with correct `__Host-` / `__Secure-` prefixes
- Refresh rotation with token families and RFC 9700 reuse detection
- Idempotent grace window for concurrent refreshes
- Refresh tokens stored as sha256 digests only
- `TokenStore` port with ORM and cache adapters, allowlist or denylist
- Stateless access verification plus opt-in `Strict*` classes
- Double-submit CSRF with constant-time comparison, enforced on both the
  access-token authenticator and the refresh endpoint
- Django system checks for insecure or incoherent configuration
