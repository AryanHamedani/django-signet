# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through GitHub Security Advisories:
<https://github.com/AryanHamedani/django-signet/security/advisories/new>

Please include the affected version, a description of the issue, and
reproduction steps or a proof of concept if you have one.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 48 hours |
| Initial assessment | 7 days |
| Fix or mitigation plan | 30 days |

Reporters are credited in the advisory and the changelog unless they ask not
to be. We follow coordinated disclosure: the advisory is published once a fix
is available, or after 90 days, whichever comes first.

## Supported versions

Until 1.0, only the latest minor release receives security fixes.

## Scope

In scope: authentication bypass, token forgery, privilege escalation, session
fixation, CSRF bypass, token leakage, and timing attacks in this library.

Out of scope: vulnerabilities in Django, DRF or PyJWT themselves (report those
upstream); insecure configuration explicitly warned about by our system
checks; and denial of service through unbounded request volume, which belongs
to your rate limiter.

## Design notes for reviewers

- Refresh tokens are persisted only as SHA-256 digests.
- `jwt.decode` is always called with an explicit single-element `algorithms`
  list; the token's own `alg` header is never trusted.
- Every authentication failure returns the same generic message, whatever
  its cause, to avoid oracles. A failed CSRF check answers 403 with it;
  every other failure answers 401.
- The adversarial suite in `tests/security/` runs as its own CI job.
