## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem this solves. -->

## Checklist

- [ ] `nox -s lint typecheck architecture` passes
- [ ] `nox -s tests` passes
- [ ] New behaviour has a test that fails without the change
- [ ] Touches authentication, tokens or cookies? Then `tests/security/` covers it
- [ ] Public API changes are noted in `CHANGELOG.md`
- [ ] No new global setting was added where a subclass hook would do

## Security impact

<!-- State "none" explicitly if there is none. If this changes token
     handling, cookie flags, or the authentication path, describe the
     threat model change. -->
