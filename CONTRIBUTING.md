# Contributing to django-signet

Thank you for considering a contribution.

## Ground rules

This is a security library. Two consequences follow:

1. **Never open a public issue for a vulnerability.** See [SECURITY.md](SECURITY.md).
2. **Every change to authentication, token handling, or cookies needs a test
   that fails without it.** "It works locally" is not evidence.

## Getting set up

```bash
python -m venv .venv
.venv/bin/pip install -e ".[rsa]"
.venv/bin/pip install nox pre-commit
.venv/bin/pre-commit install
```

## Before you open a pull request

```bash
nox            # lint, typecheck, architecture, and the full matrix
```

Or individually:

```bash
nox -s lint typecheck architecture
nox -s tests
```

All four must pass. CI runs the same sessions.

## Architecture rules

Module boundaries are enforced by `import-linter` contracts in
`pyproject.toml`, not by convention:

- `tokens` is a leaf: it knows nothing about storage, the wire, or DRF.
- `transport` moves bytes: it knows nothing about storage or authentication.
- `sessions` persists and rotates: it never touches the wire.
- `conf`, `exceptions`, `hashing`, `signals` and `users` depend on nothing above
  them.

If your change needs to cross a boundary, that is a design discussion — open
an issue before writing the code.

## Style

- `ruff` handles formatting and linting; do not hand-format.
- Maximum cyclomatic complexity is 8. If a function trips it, it wants
  splitting rather than an ignore comment.
- Public API needs type hints; `mypy --strict` must pass. It gates `src/`
  only - the test suite is **not** type-checked (the `tests.*` override in
  `pyproject.toml` relaxes it, and `mypy tests` currently reports existing
  errors). Don't read a green `mypy` run as covering the tests.
- New behaviour is added by subclassing hooks, not by adding settings flags.
  If your feature needs a new global setting, say why in the issue first.

## Commit messages

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
Security fixes use `fix(security):` and reference the advisory.

## Adding a hook

Hook names and signatures are public API, but **the public API is not
frozen until 1.0.** This is 0.x: a hook may still be renamed, moved or
change shape in a minor release when a design flaw demands it - 0.1.0's
own final review moved `get_claims` onto the refresh path and replaced
`RotationPolicy.rotate(extra=...)` with `rotate(get_claims=...)`. Every
such change is called out in `CHANGELOG.md`. From 1.0 on, renaming or
removing a hook is a breaking change and waits for a major release.
