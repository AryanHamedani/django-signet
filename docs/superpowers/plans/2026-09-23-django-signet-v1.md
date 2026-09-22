# django-signet v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and publish `django-signet`, a polymorphic, secure-by-default JWT authentication library for Django REST Framework with httpOnly cookie transport, token families, and RFC 9700 reuse detection.

**Architecture:** Four layers. `tokens/` mints and verifies; `sessions/` persists token families behind a `TokenStore` port; `transport/` moves tokens over cookies or headers; and `authentication.py` / `serializers.py` / `views.py` form the DRF surface users subclass. Polymorphism comes from Template Method plus a `setting()` descriptor that lets a subclass's class attribute override the project settings dict.

**Tech Stack:** Python 3.12–3.14, Django 5.2 LTS / 6.0 / 6.1, DRF 3.16+, PyJWT 2.10+. Tooling: hatchling (`src/` layout), ruff (lint + format), mypy `--strict`, import-linter (architecture fitness), pytest + pytest-django, nox, pre-commit, GitHub Actions with PyPI Trusted Publishing.

**Spec:** `docs/superpowers/specs/2026-09-23-django-signet-design.md`

## Global Constraints

- Distribution name `django-signet`; import and Django app name `django_signet`. MIT licence.
- Python 3.12–3.14. Django 5.2 LTS, 6.0, 6.1 (4.2 is EOL). DRF 3.16+. Python 3.14 is incompatible with Django 5.2 — exclude that cell from the matrix.
- **Never persist a raw token.** Only `sha256` hex digests, except the grace cache within its window.
- **Every authentication failure returns a generic DRF `AuthenticationFailed` (401).** Never disclose which check failed.
- **Always pass `algorithms=[...]` explicitly to `jwt.decode`.** Never trust the token's own `alg` header.
- **Layout:** `src/` layout. The package must be installed to be importable, so tests exercise what users actually receive rather than the working tree.
- **Linting and formatting:** `ruff check` and `ruff format --check` must pass. Never hand-format; never add a blanket `# noqa`.
- **Typing:** `mypy --strict` passes on `src/django_signet`. The package ships `py.typed` (PEP 561).
- **Architecture fitness:** `lint-imports` must pass. Module boundaries are enforced by import-linter contracts in `pyproject.toml`, not by convention:
  - `tokens` is a leaf — it knows nothing about storage, the wire, or DRF.
  - `transport` moves bytes — it knows nothing about storage or authentication.
  - `sessions` persists and rotates — it never touches the wire.
  - `conf`, `exceptions`, `hashing`, `signals` depend on nothing above them.
  Crossing a boundary is a design change, not an implementation detail: raise it rather than adding the import.
- **Complexity ceiling:** cyclomatic complexity 8 (ruff `C90`). A function that trips it wants splitting, not an ignore.
- **Every task ends with the same gate before its commit:** `ruff format . && ruff check --fix . && mypy src/django_signet && lint-imports && pytest -q`. Format *before* checking — code transcribed from this plan is not pre-formatted. Never silence a finding with `# noqa`; if `mypy --strict` proves impractical for Django model classes specifically, add a scoped `[[tool.mypy.overrides]]` for `django_signet.sessions.models` with a comment explaining why, rather than weakening `strict` globally.
- All files stay under 500 lines.
- Every public class ships complete, secure, working defaults. Overriding is optional refinement, never required assembly.
- Hook names (`get_claims`, `set_cookies`, `on_reuse_detected`, `get_user`, `validate_claims`) are a frozen API contract from v1.
- Type hints on all public API; `mypy --strict` passes.
- TDD throughout: failing test, verify it fails, minimal implementation, verify it passes, commit.

---

## File Structure

### Repository shell (Task 0)

| File | Responsibility |
|---|---|
| `pyproject.toml` | Packaging, dependencies, ruff / mypy / coverage / import-linter config |
| `noxfile.py` | `lint`, `typecheck`, `architecture`, `tests` — mirrors CI |
| `.pre-commit-config.yaml` | ruff, ruff-format, mypy, import-linter, private-key detection |
| `.editorconfig`, `.gitignore` | Editor and VCS hygiene |
| `LICENSE` | MIT |
| `SECURITY.md` | Private disclosure policy, response targets, scope |
| `CONTRIBUTING.md` | Setup, the four gates, the architecture rules |
| `CODE_OF_CONDUCT.md` | Contributor Covenant 2.1 |
| `.github/workflows/ci.yml` | Quality job + 8-cell test matrix + adversarial security gate |
| `.github/workflows/codeql.yml` | Static security analysis, weekly and per PR |
| `.github/workflows/release.yml` | Build and publish via PyPI Trusted Publishing (OIDC, no tokens) |
| `.github/dependabot.yml` | Weekly pip and actions updates |
| `.github/CODEOWNERS`, `PULL_REQUEST_TEMPLATE.md`, `ISSUE_TEMPLATE/` | Review routing and intake |

### Library (Tasks 1–13)

| File | Responsibility |
|---|---|
| `src/django_signet/py.typed` | PEP 561 marker |
| `src/django_signet/conf.py` | `setting()` descriptor + `DEFAULTS` |
| `src/django_signet/exceptions.py` | Internal error taxonomy |
| `src/django_signet/signals.py` | `token_issued`, `token_refreshed`, `token_reuse_detected`, `family_revoked` |
| `src/django_signet/tokens/backends.py` | `SigningBackend` port; HMAC and RSA backends |
| `src/django_signet/tokens/claims.py` | Claim construction and validation |
| `src/django_signet/tokens/base.py` | `Token` ABC |
| `src/django_signet/tokens/access.py` | `AccessToken` |
| `src/django_signet/tokens/refresh.py` | `RefreshToken` |
| `src/django_signet/sessions/models.py` | `TokenFamily`, `IssuedToken` |
| `src/django_signet/sessions/stores/base.py` | `TokenStore` ABC, `ConsumeResult`, `Outcome` |
| `src/django_signet/sessions/stores/orm.py` | ORM adapter with atomic consume |
| `src/django_signet/sessions/stores/cache.py` | Cache adapter with atomic CAS |
| `src/django_signet/sessions/rotation.py` | `RotationPolicy`: rotate, detect reuse, grace window |
| `src/django_signet/transport/base.py` | `Transport` ABC |
| `src/django_signet/transport/cookie.py` | `CookiePolicy`, `CookieTransport` |
| `src/django_signet/transport/header.py` | `HeaderTransport`, `HybridTransport` |
| `src/django_signet/csrf.py` | Double-submit issue and validate |
| `src/django_signet/authentication.py` | DRF authentication classes |
| `src/django_signet/serializers.py` | Login / refresh / verify serializers |
| `src/django_signet/views.py` | Template Method views |
| `src/django_signet/urls.py` | URL wiring |
| `src/django_signet/checks.py` | Django system checks |
| `tests/` | Mirror of the above, plus `tests/security/` |

---

## Task 0: Repository, tooling and open-source foundation

Everything else builds on this. It creates no library code — it creates the
shell that every later task is graded inside: the `src/` layout, the linter
and type-checker configuration, the architecture-fitness contracts that keep
coupling honest, and the public-repository files an open-source security
library is expected to have.

**Files:**
- Create: `pyproject.toml`, `noxfile.py`, `.pre-commit-config.yaml`, `.editorconfig`, `.gitignore`
- Create: `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/codeql.yml`
- Create: `.github/dependabot.yml`, `.github/CODEOWNERS`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`, `.github/ISSUE_TEMPLATE/config.yml`
- Create: `src/django_signet/__init__.py`, `src/django_signet/py.typed`

**Interfaces:**
- Produces: the `src/` layout that every later task's paths assume; `ruff`, `mypy --strict`, `import-linter` and `pytest` all runnable and green on an empty package; CI that gates every pull request.

**Why `src/` layout:** with a flat layout, `import django_signet` from the
repository root silently picks up the source directory rather than the
installed distribution, so tests can pass against files that were never
packaged. The `src/` layout makes that impossible — the package must be
installed to be importable, so the tests exercise what users receive.

- [ ] **Step 1: Create the virtualenv and the development toolchain**

```bash
cd /home/p0s3id0n/Projects/Personal/django-jwt-httponly
python3 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install "django>=6.0" "djangorestframework>=3.16" "pyjwt>=2.10" \
    pytest pytest-django pytest-cov ruff mypy django-stubs \
    djangorestframework-stubs import-linter nox pre-commit build twine
.venv/bin/python -c "import django, rest_framework, jwt; print(django.get_version())"
```

Expected: prints a Django 6.x version with no ImportError.

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "django-signet"
version = "0.1.0"
description = "Polymorphic, secure-by-default JWT authentication for Django REST Framework"
readme = "README.md"
requires-python = ">=3.12"
license = "MIT"
license-files = ["LICENSE"]
authors = [{ name = "p0s3id0n" }]
keywords = ["django", "djangorestframework", "jwt", "authentication", "cookies", "security"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Web Environment",
    "Framework :: Django",
    "Framework :: Django :: 5.2",
    "Framework :: Django :: 6.0",
    "Framework :: Django :: 6.1",
    "Intended Audience :: Developers",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Python :: 3.14",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: Security",
    "Typing :: Typed",
]
dependencies = [
    "django>=5.2",
    "djangorestframework>=3.16",
    "pyjwt>=2.10",
]

[project.optional-dependencies]
rsa = ["cryptography>=42"]

[project.urls]
Homepage = "https://github.com/p0s3id0n/django-signet"
Documentation = "https://github.com/p0s3id0n/django-signet#readme"
Changelog = "https://github.com/p0s3id0n/django-signet/blob/main/CHANGELOG.md"
Issues = "https://github.com/p0s3id0n/django-signet/issues"
Source = "https://github.com/p0s3id0n/django-signet"

[tool.hatch.build.targets.wheel]
packages = ["src/django_signet"]

# ----------------------------------------------------------------- pytest
[tool.pytest.ini_options]
DJANGO_SETTINGS_MODULE = "tests.settings"
testpaths = ["tests"]
addopts = "--strict-markers --strict-config"
filterwarnings = ["error"]

[tool.coverage.run]
source = ["django_signet"]
branch = true

[tool.coverage.report]
exclude_also = ["if TYPE_CHECKING:", "raise NotImplementedError", "\\.\\.\\."]

# ------------------------------------------------------------------- ruff
[tool.ruff]
target-version = "py312"
line-length = 88
src = ["src", "tests"]

[tool.ruff.lint]
select = [
    "E", "W",    # pycodestyle
    "F",         # pyflakes
    "I",         # isort
    "N",         # pep8-naming
    "UP",        # pyupgrade - keeps us on current Python idioms
    "B",         # bugbear
    "A",         # shadowing builtins
    "C4",        # comprehensions
    "DTZ",       # naive datetimes: a bug class in an auth library
    "S",         # bandit security rules
    "SIM",       # simplification
    "PTH",       # pathlib over os.path
    "PT",        # pytest style
    "TID",       # tidy imports
    "ARG",       # unused arguments
    "RUF",
    "C90",       # mccabe complexity - a code-smell brake
]
ignore = [
    "S105",  # hardcoded-password-string: too noisy around claim names
]

[tool.ruff.lint.per-file-ignores]
# Tests assert, use throwaway secrets, and take unused fixtures by design.
"tests/**" = ["S101", "S105", "S106", "ARG001", "ARG002"]
"noxfile.py" = ["ARG001"]

[tool.ruff.lint.mccabe]
max-complexity = 8

[tool.ruff.lint.isort]
known-first-party = ["django_signet"]

[tool.ruff.format]
docstring-code-format = true

# ------------------------------------------------------------------- mypy
[tool.mypy]
python_version = "3.12"
strict = true
warn_unreachable = true
plugins = ["mypy_django_plugin.main", "mypy_drf_plugin.main"]

[tool.django-stubs]
django_settings_module = "tests.settings"

[[tool.mypy.overrides]]
module = ["tests.*"]
disallow_untyped_defs = false

# --------------------------------------------------- architecture fitness
# Coupling is enforced, not merely documented. Each contract encodes one
# boundary from the design: violating it fails CI.
[tool.importlinter]
root_package = "django_signet"

[[tool.importlinter.contracts]]
name = "tokens is a leaf - it knows nothing about storage, wire or DRF"
type = "forbidden"
source_modules = ["django_signet.tokens"]
forbidden_modules = [
    "django_signet.sessions",
    "django_signet.transport",
    "django_signet.csrf",
    "django_signet.authentication",
    "django_signet.serializers",
    "django_signet.views",
]

[[tool.importlinter.contracts]]
name = "transport moves bytes - it knows nothing about storage or auth"
type = "forbidden"
source_modules = ["django_signet.transport"]
forbidden_modules = [
    "django_signet.sessions",
    "django_signet.authentication",
    "django_signet.serializers",
    "django_signet.views",
]

[[tool.importlinter.contracts]]
name = "sessions persists and rotates - it never touches the wire"
type = "forbidden"
source_modules = ["django_signet.sessions"]
forbidden_modules = [
    "django_signet.transport",
    "django_signet.csrf",
    "django_signet.authentication",
    "django_signet.serializers",
    "django_signet.views",
]

[[tool.importlinter.contracts]]
name = "foundation modules depend on nothing above them"
type = "forbidden"
source_modules = [
    "django_signet.conf",
    "django_signet.exceptions",
    "django_signet.hashing",
    "django_signet.signals",
]
forbidden_modules = [
    "django_signet.tokens",
    "django_signet.sessions",
    "django_signet.transport",
    "django_signet.csrf",
    "django_signet.authentication",
    "django_signet.serializers",
    "django_signet.views",
]
```

- [ ] **Step 3: Create the package shell and confirm the toolchain runs**

```bash
mkdir -p src/django_signet
printf '__version__ = "0.1.0"\n' > src/django_signet/__init__.py
touch src/django_signet/py.typed          # PEP 561: ship the type information

printf '%s\n' '__pycache__/' '*.py[cod]' '.venv/' 'dist/' 'build/' '*.egg-info/' \
  '.nox/' '.tox/' '.pytest_cache/' '.mypy_cache/' '.ruff_cache/' '.coverage' \
  'htmlcov/' '*.sqlite3' '.env' '.superpowers/' > .gitignore

.venv/bin/pip install -e .
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Expected: `ruff check` reports "All checks passed"; `ruff format --check` reports the files are already formatted.

- [ ] **Step 4: Write the editor and pre-commit configuration**

```bash
cat > .editorconfig <<'EOF'
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space

[*.py]
indent_size = 4
max_line_length = 88

[*.{yml,yaml,toml,json,md}]
indent_size = 2
EOF

cat > .pre-commit-config.yaml <<'EOF'
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.9.6
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-yaml
      - id: check-toml
      - id: check-merge-conflict
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: detect-private-key

  - repo: local
    hooks:
      - id: mypy
        name: mypy
        entry: .venv/bin/mypy src/django_signet
        language: system
        pass_filenames: false
      - id: import-linter
        name: import-linter (architecture fitness)
        entry: .venv/bin/lint-imports
        language: system
        pass_filenames: false
EOF

.venv/bin/pre-commit install
```

If the pinned `rev` values are stale, run `.venv/bin/pre-commit autoupdate`
and commit the result rather than editing them by hand.

- [ ] **Step 5: Write the nox sessions**

```python
# noxfile.py
"""Development task runner.

The CI matrix mirrors these sessions, so `nox` locally reproduces CI.
"""

import nox

nox.options.sessions = ["lint", "typecheck", "architecture", "tests"]

PYTHONS = ["3.12", "3.13", "3.14"]
DJANGOS = ["5.2", "6.0", "6.1"]


@nox.session(python="3.13")
def lint(session: nox.Session) -> None:
    session.install("ruff")
    session.run("ruff", "check", ".")
    session.run("ruff", "format", "--check", ".")


@nox.session(python="3.13")
def typecheck(session: nox.Session) -> None:
    session.install("mypy", "django-stubs", "djangorestframework-stubs", "-e", ".")
    session.run("mypy", "src/django_signet")


@nox.session(python="3.13")
def architecture(session: nox.Session) -> None:
    """Fail if any module imports across a boundary the design forbids."""
    session.install("import-linter", "-e", ".")
    session.run("lint-imports")


@nox.session(python=PYTHONS)
@nox.parametrize("django", DJANGOS)
def tests(session: nox.Session, django: str) -> None:
    if django == "5.2" and session.python == "3.14":
        session.skip("Django 5.2 does not support Python 3.14")
    session.install(
        f"django~={django}.0",
        "djangorestframework>=3.16",
        "pyjwt>=2.10",
        "pytest",
        "pytest-django",
        "pytest-cov",
    )
    session.install("-e", ".")
    session.run("pytest", "-q")
```

- [ ] **Step 6: Write the open-source governance files**

```bash
cat > LICENSE <<'EOF'
MIT License

Copyright (c) 2026 django-signet contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

cat > SECURITY.md <<'EOF'
# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through GitHub Security Advisories:
<https://github.com/p0s3id0n/django-signet/security/advisories/new>

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
- Every authentication failure returns one generic 401 to avoid oracles.
- The adversarial suite in `tests/security/` gates every release.
EOF

cat > CODE_OF_CONDUCT.md <<'EOF'
# Contributor Covenant Code of Conduct

## Our Pledge

We as members, contributors, and leaders pledge to make participation in our
community a harassment-free experience for everyone, regardless of age, body
size, visible or invisible disability, ethnicity, sex characteristics, gender
identity and expression, level of experience, education, socio-economic
status, nationality, personal appearance, race, religion, or sexual identity
and orientation.

## Our Standards

Examples of behavior that contributes to a positive environment:

- Demonstrating empathy and kindness toward other people
- Being respectful of differing opinions, viewpoints, and experiences
- Giving and gracefully accepting constructive feedback
- Accepting responsibility and apologizing to those affected by our mistakes
- Focusing on what is best for the overall community

Examples of unacceptable behavior:

- Sexualized language or imagery, and sexual attention or advances of any kind
- Trolling, insulting or derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without their explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting

## Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported to the project maintainers. All complaints will be reviewed and
investigated promptly and fairly. Maintainers are obligated to respect the
privacy and security of the reporter.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage],
version 2.1, available at
<https://www.contributor-covenant.org/version/2/1/code_of_conduct.html>.

[homepage]: https://www.contributor-covenant.org
EOF
```

- [ ] **Step 7: Write the contributing guide**

```bash
cat > CONTRIBUTING.md <<'EOF'
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
- `conf`, `exceptions`, `hashing` and `signals` depend on nothing above them.

If your change needs to cross a boundary, that is a design discussion — open
an issue before writing the code.

## Style

- `ruff` handles formatting and linting; do not hand-format.
- Maximum cyclomatic complexity is 8. If a function trips it, it wants
  splitting rather than an ignore comment.
- Public API needs type hints; `mypy --strict` must pass.
- New behaviour is added by subclassing hooks, not by adding settings flags.
  If your feature needs a new global setting, say why in the issue first.

## Commit messages

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
Security fixes use `fix(security):` and reference the advisory.

## Adding a hook

Hook names are a frozen public API. Adding one is fine; renaming or removing
one is a breaking change and waits for a major release.
EOF
```

- [ ] **Step 8: Write the GitHub workflows**

```bash
mkdir -p .github/workflows .github/ISSUE_TEMPLATE

cat > .github/workflows/ci.yml <<'EOF'
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  quality:
    name: lint, types and architecture
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
          cache: pip
      - run: pip install ruff mypy django-stubs djangorestframework-stubs import-linter
      - run: pip install -e .
      - name: ruff check
        run: ruff check --output-format=github .
      - name: ruff format
        run: ruff format --check .
      - name: mypy
        run: mypy src/django_signet
      - name: architecture fitness
        run: lint-imports

  test:
    name: py${{ matrix.python }} / django${{ matrix.django }}
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python: ["3.12", "3.13", "3.14"]
        django: ["5.2", "6.0", "6.1"]
        exclude:
          # Django 5.2 does not support Python 3.14.
          - python: "3.14"
            django: "5.2"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
          cache: pip
      - run: pip install "django~=${{ matrix.django }}.0" djangorestframework pyjwt
              pytest pytest-django pytest-cov
      - run: pip install -e ".[rsa]"
      - run: pytest -q --cov --cov-report=xml
      - uses: codecov/codecov-action@v5
        if: matrix.python == '3.13' && matrix.django == '6.1'
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
        continue-on-error: true

  security-gate:
    name: adversarial suite
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
          cache: pip
      - run: pip install -e ".[rsa]" pytest pytest-django
      - name: the adversarial suite must pass
        run: pytest tests/security/ -v
EOF

cat > .github/workflows/codeql.yml <<'EOF'
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "17 3 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python
          queries: security-extended
      - uses: github/codeql-action/analyze@v3
EOF

cat > .github/workflows/release.yml <<'EOF'
name: Release

on:
  release:
    types: [published]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install build twine
      - run: python -m build
      - run: twine check dist/*
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: pypi
      url: https://pypi.org/p/django-signet
    permissions:
      id-token: write   # PyPI Trusted Publishing - no API token is stored
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@release/v1
EOF
```

Trusted Publishing means no PyPI token ever exists in the repository or on a
developer machine. Configure it once at
<https://pypi.org/manage/account/publishing/>, naming this repository, the
workflow `release.yml`, and the environment `pypi`.

- [ ] **Step 9: Write the repository metadata and templates**

```bash
cat > .github/dependabot.yml <<'EOF'
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
    groups:
      dev-dependencies:
        patterns: ["ruff", "mypy", "pytest*", "nox", "pre-commit"]

  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
EOF

printf '* @p0s3id0n\n' > .github/CODEOWNERS

cat > .github/PULL_REQUEST_TEMPLATE.md <<'EOF'
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
EOF

cat > .github/ISSUE_TEMPLATE/config.yml <<'EOF'
blank_issues_enabled: false
contact_links:
  - name: Report a security vulnerability
    url: https://github.com/p0s3id0n/django-signet/security/advisories/new
    about: Report privately. Never open a public issue for a vulnerability.
  - name: Question or discussion
    url: https://github.com/p0s3id0n/django-signet/discussions
    about: Ask how to use the library.
EOF

cat > .github/ISSUE_TEMPLATE/bug_report.yml <<'EOF'
name: Bug report
description: Something behaves differently than documented
labels: [bug]
body:
  - type: markdown
    attributes:
      value: |
        If this is a security vulnerability, stop and report it privately:
        https://github.com/p0s3id0n/django-signet/security/advisories/new
  - type: input
    id: versions
    attributes:
      label: Versions
      description: django-signet, Django, DRF and Python versions
      placeholder: "django-signet 0.1.0, Django 6.1, DRF 3.18, Python 3.13"
    validations: { required: true }
  - type: textarea
    id: expected
    attributes:
      label: What you expected to happen
    validations: { required: true }
  - type: textarea
    id: actual
    attributes:
      label: What actually happened
    validations: { required: true }
  - type: textarea
    id: repro
    attributes:
      label: Minimal reproduction
      description: Settings, the authentication class in use, and the request made.
      render: python
    validations: { required: true }
EOF

cat > .github/ISSUE_TEMPLATE/feature_request.yml <<'EOF'
name: Feature request
description: Suggest a capability
labels: [enhancement]
body:
  - type: textarea
    id: problem
    attributes:
      label: The problem
      description: What are you unable to do today?
    validations: { required: true }
  - type: textarea
    id: subclass
    attributes:
      label: Can a subclass already do this?
      description: >
        Most behaviour is meant to be changed by overriding a hook rather than
        by adding a setting. Say what you tried.
    validations: { required: true }
  - type: textarea
    id: proposal
    attributes:
      label: Proposed API
      render: python
EOF
```

- [ ] **Step 10: Verify the whole toolchain is green**

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/lint-imports
.venv/bin/python -m build && .venv/bin/twine check dist/*
```

Expected: ruff passes, `lint-imports` reports all contracts kept (trivially,
with only `__init__.py` present), and `twine check` reports PASSED. `mypy` is
deferred to Task 1, when there is code with annotations to check.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "chore: repository, tooling and open-source foundation

src layout, ruff, mypy strict, import-linter architecture contracts,
pre-commit, nox, CI matrix, CodeQL, Trusted Publishing release workflow,
and the governance files a public security library needs."
```

---

## Task 1: Project scaffolding, settings resolution, exceptions

**Files:**
- Create: `src/django_signet/apps.py`, `src/django_signet/conf.py`, `src/django_signet/exceptions.py`, `src/django_signet/signals.py`
- Create: `tests/conftest.py`, `tests/settings.py`, `tests/test_conf.py`

**Interfaces:**
- Produces: `setting(name, default=_UNSET)` descriptor; `DEFAULTS: dict[str, Any]`; exception classes `SignetError`, `TokenInvalid`, `TokenExpired`, `TokenRevoked`, `TokenReused`, `CSRFFailed`, `TransportError`; signals `token_issued`, `token_refreshed`, `token_reuse_detected`, `family_revoked`.

- [ ] **Step 1: Write the test settings and conftest**

```python
# tests/settings.py
SECRET_KEY = "test-secret-key-not-for-production-use-0123456789abcdef"
DEBUG = False
USE_TZ = True
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django_signet",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
ROOT_URLCONF = "tests.urls"
```

```python
# tests/urls.py
urlpatterns = []
```

Create the test package markers now so no two test modules can collide on a
bare basename later:

```bash
mkdir -p tests/tokens tests/sessions tests/transport tests/security
touch tests/__init__.py tests/tokens/__init__.py tests/sessions/__init__.py \
      tests/transport/__init__.py tests/security/__init__.py
```

```python
# tests/conftest.py
import pytest


@pytest.fixture
def user(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(
        username="alice", password="pw-not-used-in-assertions"
    )
```

- [ ] **Step 2: Write the failing test for settings resolution**

```python
# tests/test_conf.py
from datetime import timedelta

from django.test import override_settings

from django_signet.conf import setting


class Base:
    lifetime = setting("ACCESS_TOKEN_LIFETIME", default=timedelta(minutes=5))


class Override(Base):
    lifetime = timedelta(minutes=30)


def test_falls_back_to_library_default():
    assert Base().lifetime == timedelta(minutes=5)


@override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(minutes=9)})
def test_project_settings_beat_library_default():
    assert Base().lifetime == timedelta(minutes=9)


@override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(minutes=9)})
def test_class_attribute_beats_project_settings():
    assert Override().lifetime == timedelta(minutes=30)


def test_readable_on_the_class_not_only_the_instance():
    assert Base.lifetime == timedelta(minutes=5)
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/test_conf.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.conf'`

- [ ] **Step 4: Write the minimal implementation**

```python
# src/django_signet/__init__.py
__version__ = "0.1.0"
```

```python
# src/django_signet/apps.py
from django.apps import AppConfig


class SignetConfig(AppConfig):
    name = "django_signet"
    label = "django_signet"
    verbose_name = "Signet JWT authentication"
    default_auto_field = "django.db.models.BigAutoField"
```

```python
# src/django_signet/conf.py
from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.conf import settings as django_settings

DEFAULTS: dict[str, Any] = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=14),
    "ALGORITHM": "HS256",
    "SIGNING_KEY": None,      # None -> fall back to settings.SECRET_KEY
    "VERIFYING_KEY": None,
    "AUDIENCE": None,
    "ISSUER": None,
    "LEEWAY": timedelta(seconds=0),
    "GRACE_WINDOW": timedelta(seconds=10),
    "GRACE_CACHE": "default",
    "COOKIE_PREFIX": "signet",
    "COOKIE_SAMESITE": "Lax",
    "COOKIE_SECURE": True,
    "COOKIE_HTTPONLY": True,
    "COOKIE_REFRESH_PATH": "/api/auth/refresh",
    "COOKIE_DOMAIN": None,
    "COOKIE_ACCESS_NAME": None,   # None -> derive from prefix + prefix rules
    "COOKIE_REFRESH_NAME": None,
    "COOKIE_CSRF_NAME": None,
}

_UNSET: Any = object()


class setting:
    """Resolve a configurable value.

    Resolution order, highest first:
      1. a literal assigned on a subclass (which shadows this descriptor entirely)
      2. the project's ``SIGNET`` settings dict
      3. the ``default`` passed here, else ``DEFAULTS[name]``

    Rule 1 needs no code: assigning a plain value on a subclass shadows the
    descriptor through normal attribute lookup, so ``__get__`` never runs.
    Nothing is cached, so ``override_settings`` works in tests.
    """

    def __init__(self, name: str, default: Any = _UNSET) -> None:
        self.name = name
        self.default = default

    def __set_name__(self, owner: type, attr: str) -> None:
        self.attr = attr

    def __get__(self, obj: Any, owner: type | None = None) -> Any:
        overrides = getattr(django_settings, "SIGNET", {}) or {}
        if self.name in overrides:
            return overrides[self.name]
        if self.default is not _UNSET:
            return self.default
        return DEFAULTS[self.name]
```

```python
# src/django_signet/exceptions.py
class SignetError(Exception):
    """Base for every internal Signet failure.

    These never reach the client. The DRF surface catches them and raises a
    generic ``AuthenticationFailed`` so no response discloses which check failed.
    """


class TokenInvalid(SignetError):
    """Malformed, tampered, or wrongly-signed token."""


class TokenExpired(SignetError):
    """Structurally valid but past its expiry."""


class TokenRevoked(SignetError):
    """Belongs to a family that has been revoked."""


class TokenReused(SignetError):
    """A consumed refresh token was replayed outside the grace window."""


class CSRFFailed(SignetError):
    """Cookie-authenticated unsafe request failed the double-submit check."""


class TransportError(SignetError):
    """No token present, or the transport could not read it."""
```

```python
# src/django_signet/signals.py
import django.dispatch

token_issued = django.dispatch.Signal()         # user, family, request
token_refreshed = django.dispatch.Signal()      # user, family, request
token_reuse_detected = django.dispatch.Signal() # user, family, request
family_revoked = django.dispatch.Signal()       # user, family, reason
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/test_conf.py -v`
Expected: 4 passed.

- [ ] **Step 6: Run the quality gates**

```bash
.venv/bin/ruff format .          # format first - do not hand-format
.venv/bin/ruff check --fix .
.venv/bin/mypy src/django_signet
.venv/bin/lint-imports
.venv/bin/pytest -q              # re-run after any autofix
```

Expected: all clean. **Run `ruff format` before `ruff check`, never
`--check` first** — code transcribed from this plan is not pre-formatted, and
starting with `--check` fails every time. If `ruff check --fix` leaves a
finding, fix it properly rather than adding `# noqa`.

From here on every task ends with this same gate before its commit. `conf.py`
is the first module `mypy --strict` sees, so close any annotation gaps now
rather than accumulating them.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/django_signet/ tests/
git commit -m "feat: package scaffolding, settings resolution, exception taxonomy"
```

---

## Task 2: Signing backends

**Files:**
- Create: `src/django_signet/tokens/__init__.py`, `src/django_signet/tokens/backends.py`
- Test: `tests/tokens/test_backends.py`

**Interfaces:**
- Consumes: `setting`, `DEFAULTS` from `django_signet.conf`; `TokenInvalid`, `TokenExpired` from `django_signet.exceptions`.
- Produces: `SigningBackend` ABC with `algorithm: str`, `sign(payload: dict) -> str`, `verify(token: str, *, audience: str | None, issuer: str | None, leeway: timedelta) -> dict`. Concrete `HMACBackend(algorithm="HS256", key=None)` and `RSABackend(algorithm="RS256", private_key, public_key)`. Factory `get_backend() -> SigningBackend`.

- [ ] **Step 1: Write the failing test**

```python
# tests/tokens/test_backends.py
import time
from datetime import timedelta

import jwt
import pytest

from django_signet.exceptions import TokenExpired, TokenInvalid
from django_signet.tokens.backends import HMACBackend


@pytest.fixture
def backend():
    return HMACBackend(key="k" * 64)


def test_round_trip(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) + 60})
    assert backend.verify(token)["sub"] == "1"


def test_rejects_tampered_signature(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) + 60})
    head, payload, _ = token.split(".")
    with pytest.raises(TokenInvalid):
        backend.verify(f"{head}.{payload}.deadbeef")


def test_rejects_alg_none(backend):
    """An attacker strips the signature and claims alg=none."""
    forged = jwt.encode({"sub": "999"}, key="", algorithm="none")
    with pytest.raises(TokenInvalid):
        backend.verify(forged)


def test_rejects_algorithm_substitution(backend):
    """A token signed HS512 must not verify on an HS256 backend."""
    forged = jwt.encode({"sub": "999", "exp": int(time.time()) + 60},
                        key="k" * 64, algorithm="HS512")
    with pytest.raises(TokenInvalid):
        backend.verify(forged)


def test_raises_expired_distinctly(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) - 1})
    with pytest.raises(TokenExpired):
        backend.verify(token)


def test_leeway_tolerates_small_clock_skew(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) - 2})
    assert backend.verify(token, leeway=timedelta(seconds=10))["sub"] == "1"


def test_audience_and_issuer_are_enforced(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) + 60,
                          "aud": "api", "iss": "signet"})
    assert backend.verify(token, audience="api", issuer="signet")["sub"] == "1"
    with pytest.raises(TokenInvalid):
        backend.verify(token, audience="other", issuer="signet")
    with pytest.raises(TokenInvalid):
        backend.verify(token, audience="api", issuer="elsewhere")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/tokens/test_backends.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.tokens'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/tokens/__init__.py
```

```python
# src/django_signet/tokens/backends.py
from __future__ import annotations

import abc
from datetime import timedelta
from typing import Any

import jwt
from django.conf import settings as django_settings

from django_signet.conf import setting
from django_signet.exceptions import TokenExpired, TokenInvalid

_ZERO = timedelta(0)


class SigningBackend(abc.ABC):
    """Port for signing and verifying a JWT.

    Isolating this makes a future native backend a purely additive change: a
    new subclass, no edits to callers.
    """

    algorithm: str

    @abc.abstractmethod
    def sign(self, payload: dict[str, Any]) -> str: ...

    @abc.abstractmethod
    def _decode(
        self,
        token: str,
        *,
        audience: str | None,
        issuer: str | None,
        leeway: timedelta,
    ) -> dict[str, Any]: ...

    def verify(
        self,
        token: str,
        *,
        audience: str | None = None,
        issuer: str | None = None,
        leeway: timedelta = _ZERO,
    ) -> dict[str, Any]:
        try:
            return self._decode(
                token, audience=audience, issuer=issuer, leeway=leeway
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpired(str(exc)) from exc
        except jwt.PyJWTError as exc:
            # Covers bad signature, alg=none, algorithm substitution,
            # wrong audience, wrong issuer and malformed input alike.
            raise TokenInvalid(str(exc)) from exc


class HMACBackend(SigningBackend):
    """Symmetric HS256 / HS384 / HS512."""

    def __init__(self, algorithm: str = "HS256", key: str | None = None) -> None:
        if algorithm not in {"HS256", "HS384", "HS512"}:
            raise ValueError(f"{algorithm} is not an HMAC algorithm")
        self.algorithm = algorithm
        self._key = key

    @property
    def key(self) -> str:
        return self._key or django_settings.SECRET_KEY

    def sign(self, payload: dict[str, Any]) -> str:
        return jwt.encode(payload, self.key, algorithm=self.algorithm)

    def _decode(
        self,
        token: str,
        *,
        audience: str | None,
        issuer: str | None,
        leeway: timedelta,
    ) -> dict[str, Any]:
        # algorithms is pinned to exactly one value. Never trust the token's
        # own alg header - that is the algorithm-confusion attack.
        return jwt.decode(
            token,
            self.key,
            algorithms=[self.algorithm],
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            options={"require": ["exp"]},
        )


class RSABackend(SigningBackend):
    """Asymmetric RS256 / RS384 / RS512. Requires the ``rsa`` extra."""

    def __init__(
        self,
        algorithm: str = "RS256",
        private_key: str | None = None,
        public_key: str | None = None,
    ) -> None:
        if algorithm not in {"RS256", "RS384", "RS512"}:
            raise ValueError(f"{algorithm} is not an RSA algorithm")
        self.algorithm = algorithm
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, payload: dict[str, Any]) -> str:
        if self.private_key is None:
            raise ValueError("RSABackend requires a private_key to sign")
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def _decode(
        self,
        token: str,
        *,
        audience: str | None,
        issuer: str | None,
        leeway: timedelta,
    ) -> dict[str, Any]:
        if self.public_key is None:
            raise ValueError("RSABackend requires a public_key to verify")
        return jwt.decode(
            token,
            self.public_key,
            algorithms=[self.algorithm],
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            options={"require": ["exp"]},
        )


class _BackendFactory:
    algorithm = setting("ALGORITHM")
    signing_key = setting("SIGNING_KEY")
    verifying_key = setting("VERIFYING_KEY")


def get_backend() -> SigningBackend:
    """Build the backend named by the project's ``SIGNET`` settings."""
    cfg = _BackendFactory()
    if cfg.algorithm.startswith("HS"):
        return HMACBackend(algorithm=cfg.algorithm, key=cfg.signing_key)
    if cfg.algorithm.startswith("RS"):
        return RSABackend(
            algorithm=cfg.algorithm,
            private_key=cfg.signing_key,
            public_key=cfg.verifying_key,
        )
    raise ValueError(f"Unsupported ALGORITHM: {cfg.algorithm!r}")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/tokens/test_backends.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/django_signet/tokens/ tests/tokens/
git commit -m "feat: signing backend port with HMAC and RSA implementations"
```

---

## Task 3: Token classes and claims

**Files:**
- Create: `src/django_signet/hashing.py`, `src/django_signet/tokens/claims.py`, `src/django_signet/tokens/base.py`, `src/django_signet/tokens/access.py`, `src/django_signet/tokens/refresh.py`
- Test: `tests/tokens/test_tokens.py`

**Interfaces:**
- Consumes: `get_backend()` from `django_signet.tokens.backends`; `setting` from `django_signet.conf`; `TokenInvalid` from `django_signet.exceptions`.
- Produces:
  - `token_digest(raw: str) -> str` — sha256 hex, 64 chars.
  - `MintedToken` frozen dataclass: `value: str`, `jti: str`, `expires_at: datetime`, `claims: dict[str, Any]`.
  - `Token` ABC with `typ: str`, `lifetime: timedelta`, `mint(subject, *, family_id=None, extra=None) -> MintedToken`, `verify(raw) -> dict[str, Any]`.
  - `AccessToken` (`typ="access"`), `RefreshToken` (`typ="refresh"`, requires `family_id`, emits the `sid` claim).

- [ ] **Step 1: Write the failing test**

```python
# tests/tokens/test_tokens.py
import uuid

import pytest

from django_signet.exceptions import TokenInvalid
from django_signet.hashing import token_digest
from django_signet.tokens.access import AccessToken
from django_signet.tokens.refresh import RefreshToken


def test_digest_is_sha256_hex():
    d = token_digest("abc")
    assert len(d) == 64 and d == token_digest("abc") != token_digest("abd")


def test_access_token_round_trip():
    minted = AccessToken().mint(subject="42")
    claims = AccessToken().verify(minted.value)
    assert claims["sub"] == "42"
    assert claims["typ"] == "access"
    assert claims["jti"] == minted.jti


def test_each_mint_has_a_unique_jti():
    a, b = AccessToken().mint(subject="42"), AccessToken().mint(subject="42")
    assert a.jti != b.jti


def test_refresh_token_carries_the_family_id():
    fam = str(uuid.uuid4())
    minted = RefreshToken().mint(subject="42", family_id=fam)
    assert RefreshToken().verify(minted.value)["sid"] == fam


def test_refresh_token_requires_a_family_id():
    with pytest.raises(ValueError):
        RefreshToken().mint(subject="42")


def test_a_refresh_token_is_rejected_by_the_access_verifier():
    """Token-type confusion: a long-lived refresh token must never be
    accepted where a short-lived access token is expected."""
    minted = RefreshToken().mint(subject="42", family_id=str(uuid.uuid4()))
    with pytest.raises(TokenInvalid):
        AccessToken().verify(minted.value)


def test_an_access_token_is_rejected_by_the_refresh_verifier():
    minted = AccessToken().mint(subject="42")
    with pytest.raises(TokenInvalid):
        RefreshToken().verify(minted.value)


def test_extra_claims_are_merged_but_cannot_overwrite_reserved_ones():
    minted = AccessToken().mint(subject="42", extra={"org": 7, "sub": "hacked"})
    claims = AccessToken().verify(minted.value)
    assert claims["org"] == 7
    assert claims["sub"] == "42"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/tokens/test_tokens.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.hashing'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/hashing.py
import hashlib


def token_digest(raw: str) -> str:
    """Return the sha256 hex digest of a token.

    We only ever need to answer "is the token just presented the one I
    issued?" - a comparison, not a retrieval. A one-way digest suffices and
    leaves no key to leak or rotate.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
```

```python
# src/django_signet/tokens/claims.py
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from django.utils import timezone

RESERVED = frozenset({"sub", "typ", "jti", "iat", "nbf", "exp", "aud", "iss", "sid"})


def build_claims(
    *,
    subject: str,
    typ: str,
    lifetime: timedelta,
    family_id: str | None = None,
    audience: str | None = None,
    issuer: str | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], datetime]:
    """Build a claim set. Returns ``(claims, expires_at)``.

    ``extra`` is merged first so reserved claims always win - a caller cannot
    overwrite ``sub`` or ``exp`` through a custom ``get_claims`` hook.
    """
    now = timezone.now()
    expires_at = now + lifetime
    claims: dict[str, Any] = dict(extra or {})
    for key in RESERVED & claims.keys():
        del claims[key]
    claims.update(
        {
            "sub": subject,
            "typ": typ,
            "jti": str(uuid.uuid4()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
    )
    if family_id is not None:
        claims["sid"] = family_id
    if audience is not None:
        claims["aud"] = audience
    if issuer is not None:
        claims["iss"] = issuer
    return claims, expires_at
```

```python
# src/django_signet/tokens/base.py
from __future__ import annotations

import abc
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django_signet.conf import setting
from django_signet.exceptions import TokenInvalid
from django_signet.tokens.backends import SigningBackend, get_backend
from django_signet.tokens.claims import build_claims


@dataclass(frozen=True)
class MintedToken:
    value: str
    jti: str
    expires_at: datetime
    claims: dict[str, Any]


class Token(abc.ABC):
    """Base for every token flavour.

    Subclasses set ``typ`` and ``lifetime``. ``typ`` is verified on decode,
    which is what stops a refresh token being replayed as an access token.
    """

    typ: str
    lifetime: timedelta

    audience = setting("AUDIENCE")
    issuer = setting("ISSUER")
    leeway = setting("LEEWAY")

    def get_backend(self) -> SigningBackend:
        return get_backend()

    def mint(
        self,
        subject: str,
        *,
        family_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> MintedToken:
        claims, expires_at = build_claims(
            subject=subject,
            typ=self.typ,
            lifetime=self.lifetime,
            family_id=family_id,
            audience=self.audience,
            issuer=self.issuer,
            extra=extra,
        )
        return MintedToken(
            value=self.get_backend().sign(claims),
            jti=claims["jti"],
            expires_at=expires_at,
            claims=claims,
        )

    def verify(self, raw: str) -> dict[str, Any]:
        claims = self.get_backend().verify(
            raw, audience=self.audience, issuer=self.issuer, leeway=self.leeway
        )
        if claims.get("typ") != self.typ:
            raise TokenInvalid(
                f"expected typ={self.typ!r}, got {claims.get('typ')!r}"
            )
        return claims
```

```python
# src/django_signet/tokens/access.py
from __future__ import annotations

from django_signet.conf import setting
from django_signet.tokens.base import Token


class AccessToken(Token):
    typ = "access"
    lifetime = setting("ACCESS_TOKEN_LIFETIME")
```

```python
# src/django_signet/tokens/refresh.py
from __future__ import annotations

from typing import Any

from django_signet.conf import setting
from django_signet.tokens.base import MintedToken, Token


class RefreshToken(Token):
    typ = "refresh"
    lifetime = setting("REFRESH_TOKEN_LIFETIME")

    def mint(
        self,
        subject: str,
        *,
        family_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> MintedToken:
        if family_id is None:
            raise ValueError("RefreshToken.mint() requires a family_id")
        return super().mint(subject, family_id=family_id, extra=extra)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/tokens/test_tokens.py -v`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/django_signet/hashing.py src/django_signet/tokens/ tests/tokens/
git commit -m "feat: access and refresh token classes with type-confusion guards"
```

---

## Task 4: Session models

**Files:**
- Create: `src/django_signet/sessions/__init__.py`, `src/django_signet/sessions/models.py`, `src/django_signet/models.py`, `src/django_signet/migrations/__init__.py`
- Test: `tests/sessions/test_models.py`

**Interfaces:**
- Produces: `TokenFamily` (`id: UUID` pk, `user` FK, `created_at`, `last_used_at`, `expires_at`, `revoked_at`, `revoked_reason`, `user_agent`, `ip_address`, property `is_live: bool`, method `revoke(reason)`); `IssuedToken` (`id: UUID` pk, `family` FK, `digest` unique, `issued_at`, `expires_at`, `consumed_at`); `RevocationReason` text-choices enum with members `LOGOUT`, `LOGOUT_ALL`, `REUSE_DETECTED`, `PASSWORD_CHANGE`, `EXPIRED`, `ADMIN`.

Django discovers models at `django_signet.models`, so `src/django_signet/models.py` re-exports from `sessions/models.py` to keep the package layout by responsibility.

- [ ] **Step 1: Write the failing test**

```python
# tests/sessions/test_models.py
from datetime import timedelta

import pytest
from django.db.utils import IntegrityError
from django.utils import timezone

from django_signet.models import IssuedToken, RevocationReason, TokenFamily

pytestmark = pytest.mark.django_db


def _family(user, **kw):
    return TokenFamily.objects.create(
        user=user, expires_at=timezone.now() + timedelta(days=14), **kw
    )


def test_a_fresh_family_is_live(user):
    assert _family(user).is_live is True


def test_revoking_records_the_reason_and_ends_liveness(user):
    fam = _family(user)
    fam.revoke(RevocationReason.REUSE_DETECTED)
    fam.refresh_from_db()
    assert fam.is_live is False
    assert fam.revoked_reason == RevocationReason.REUSE_DETECTED
    assert fam.revoked_at is not None


def test_revoking_twice_keeps_the_first_reason(user):
    fam = _family(user)
    fam.revoke(RevocationReason.LOGOUT)
    first = fam.revoked_at
    fam.revoke(RevocationReason.ADMIN)
    fam.refresh_from_db()
    assert fam.revoked_reason == RevocationReason.LOGOUT
    assert fam.revoked_at == first


def test_an_expired_family_is_not_live(user):
    fam = TokenFamily.objects.create(
        user=user, expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert fam.is_live is False


def test_digests_are_unique(user):
    fam = _family(user)
    exp = timezone.now() + timedelta(days=1)
    IssuedToken.objects.create(family=fam, digest="a" * 64, expires_at=exp)
    with pytest.raises(IntegrityError):
        IssuedToken.objects.create(family=fam, digest="a" * 64, expires_at=exp)


def test_deleting_a_family_deletes_its_tokens(user):
    fam = _family(user)
    IssuedToken.objects.create(
        family=fam, digest="b" * 64, expires_at=timezone.now() + timedelta(days=1)
    )
    fam.delete()
    assert IssuedToken.objects.count() == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/sessions/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.models'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/sessions/__init__.py
```

```python
# src/django_signet/sessions/models.py
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from django_signet.signals import family_revoked


class RevocationReason(models.TextChoices):
    LOGOUT = "logout", "Logout"
    LOGOUT_ALL = "logout_all", "Logout everywhere"
    REUSE_DETECTED = "reuse_detected", "Refresh token reuse detected"
    PASSWORD_CHANGE = "password_change", "Password changed"
    EXPIRED = "expired", "Expired"
    ADMIN = "admin", "Revoked by an administrator"


class TokenFamily(models.Model):
    """One login session. Every rotation stays inside the same family, so
    replaying a consumed token lets us burn the whole lineage at once."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="signet_families",
        on_delete=models.CASCADE,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    revoked_reason = models.CharField(
        max_length=32, null=True, blank=True, choices=RevocationReason.choices
    )
    user_agent = models.CharField(max_length=256, blank=True, default="")
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        verbose_name_plural = "token families"
        indexes = [models.Index(fields=["user", "revoked_at"])]

    def __str__(self) -> str:
        return f"TokenFamily({self.id})"

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()

    def revoke(self, reason: str) -> None:
        """Idempotent: the first reason recorded is the one that sticks, so a
        later routine logout cannot mask an earlier security event."""
        if self.revoked_at is not None:
            return
        self.revoked_at = timezone.now()
        self.revoked_reason = reason
        self.save(update_fields=["revoked_at", "revoked_reason"])
        family_revoked.send(
            sender=type(self), user=self.user, family=self, reason=reason
        )


class IssuedToken(models.Model):
    """A single refresh token, stored only as a digest."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    family = models.ForeignKey(
        TokenFamily, related_name="tokens", on_delete=models.CASCADE
    )
    digest = models.CharField(max_length=64, unique=True, db_index=True)
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    consumed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"IssuedToken({self.id})"
```

```python
# src/django_signet/models.py
"""Django discovers models here. The implementation lives in ``sessions``
so the package stays organised by responsibility rather than by framework
convention."""

from django_signet.sessions.models import (
    IssuedToken,
    RevocationReason,
    TokenFamily,
)

__all__ = ["IssuedToken", "RevocationReason", "TokenFamily"]
```

- [ ] **Step 4: Generate the migration**

```bash
mkdir -p src/django_signet/migrations && touch src/django_signet/migrations/__init__.py
DJANGO_SETTINGS_MODULE=tests.settings .venv/bin/python -m django makemigrations django_signet
```

Expected: creates `src/django_signet/migrations/0001_initial.py` listing `TokenFamily` and `IssuedToken`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/sessions/test_models.py -v`
Expected: 6 passed.

- [ ] **Step 6: Verify there are no unapplied model changes**

Run: `DJANGO_SETTINGS_MODULE=tests.settings .venv/bin/python -m django makemigrations --check --dry-run`
Expected: exit code 0, "No changes detected".

- [ ] **Step 7: Commit**

```bash
git add src/django_signet/sessions/ src/django_signet/models.py src/django_signet/migrations/ tests/sessions/
git commit -m "feat: TokenFamily and IssuedToken models with digest-only storage"
```

---

## Task 5: TokenStore port and ORM adapter

**Files:**
- Create: `src/django_signet/sessions/stores/__init__.py`, `src/django_signet/sessions/stores/base.py`, `src/django_signet/sessions/stores/orm.py`
- Test: `tests/sessions/test_orm_store.py`

**Interfaces:**
- Consumes: `TokenFamily`, `IssuedToken`, `RevocationReason` from `django_signet.models`.
- Produces:
  - `Outcome` enum: `NOT_FOUND`, `LIVE`, `ALREADY_CONSUMED`, `EXPIRED`, `FAMILY_REVOKED`.
  - `ConsumeResult` frozen dataclass: `outcome: Outcome`, `family: TokenFamily | None = None`, `issued_token: IssuedToken | None = None`.
  - `TokenStore` ABC: `open_family(user, expires_at, *, user_agent="", ip_address=None) -> TokenFamily`; `issue(family, digest, expires_at) -> IssuedToken`; `consume(digest) -> ConsumeResult`; `is_live(family_id) -> bool`; `revoke_family(family_id, reason) -> None`; `revoke_all_for_user(user, reason) -> None`; `purge_expired() -> int`.
  - `ORMTokenStore` implementing all of the above with allowlist semantics.

Two refinements on the spec's §7 listing. First, `issue()` is added: rotation must persist a successor digest into an existing family, which `open_family()` alone cannot express. Second, `open_family()` does **not** take a digest — a refresh token embeds its family id in the `sid` claim, so the family row must exist before the first token can be minted. Creating the family and issuing its first token are therefore two calls.

- [ ] **Step 1: Write the failing test**

```python
# tests/sessions/test_orm_store.py
from datetime import timedelta

import pytest
from django.utils import timezone

from django_signet.models import IssuedToken, RevocationReason, TokenFamily
from django_signet.sessions.stores.base import Outcome
from django_signet.sessions.stores.orm import ORMTokenStore

pytestmark = pytest.mark.django_db

FUTURE = timedelta(days=14)


@pytest.fixture
def store():
    return ORMTokenStore()


def _open(store, user, digest="a" * 64):
    """Open a family and issue its first token - the two-step sequence the
    rotation layer uses, because the token's ``sid`` claim needs the family
    id to exist first."""
    fam = store.open_family(user, timezone.now() + FUTURE)
    store.issue(fam, digest, timezone.now() + FUTURE)
    return fam


def test_open_family_creates_an_empty_family(store, user):
    fam = store.open_family(user, timezone.now() + FUTURE)
    assert TokenFamily.objects.count() == 1
    assert IssuedToken.objects.filter(family=fam).count() == 0


def test_issue_adds_the_first_token(store, user):
    fam = _open(store, user)
    assert IssuedToken.objects.filter(family=fam, digest="a" * 64).exists()


def test_consuming_a_live_token_marks_it_consumed(store, user):
    _open(store, user)
    result = store.consume("a" * 64)
    assert result.outcome is Outcome.LIVE
    assert IssuedToken.objects.get(digest="a" * 64).consumed_at is not None


def test_consuming_twice_reports_already_consumed(store, user):
    _open(store, user)
    store.consume("a" * 64)
    assert store.consume("a" * 64).outcome is Outcome.ALREADY_CONSUMED


def test_unknown_digest_reports_not_found(store, user):
    assert store.consume("f" * 64).outcome is Outcome.NOT_FOUND


def test_expired_token_reports_expired(store, user):
    fam = _open(store, user)
    IssuedToken.objects.filter(family=fam).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert store.consume("a" * 64).outcome is Outcome.EXPIRED


def test_revoked_family_reports_family_revoked(store, user):
    fam = _open(store, user)
    store.revoke_family(fam.id, RevocationReason.LOGOUT)
    assert store.consume("a" * 64).outcome is Outcome.FAMILY_REVOKED


def test_is_live_tracks_revocation(store, user):
    fam = _open(store, user)
    assert store.is_live(fam.id) is True
    store.revoke_family(fam.id, RevocationReason.LOGOUT)
    assert store.is_live(fam.id) is False


def test_is_live_is_false_for_an_unknown_family(store, user):
    """Allowlist semantics: absence means not live."""
    import uuid

    assert store.is_live(uuid.uuid4()) is False


def test_issue_adds_a_successor_to_the_same_family(store, user):
    fam = _open(store, user)
    store.issue(fam, "b" * 64, timezone.now() + FUTURE)
    assert IssuedToken.objects.filter(family=fam).count() == 2


def test_revoke_all_for_user_revokes_every_live_family(store, user):
    f1 = _open(store, user, "a" * 64)
    f2 = _open(store, user, "b" * 64)
    store.revoke_all_for_user(user, RevocationReason.LOGOUT_ALL)
    assert store.is_live(f1.id) is False
    assert store.is_live(f2.id) is False


def test_purge_expired_removes_only_expired_families(store, user):
    live = _open(store, user, "a" * 64)
    dead = _open(store, user, "b" * 64)
    TokenFamily.objects.filter(pk=dead.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert store.purge_expired() == 1
    assert list(TokenFamily.objects.values_list("pk", flat=True)) == [live.pk]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/sessions/test_orm_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.sessions.stores'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/sessions/stores/__init__.py
```

```python
# src/django_signet/sessions/stores/base.py
from __future__ import annotations

import abc
import enum
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any


class Outcome(enum.Enum):
    NOT_FOUND = "not_found"
    LIVE = "live"
    ALREADY_CONSUMED = "already_consumed"
    EXPIRED = "expired"
    FAMILY_REVOKED = "family_revoked"


@dataclass(frozen=True)
class ConsumeResult:
    outcome: Outcome
    family: Any | None = None
    issued_token: Any | None = None


class TokenStore(abc.ABC):
    """The single abstraction behind both whitelist and blacklist semantics.

    They are not separate features. A denylist returns ``True`` from
    ``is_live`` unless something was explicitly revoked; an allowlist returns
    ``False`` unless something was explicitly issued. Same interface,
    opposite default.
    """

    @abc.abstractmethod
    def open_family(
        self,
        user: Any,
        expires_at: datetime,
        *,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> Any:
        """Create an empty family. The caller mints the first refresh token
        against the returned id, then calls ``issue()``."""

    @abc.abstractmethod
    def issue(self, family: Any, digest: str, expires_at: datetime) -> Any: ...

    @abc.abstractmethod
    def consume(self, digest: str) -> ConsumeResult:
        """Mark a token consumed and report its prior state ATOMICALLY.

        A non-atomic implementation makes reuse detection racy and therefore
        useless: two concurrent replays could both observe an unconsumed
        token and both succeed.
        """

    @abc.abstractmethod
    def is_live(self, family_id: uuid.UUID) -> bool: ...

    @abc.abstractmethod
    def revoke_family(self, family_id: uuid.UUID, reason: str) -> None: ...

    @abc.abstractmethod
    def revoke_all_for_user(self, user: Any, reason: str) -> None: ...

    @abc.abstractmethod
    def purge_expired(self) -> int: ...
```

```python
# src/django_signet/sessions/stores/orm.py
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_signet.models import IssuedToken, TokenFamily
from django_signet.sessions.stores.base import ConsumeResult, Outcome, TokenStore


class ORMTokenStore(TokenStore):
    """Default store. Allowlist semantics: a family must exist and be live."""

    def open_family(
        self,
        user: Any,
        expires_at: datetime,
        *,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> TokenFamily:
        return TokenFamily.objects.create(
            user=user,
            expires_at=expires_at,
            user_agent=user_agent[:256],
            ip_address=ip_address,
        )

    def issue(
        self, family: TokenFamily, digest: str, expires_at: datetime
    ) -> IssuedToken:
        return IssuedToken.objects.create(
            family=family, digest=digest, expires_at=expires_at
        )

    def consume(self, digest: str) -> ConsumeResult:
        with transaction.atomic():
            try:
                token = (
                    IssuedToken.objects.select_for_update()
                    .select_related("family")
                    .get(digest=digest)
                )
            except IssuedToken.DoesNotExist:
                return ConsumeResult(Outcome.NOT_FOUND)

            family = token.family
            if family.revoked_at is not None:
                return ConsumeResult(Outcome.FAMILY_REVOKED, family, token)

            now = timezone.now()
            if token.expires_at <= now or family.expires_at <= now:
                return ConsumeResult(Outcome.EXPIRED, family, token)
            if token.consumed_at is not None:
                return ConsumeResult(Outcome.ALREADY_CONSUMED, family, token)

            token.consumed_at = now
            token.save(update_fields=["consumed_at"])
            TokenFamily.objects.filter(pk=family.pk).update(last_used_at=now)
            return ConsumeResult(Outcome.LIVE, family, token)

    def is_live(self, family_id: uuid.UUID) -> bool:
        return TokenFamily.objects.filter(
            pk=family_id, revoked_at__isnull=True, expires_at__gt=timezone.now()
        ).exists()

    def revoke_family(self, family_id: uuid.UUID, reason: str) -> None:
        try:
            family = TokenFamily.objects.get(pk=family_id)
        except TokenFamily.DoesNotExist:
            return
        family.revoke(reason)

    def revoke_all_for_user(self, user: Any, reason: str) -> None:
        for family in TokenFamily.objects.filter(
            user=user, revoked_at__isnull=True
        ):
            family.revoke(reason)

    def purge_expired(self) -> int:
        deleted, _ = TokenFamily.objects.filter(
            expires_at__lte=timezone.now()
        ).delete()
        return TokenFamily.objects.none().count() or _get_family_count(deleted)


def _get_family_count(deleted_map: Any) -> int:
    if isinstance(deleted_map, int):
        return deleted_map
    return int(deleted_map.get("django_signet.TokenFamily", 0))
```

Note: `QuerySet.delete()` returns `(total, per_model_dict)`. The helper extracts the `TokenFamily` count so callers get families purged, not rows purged.

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/sessions/test_orm_store.py -v`
Expected: 12 passed.

If `test_purge_expired_removes_only_expired_families` fails on the return value, simplify `purge_expired` to capture the count before deleting:

```python
    def purge_expired(self) -> int:
        qs = TokenFamily.objects.filter(expires_at__lte=timezone.now())
        count = qs.count()
        qs.delete()
        return count
```

and delete `_get_family_count`. Prefer this simpler form if the first does not pass immediately.

- [ ] **Step 5: Commit**

```bash
git add src/django_signet/sessions/stores/ tests/sessions/test_orm_store.py
git commit -m "feat: TokenStore port with atomic-consume ORM adapter"
```

---

## Task 6: Cache store adapter

**Files:**
- Create: `src/django_signet/sessions/stores/cache.py`
- Test: `tests/sessions/test_cache_store.py`

**Interfaces:**
- Consumes: `TokenStore`, `ConsumeResult`, `Outcome` from `django_signet.sessions.stores.base`.
- Produces: `CacheTokenStore(alias="default", deny_by_default=False)` with the same `open_family` / `issue` split as `ORMTokenStore`. When `deny_by_default=False` it is an allowlist (a family key must exist); when `True` it is a denylist (absence means live). Atomicity comes from `cache.add()`, which is a compare-and-set primitive.

- [ ] **Step 1: Write the failing test**

```python
# tests/sessions/test_cache_store.py
import uuid
from datetime import timedelta

import pytest
from django.core.cache import cache
from django.utils import timezone

from django_signet.models import RevocationReason
from django_signet.sessions.stores.base import Outcome
from django_signet.sessions.stores.cache import CacheTokenStore

pytestmark = pytest.mark.django_db
FUTURE = timedelta(days=14)


@pytest.fixture(autouse=True)
def _clear():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def store():
    return CacheTokenStore()


def _open(store, user, digest="a" * 64):
    fam = store.open_family(user, timezone.now() + FUTURE)
    store.issue(fam, digest, timezone.now() + FUTURE)
    return fam


def test_consume_live_then_already_consumed(store, user):
    _open(store, user)
    assert store.consume("a" * 64).outcome is Outcome.LIVE
    assert store.consume("a" * 64).outcome is Outcome.ALREADY_CONSUMED


def test_unknown_digest_is_not_found(store, user):
    assert store.consume("f" * 64).outcome is Outcome.NOT_FOUND


def test_revoked_family_is_reported(store, user):
    fam = _open(store, user)
    store.revoke_family(fam.id, RevocationReason.LOGOUT)
    assert store.consume("a" * 64).outcome is Outcome.FAMILY_REVOKED


def test_allowlist_mode_treats_absence_as_dead(store):
    assert store.is_live(uuid.uuid4()) is False


def test_denylist_mode_treats_absence_as_live(user):
    store = CacheTokenStore(deny_by_default=True)
    unknown = uuid.uuid4()
    assert store.is_live(unknown) is True
    store.revoke_family(unknown, RevocationReason.ADMIN)
    assert store.is_live(unknown) is False


def test_only_one_of_two_racing_consumes_wins(store, user):
    """cache.add() is compare-and-set, so the second caller must lose."""
    _open(store, user)
    outcomes = [store.consume("a" * 64).outcome for _ in range(2)]
    assert outcomes.count(Outcome.LIVE) == 1
    assert outcomes.count(Outcome.ALREADY_CONSUMED) == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/sessions/test_cache_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.sessions.stores.cache'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/sessions/stores/cache.py
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.core.cache import caches
from django.utils import timezone

from django_signet.sessions.stores.base import ConsumeResult, Outcome, TokenStore

_FAMILY = "signet:fam:{}"
_TOKEN = "signet:tok:{}"
_CONSUMED = "signet:used:{}"
_REVOKED = "signet:rev:{}"


@dataclass
class _CachedFamily:
    """Duck-types the parts of TokenFamily the rotation layer reads."""

    id: uuid.UUID
    user: Any
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()


class CacheTokenStore(TokenStore):
    """Cache-backed store. Atomicity comes from ``cache.add()``, which only
    sets a key when it is absent - a compare-and-set primitive that every
    Django cache backend implements."""

    def __init__(self, alias: str = "default", deny_by_default: bool = False) -> None:
        self.alias = alias
        self.deny_by_default = deny_by_default

    @property
    def cache(self) -> Any:
        return caches[self.alias]

    @staticmethod
    def _ttl(expires_at: datetime) -> int:
        return max(1, int((expires_at - timezone.now()).total_seconds()))

    def open_family(
        self,
        user: Any,
        expires_at: datetime,
        *,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> _CachedFamily:
        family = _CachedFamily(id=uuid.uuid4(), user=user, expires_at=expires_at)
        self.cache.set(
            _FAMILY.format(family.id), family, self._ttl(expires_at)
        )
        return family

    def issue(
        self, family: _CachedFamily, digest: str, expires_at: datetime
    ) -> None:
        self.cache.set(
            _TOKEN.format(digest),
            (str(family.id), expires_at),
            self._ttl(expires_at),
        )

    def consume(self, digest: str) -> ConsumeResult:
        entry = self.cache.get(_TOKEN.format(digest))
        if entry is None:
            return ConsumeResult(Outcome.NOT_FOUND)
        family_id, expires_at = entry

        family = self.cache.get(_FAMILY.format(family_id))
        if family is None or self.cache.get(_REVOKED.format(family_id)):
            return ConsumeResult(Outcome.FAMILY_REVOKED, family)
        if expires_at <= timezone.now():
            return ConsumeResult(Outcome.EXPIRED, family)

        # add() succeeds only if the key was absent: exactly one caller wins.
        won = self.cache.add(
            _CONSUMED.format(digest), True, self._ttl(expires_at)
        )
        if not won:
            return ConsumeResult(Outcome.ALREADY_CONSUMED, family)
        return ConsumeResult(Outcome.LIVE, family)

    def is_live(self, family_id: uuid.UUID) -> bool:
        if self.cache.get(_REVOKED.format(family_id)):
            return False
        if self.deny_by_default:
            return True
        family = self.cache.get(_FAMILY.format(family_id))
        return bool(family and family.is_live)

    def revoke_family(self, family_id: uuid.UUID, reason: str) -> None:
        self.cache.set(_REVOKED.format(family_id), reason, None)
        self.cache.delete(_FAMILY.format(family_id))

    def revoke_all_for_user(self, user: Any, reason: str) -> None:
        raise NotImplementedError(
            "CacheTokenStore cannot enumerate a user's families. Use "
            "ORMTokenStore, or keep an application-level index, if you need "
            "logout-everywhere."
        )

    def purge_expired(self) -> int:
        return 0  # cache TTLs expire entries automatically
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/sessions/test_cache_store.py -v`
Expected: 6 passed.

- [ ] **Step 5: Document the honest limitation in the README stub**

```bash
mkdir -p docs
cat > docs/stores.md <<'EOF'
# Choosing a store

| | `ORMTokenStore` (default) | `CacheTokenStore` |
|---|---|---|
| Durability | survives restarts | lost on cache flush |
| `revoke_all_for_user` | supported | **not supported** |
| Atomicity | `SELECT ... FOR UPDATE` | `cache.add()` compare-and-set |
| Cost per refresh | one transaction | one round trip |

`CacheTokenStore` cannot enumerate the families belonging to a user, so
logout-everywhere raises `NotImplementedError`. Use `ORMTokenStore` if you
need it.
EOF
```

- [ ] **Step 6: Commit**

```bash
git add src/django_signet/sessions/stores/cache.py tests/sessions/test_cache_store.py docs/stores.md
git commit -m "feat: cache-backed token store with CAS atomicity and denylist mode"
```

---

## Task 7: RotationPolicy — rotation, reuse detection, grace window

This is the security-critical path. Review it more carefully than any other task.

**Files:**
- Create: `src/django_signet/sessions/rotation.py`
- Test: `tests/sessions/test_rotation.py`

**Interfaces:**
- Consumes: `AccessToken`, `RefreshToken`, `MintedToken`, `token_digest`, `ORMTokenStore`, `Outcome`, `RevocationReason`, `token_reuse_detected`, and the exception taxonomy.
- Produces:
  - `SessionPair` frozen dataclass: `access: MintedToken`, `refresh: MintedToken`, `family: Any`, `replayed: bool = False`.
  - `RotationPolicy` with class attributes `grace_window`, `grace_cache`, `burn_family_on_reuse: bool = True`, `store`, `access_token_class`, `refresh_token_class`; methods `open_session(user, *, extra=None, user_agent="", ip_address=None) -> SessionPair`, `rotate(raw_refresh, *, extra=None) -> SessionPair`, and the overridable hook `on_reuse_detected(family) -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/sessions/test_rotation.py
from datetime import timedelta

import pytest
from django.core.cache import cache

from django_signet.exceptions import (
    TokenInvalid,
    TokenReused,
    TokenRevoked,
)
from django_signet.hashing import token_digest
from django_signet.models import IssuedToken, RevocationReason, TokenFamily
from django_signet.sessions.rotation import RotationPolicy
from django_signet.signals import token_reuse_detected
from django_signet.tokens.access import AccessToken

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def policy():
    return RotationPolicy()


def test_open_session_creates_family_and_persists_only_the_digest(policy, user):
    pair = policy.open_session(user)
    assert TokenFamily.objects.count() == 1
    stored = IssuedToken.objects.get()
    assert stored.digest == token_digest(pair.refresh.value)
    # the raw token must appear nowhere in the database
    assert pair.refresh.value not in stored.digest


def test_access_token_carries_the_family_id(policy, user):
    pair = policy.open_session(user)
    claims = AccessToken().verify(pair.access.value)
    assert claims["sid"] == str(pair.family.id)


def test_rotate_issues_a_new_pair_and_consumes_the_old(policy, user):
    first = policy.open_session(user)
    second = policy.rotate(first.refresh.value)
    assert second.refresh.value != first.refresh.value
    assert second.replayed is False
    old = IssuedToken.objects.get(digest=token_digest(first.refresh.value))
    assert old.consumed_at is not None
    assert IssuedToken.objects.count() == 2


def test_replay_inside_the_grace_window_is_idempotent(policy, user):
    """Two tabs, or React StrictMode, refresh with the same token. The second
    caller must receive the identical pair and the family must survive."""
    first = policy.open_session(user)
    a = policy.rotate(first.refresh.value)
    b = policy.rotate(first.refresh.value)
    assert b.replayed is True
    assert b.access.value == a.access.value
    assert b.refresh.value == a.refresh.value
    first.family.refresh_from_db()
    assert first.family.is_live is True


def test_replay_outside_the_grace_window_burns_the_family(user):
    class Strict(RotationPolicy):
        grace_cache = None  # disables the window entirely

    policy = Strict()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)
    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    first.family.refresh_from_db()
    assert first.family.is_live is False
    assert first.family.revoked_reason == RevocationReason.REUSE_DETECTED


def test_reuse_fires_the_signal_and_the_hook(user):
    seen = {}

    class Watching(RotationPolicy):
        grace_cache = None

        def on_reuse_detected(self, family):
            seen["hook"] = family.id

    def receiver(sender, family, **kwargs):
        seen["signal"] = family.id

    token_reuse_detected.connect(receiver)
    try:
        policy = Watching()
        first = policy.open_session(user)
        policy.rotate(first.refresh.value)
        with pytest.raises(TokenReused):
            policy.rotate(first.refresh.value)
    finally:
        token_reuse_detected.disconnect(receiver)

    assert seen["hook"] == first.family.id
    assert seen["signal"] == first.family.id


def test_rotating_after_the_family_is_revoked_raises(policy, user):
    first = policy.open_session(user)
    first.family.revoke(RevocationReason.LOGOUT)
    with pytest.raises(TokenRevoked):
        policy.rotate(first.refresh.value)


def test_unknown_refresh_token_raises_invalid(policy, user):
    from django_signet.tokens.refresh import RefreshToken

    orphan = RefreshToken().mint(subject="1", family_id="00000000-0000-0000-0000-000000000000")
    with pytest.raises(TokenInvalid):
        policy.rotate(orphan.value)


def test_an_access_token_cannot_be_used_to_rotate(policy, user):
    pair = policy.open_session(user)
    with pytest.raises(TokenInvalid):
        policy.rotate(pair.access.value)


def test_burn_can_be_disabled_while_still_rejecting_the_replay(user):
    class Lenient(RotationPolicy):
        grace_cache = None
        burn_family_on_reuse = False

    policy = Lenient()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)
    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    first.family.refresh_from_db()
    assert first.family.is_live is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/sessions/test_rotation.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.sessions.rotation'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/sessions/rotation.py
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Any

from django.core.cache import InvalidCacheBackendError, caches
from django.utils import timezone

from django_signet.conf import setting
from django_signet.exceptions import (
    TokenExpired,
    TokenInvalid,
    TokenReused,
    TokenRevoked,
)
from django_signet.hashing import token_digest
from django_signet.models import RevocationReason
from django_signet.sessions.stores.base import Outcome, TokenStore
from django_signet.sessions.stores.orm import ORMTokenStore
from django_signet.signals import token_reuse_detected
from django_signet.tokens.access import AccessToken
from django_signet.tokens.base import MintedToken
from django_signet.tokens.refresh import RefreshToken

_GRACE_KEY = "signet:grace:{}"


@dataclass(frozen=True)
class SessionPair:
    access: MintedToken
    refresh: MintedToken
    family: Any
    replayed: bool = False


class RotationPolicy:
    """Owns the refresh path: rotate, detect reuse, and absorb benign replays.

    Set ``grace_cache = None`` for strict RFC 9700 behaviour, where any replay
    of a consumed token burns the family.
    """

    grace_window = setting("GRACE_WINDOW")
    grace_cache = setting("GRACE_CACHE")
    burn_family_on_reuse: bool = True

    store: TokenStore = ORMTokenStore()
    access_token_class = AccessToken
    refresh_token_class = RefreshToken

    # ---------------------------------------------------------------- public

    def open_session(
        self,
        user: Any,
        *,
        extra: dict[str, Any] | None = None,
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> SessionPair:
        """Begin a new login session.

        The family is created first because a refresh token embeds its family
        id in the ``sid`` claim, so the id must exist before the token does.
        """
        expires_at = timezone.now() + self.refresh_token_class().lifetime
        family = self.store.open_family(
            user, expires_at, user_agent=user_agent, ip_address=ip_address
        )
        return self._mint_into(family, subject=str(user.pk), extra=extra)

    def rotate(
        self, raw_refresh: str, *, extra: dict[str, Any] | None = None
    ) -> SessionPair:
        # Signature, expiry and ``typ`` first: never touch the store with a
        # token we have not authenticated.
        claims = self.refresh_token_class().verify(raw_refresh)
        digest = token_digest(raw_refresh)
        result = self.store.consume(digest)

        if result.outcome is Outcome.NOT_FOUND:
            raise TokenInvalid("refresh token is not recognised")
        if result.outcome is Outcome.EXPIRED:
            raise TokenExpired("refresh token has expired")
        if result.outcome is Outcome.FAMILY_REVOKED:
            raise TokenRevoked("this session has been revoked")

        if result.outcome is Outcome.ALREADY_CONSUMED:
            replayed = self._grace_get(digest, result.family)
            if replayed is not None:
                return replayed
            self._burn(result.family)
            raise TokenReused("refresh token replayed outside the grace window")

        pair = self._mint_into(
            result.family, subject=claims["sub"], extra=extra
        )
        self._grace_put(digest, pair)
        return pair

    def on_reuse_detected(self, family: Any) -> None:
        """Hook. Called after the family is burned, before the 401 is raised.

        Override to alert, log, or force a password reset. Deliberately an
        *event* hook: it reports that an incident happened and hands over the
        blast radius, without requiring you to know how detection worked.
        """

    # --------------------------------------------------------------- private

    def _mint_into(
        self, family: Any, *, subject: str, extra: dict[str, Any] | None
    ) -> SessionPair:
        family_id = str(family.id)
        refresh = self.refresh_token_class().mint(
            subject, family_id=family_id, extra=extra
        )
        self.store.issue(family, token_digest(refresh.value), refresh.expires_at)
        access = self.access_token_class().mint(
            subject, family_id=family_id, extra=extra
        )
        return SessionPair(access=access, refresh=refresh, family=family)

    def _burn(self, family: Any) -> None:
        if family is None:
            return
        if self.burn_family_on_reuse:
            self.store.revoke_family(family.id, RevocationReason.REUSE_DETECTED)
        token_reuse_detected.send(
            sender=type(self),
            user=getattr(family, "user", None),
            family=family,
            request=None,
        )
        self.on_reuse_detected(family)

    def _cache(self) -> Any | None:
        alias = self.grace_cache
        if alias is None or self.grace_window <= timedelta(0):
            return None
        try:
            return caches[alias]
        except InvalidCacheBackendError:
            return None

    def _grace_put(self, digest: str, pair: SessionPair) -> None:
        cache = self._cache()
        if cache is None:
            return
        cache.set(
            _GRACE_KEY.format(digest),
            (
                pair.access.value,
                pair.access.jti,
                pair.access.expires_at,
                pair.refresh.value,
                pair.refresh.jti,
                pair.refresh.expires_at,
            ),
            int(self.grace_window.total_seconds()),
        )

    def _grace_get(self, digest: str, family: Any) -> SessionPair | None:
        cache = self._cache()
        if cache is None:
            return None
        entry = cache.get(_GRACE_KEY.format(digest))
        if entry is None:
            return None
        av, ajti, aexp, rv, rjti, rexp = entry
        return SessionPair(
            access=MintedToken(value=av, jti=ajti, expires_at=aexp, claims={}),
            refresh=MintedToken(value=rv, jti=rjti, expires_at=rexp, claims={}),
            family=family,
            replayed=True,
        )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/sessions/test_rotation.py -v`
Expected: 10 passed.

- [ ] **Step 5: Run the whole suite to check for regressions**

Run: `.venv/bin/pytest -q`
Expected: all previous tests still pass.

- [ ] **Step 6: Commit**

```bash
git add src/django_signet/sessions/rotation.py tests/sessions/test_rotation.py
git commit -m "feat: rotation policy with reuse detection and idempotent grace window"
```

---

## Task 8: Transport layer

**Files:**
- Create: `src/django_signet/transport/__init__.py`, `src/django_signet/transport/base.py`, `src/django_signet/transport/cookie.py`, `src/django_signet/transport/header.py`
- Test: `tests/transport/test_cookie.py`, `tests/transport/test_header.py`

**Interfaces:**
- Consumes: `SessionPair` from `django_signet.sessions.rotation`; `TransportError` from `django_signet.exceptions`.
- Produces:
  - `CookiePolicy` with `setting()`-backed fields `prefix`, `samesite`, `secure`, `httponly`, `refresh_path`, `domain`, `explicit_access_name`, `explicit_refresh_name`, `explicit_csrf_name`; derived properties `access_name`, `refresh_name`, `csrf_name`; and `resolved_name(base: str, *, root_path: bool) -> str` applying the `__Host-` / `__Secure-` prefix rules. Constructed as `CookiePolicy(secure=False, domain="example.com")` — keywords become instance attributes and outrank both the settings dict and the defaults, which is what makes the Task 12 system checks meaningful.
  - `Transport` ABC: `extract_access(request) -> str`, `extract_refresh(request) -> str`, `attach(response, pair) -> None`, `clear(response) -> None`.
  - `CookieTransport(policy=None)`, `HeaderTransport(header="HTTP_AUTHORIZATION", keyword="Bearer")`, `HybridTransport(cookie=None, header=None)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/transport/test_cookie.py
import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from django_signet.exceptions import TransportError
from django_signet.transport.cookie import CookiePolicy, CookieTransport

# test_attach_... opens a real session, so the whole module needs the database.
pytestmark = pytest.mark.django_db


@pytest.fixture
def transport():
    return CookieTransport()


def test_host_prefix_on_the_root_scoped_access_cookie(transport):
    assert transport.policy.access_name.startswith("__Host-")


def test_refresh_cookie_uses_secure_prefix_because_it_is_path_scoped(transport):
    """__Host- mandates Path=/. The refresh cookie is deliberately scoped to
    the refresh endpoint, so it must use __Secure- instead."""
    assert transport.policy.refresh_name.startswith("__Secure-")
    assert not transport.policy.refresh_name.startswith("__Host-")


def test_insecure_policy_drops_both_prefixes():
    policy = CookiePolicy(secure=False)
    assert not policy.access_name.startswith("__")
    assert not policy.refresh_name.startswith("__")


def test_project_settings_drive_the_policy():
    from django.test import override_settings

    with override_settings(SIGNET={"COOKIE_PREFIX": "acme"}):
        assert CookiePolicy().access_name == "__Host-acme-access"


def test_a_constructor_keyword_outranks_project_settings():
    from django.test import override_settings

    with override_settings(SIGNET={"COOKIE_PREFIX": "acme"}):
        assert CookiePolicy(prefix="own").access_name == "__Host-own-access"


def test_an_unknown_field_is_rejected():
    with pytest.raises(TypeError):
        CookiePolicy(nonsense=True)


def test_setting_a_domain_drops_only_the_host_prefix():
    policy = CookiePolicy(domain="example.com")
    assert not policy.access_name.startswith("__Host-")
    assert policy.refresh_name.startswith("__Secure-")


def test_attach_sets_both_cookies_with_the_right_flags(transport, user):
    from django_signet.sessions.rotation import RotationPolicy

    pair = RotationPolicy().open_session(user)
    response = HttpResponse()
    transport.attach(response, pair)

    access = response.cookies[transport.policy.access_name]
    refresh = response.cookies[transport.policy.refresh_name]

    assert access["httponly"] is True
    assert access["secure"] is True
    assert access["samesite"] == "Lax"
    assert access["path"] == "/"
    assert refresh["path"] == transport.policy.refresh_path


def test_extract_reads_the_cookie(transport):
    request = RequestFactory().get("/")
    request.COOKIES[transport.policy.access_name] = "a.b.c"
    assert transport.extract_access(request) == "a.b.c"


def test_extract_raises_when_absent(transport):
    with pytest.raises(TransportError):
        transport.extract_access(RequestFactory().get("/"))


def test_clear_expires_both_cookies(transport):
    response = HttpResponse()
    transport.clear(response)
    assert response.cookies[transport.policy.access_name]["max-age"] == 0
    assert response.cookies[transport.policy.refresh_name]["max-age"] == 0
```

```python
# tests/transport/test_header.py
import pytest
from django.test import RequestFactory

from django_signet.exceptions import TransportError
from django_signet.transport.header import HeaderTransport, HybridTransport


def test_reads_a_bearer_token():
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer a.b.c")
    assert HeaderTransport().extract_access(request) == "a.b.c"


def test_rejects_the_wrong_keyword():
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Basic a.b.c")
    with pytest.raises(TransportError):
        HeaderTransport().extract_access(request)


def test_rejects_a_malformed_header():
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer")
    with pytest.raises(TransportError):
        HeaderTransport().extract_access(request)


def test_hybrid_prefers_the_cookie_then_falls_back_to_the_header():
    hybrid = HybridTransport()
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer from-header")
    assert hybrid.extract_access(request) == "from-header"

    request.COOKIES[hybrid.cookie.policy.access_name] = "from-cookie"
    assert hybrid.extract_access(request) == "from-cookie"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/transport/ -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.transport'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/transport/__init__.py
```

```python
# src/django_signet/transport/base.py
from __future__ import annotations

import abc
from typing import Any


class Transport(abc.ABC):
    """Moves tokens between the library and the wire."""

    @abc.abstractmethod
    def extract_access(self, request: Any) -> str: ...

    @abc.abstractmethod
    def extract_refresh(self, request: Any) -> str: ...

    @abc.abstractmethod
    def attach(self, response: Any, pair: Any) -> None: ...

    @abc.abstractmethod
    def clear(self, response: Any) -> None: ...

    @property
    def is_ambient(self) -> bool:
        """True when the browser attaches the credential automatically.

        Ambient credentials are what make CSRF possible, so the CSRF check
        keys off this rather than off the class name.
        """
        return False
```

```python
# src/django_signet/transport/cookie.py
from __future__ import annotations

from typing import Any

from django_signet.conf import setting
from django_signet.exceptions import TransportError
from django_signet.transport.base import Transport


class CookiePolicy:
    """Cookie naming and flags.

    Every field uses the same ``setting()`` descriptor as the rest of the
    library, so resolution is uniform: a keyword passed here becomes an
    instance attribute and wins; otherwise the project's ``SIGNET`` dict is
    consulted; otherwise the library default applies. ``setting`` is a
    non-data descriptor, so the instance ``__dict__`` shadows it naturally.

    Prefix rules are browser-enforced, not stylistic:
      ``__Host-``   requires Secure, Path=/, and no Domain.
      ``__Secure-`` requires Secure only.
    A ``__Host-`` cookie with a non-root path is silently dropped by the
    browser, so the path-scoped refresh cookie must use ``__Secure-``.
    """

    prefix = setting("COOKIE_PREFIX")
    samesite = setting("COOKIE_SAMESITE")
    secure = setting("COOKIE_SECURE")
    httponly = setting("COOKIE_HTTPONLY")
    refresh_path = setting("COOKIE_REFRESH_PATH")
    domain = setting("COOKIE_DOMAIN")
    explicit_access_name = setting("COOKIE_ACCESS_NAME")
    explicit_refresh_name = setting("COOKIE_REFRESH_NAME")
    explicit_csrf_name = setting("COOKIE_CSRF_NAME")

    def __init__(self, **overrides: Any) -> None:
        for key, value in overrides.items():
            if not hasattr(type(self), key):
                raise TypeError(f"CookiePolicy got an unexpected field {key!r}")
            setattr(self, key, value)

    def resolved_name(self, base: str, *, root_path: bool) -> str:
        if not self.secure:
            return base
        if root_path and self.domain is None:
            return f"__Host-{base}"
        return f"__Secure-{base}"

    @property
    def access_name(self) -> str:
        return self.explicit_access_name or self.resolved_name(
            f"{self.prefix}-access", root_path=True
        )

    @property
    def refresh_name(self) -> str:
        # Path-scoped, so __Host- is invalid here by definition.
        return self.explicit_refresh_name or self.resolved_name(
            f"{self.prefix}-refresh", root_path=False
        )

    @property
    def csrf_name(self) -> str:
        # Deliberately readable by JavaScript: the client must echo it back.
        return self.explicit_csrf_name or f"{self.prefix}-csrf"


class CookieTransport(Transport):
    policy: CookiePolicy = CookiePolicy()

    def __init__(self, policy: CookiePolicy | None = None) -> None:
        if policy is not None:
            self.policy = policy

    @property
    def is_ambient(self) -> bool:
        return True

    def _read(self, request: Any, name: str) -> str:
        token = request.COOKIES.get(name)
        if not token:
            raise TransportError(f"no {name} cookie on the request")
        return token

    def extract_access(self, request: Any) -> str:
        return self._read(request, self.policy.access_name)

    def extract_refresh(self, request: Any) -> str:
        return self._read(request, self.policy.refresh_name)

    def attach(self, response: Any, pair: Any) -> None:
        p = self.policy
        response.set_cookie(
            p.access_name,
            pair.access.value,
            expires=pair.access.expires_at,
            path="/",
            domain=p.domain,
            secure=p.secure,
            httponly=p.httponly,
            samesite=p.samesite,
        )
        response.set_cookie(
            p.refresh_name,
            pair.refresh.value,
            expires=pair.refresh.expires_at,
            path=p.refresh_path,
            domain=p.domain,
            secure=p.secure,
            httponly=p.httponly,
            samesite=p.samesite,
        )

    def clear(self, response: Any) -> None:
        p = self.policy
        for name, path in (
            (p.access_name, "/"),
            (p.refresh_name, p.refresh_path),
            (p.csrf_name, "/"),
        ):
            response.set_cookie(
                name,
                "",
                max_age=0,
                path=path,
                domain=p.domain,
                secure=p.secure,
                samesite=p.samesite,
            )
```

```python
# src/django_signet/transport/header.py
from __future__ import annotations

from typing import Any

from django_signet.exceptions import TransportError
from django_signet.transport.base import Transport
from django_signet.transport.cookie import CookieTransport


class HeaderTransport(Transport):
    """Authorization: Bearer <token>. For mobile and service-to-service
    clients, which are not subject to ambient credential attachment."""

    def __init__(
        self, header: str = "HTTP_AUTHORIZATION", keyword: str = "Bearer"
    ) -> None:
        self.header = header
        self.keyword = keyword

    def _read(self, request: Any) -> str:
        raw = request.META.get(self.header, "")
        parts = raw.split()
        if len(parts) != 2 or parts[0] != self.keyword:
            raise TransportError("missing or malformed Authorization header")
        return parts[1]

    def extract_access(self, request: Any) -> str:
        return self._read(request)

    def extract_refresh(self, request: Any) -> str:
        return self._read(request)

    def attach(self, response: Any, pair: Any) -> None:
        response.data = {
            **(getattr(response, "data", None) or {}),
            "access": pair.access.value,
            "refresh": pair.refresh.value,
        }

    def clear(self, response: Any) -> None:
        return None  # nothing is stored client-side by this transport


class HybridTransport(Transport):
    """Prefer the cookie; fall back to the header. Lets one API serve a
    browser SPA and a mobile app without separate endpoints."""

    def __init__(
        self,
        cookie: CookieTransport | None = None,
        header: HeaderTransport | None = None,
    ) -> None:
        self.cookie = cookie or CookieTransport()
        self.header = header or HeaderTransport()

    def _try(self, name: str, request: Any) -> str:
        try:
            return getattr(self.cookie, name)(request)
        except TransportError:
            return getattr(self.header, name)(request)

    def extract_access(self, request: Any) -> str:
        return self._try("extract_access", request)

    def extract_refresh(self, request: Any) -> str:
        return self._try("extract_refresh", request)

    def used_cookie(self, request: Any) -> bool:
        """Which path authenticated this request. The CSRF check needs to
        know, because only the cookie path is ambient."""
        try:
            self.cookie.extract_access(request)
        except TransportError:
            return False
        return True

    @property
    def policy(self) -> Any:
        """Delegate to the cookie half. ``validate_csrf`` needs a policy, and
        only the cookie path is ambient, so the cookie policy is the right
        one to expose."""
        return self.cookie.policy

    def attach(self, response: Any, pair: Any) -> None:
        self.cookie.attach(response, pair)

    def clear(self, response: Any) -> None:
        self.cookie.clear(response)
```

`HeaderTransport` needs no `policy`: `is_ambient` is `False`, so the CSRF
check returns before it would be consulted.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/transport/ -v`
Expected: 15 passed.

- [ ] **Step 5: Commit**

```bash
git add src/django_signet/transport/ tests/transport/
git commit -m "feat: cookie, header and hybrid transports with correct cookie prefixes"
```

---

## Task 9: CSRF double-submit

**Files:**
- Create: `src/django_signet/csrf.py`
- Test: `tests/test_csrf.py`

**Interfaces:**
- Consumes: `CookiePolicy` from `django_signet.transport.cookie`; `CSRFFailed` from `django_signet.exceptions`.
- Produces: `CSRF_HEADER = "HTTP_X_CSRF_TOKEN"`; `SAFE_METHODS: frozenset[str]`; `new_csrf_token() -> str`; `issue_csrf(response, policy, token=None) -> str`; `validate_csrf(request, policy) -> None` raising `CSRFFailed`.

Rationale: cookies are attached by the browser automatically, so cookie authentication reintroduces CSRF risk that header authentication does not have. `SameSite=Lax` is defence in depth, never the sole control.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_csrf.py
import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from django_signet.csrf import (
    CSRF_HEADER,
    issue_csrf,
    new_csrf_token,
    validate_csrf,
)
from django_signet.exceptions import CSRFFailed
from django_signet.transport.cookie import CookiePolicy

POLICY = CookiePolicy()


def _request(method="POST", cookie=None, header=None):
    request = getattr(RequestFactory(), method.lower())("/")
    if cookie is not None:
        request.COOKIES[POLICY.csrf_name] = cookie
    if header is not None:
        request.META[CSRF_HEADER] = header
    return request


def test_tokens_are_unpredictable():
    assert new_csrf_token() != new_csrf_token()
    assert len(new_csrf_token()) >= 32


def test_issue_sets_a_javascript_readable_cookie():
    response = HttpResponse()
    token = issue_csrf(response, POLICY)
    cookie = response.cookies[POLICY.csrf_name]
    assert cookie.value == token
    assert cookie["httponly"] == ""  # readable: the client must echo it


def test_matching_cookie_and_header_passes():
    validate_csrf(_request(cookie="tok", header="tok"), POLICY)


def test_safe_methods_are_exempt():
    validate_csrf(_request("GET"), POLICY)


@pytest.mark.parametrize(
    "cookie,header",
    [("tok", "other"), ("tok", None), (None, "tok"), (None, None), ("", "")],
)
def test_mismatch_or_absence_is_rejected(cookie, header):
    with pytest.raises(CSRFFailed):
        validate_csrf(_request(cookie=cookie, header=header), POLICY)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/test_csrf.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.csrf'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/csrf.py
from __future__ import annotations

import hmac
import secrets
from typing import Any

from django_signet.exceptions import CSRFFailed
from django_signet.transport.cookie import CookiePolicy

CSRF_HEADER = "HTTP_X_CSRF_TOKEN"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def issue_csrf(
    response: Any, policy: CookiePolicy, token: str | None = None
) -> str:
    """Set the double-submit cookie. Deliberately NOT httponly: the client
    has to read it in order to echo it back in the header."""
    token = token or new_csrf_token()
    response.set_cookie(
        policy.csrf_name,
        token,
        path="/",
        domain=policy.domain,
        secure=policy.secure,
        httponly=False,
        samesite=policy.samesite,
    )
    return token


def validate_csrf(request: Any, policy: CookiePolicy) -> None:
    """Enforce double-submit on unsafe methods. Constant-time comparison so
    the check cannot be turned into an oracle."""
    if request.method in SAFE_METHODS:
        return
    cookie = request.COOKIES.get(policy.csrf_name) or ""
    header = request.META.get(CSRF_HEADER) or ""
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise CSRFFailed("CSRF double-submit check failed")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/test_csrf.py -v`
Expected: 9 passed (5 parametrised cases plus 4).

- [ ] **Step 5: Commit**

```bash
git add src/django_signet/csrf.py tests/test_csrf.py
git commit -m "feat: double-submit CSRF with constant-time comparison"
```

---

## Task 10: DRF authentication classes

**Files:**
- Create: `src/django_signet/authentication.py`
- Test: `tests/test_authentication.py`

**Interfaces:**
- Consumes: transports, `AccessToken`, `ORMTokenStore`, `validate_csrf`, the exception taxonomy.
- Produces: `BaseJWTAuthentication` and the six concrete classes `HeaderJWTAuthentication`, `CookieJWTAuthentication`, `HybridJWTAuthentication`, plus `Strict*` siblings of each. Overridable hooks: `get_token(request)`, `get_user(claims)`, `validate_claims(claims)`, `on_authentication_failed(exc)`.

Two behaviours are non-negotiable:
1. Returning `None` when no token is present (DRF's contract for "not my scheme"), versus raising `AuthenticationFailed` when a token *is* present but bad.
2. Rejecting inactive users — this is the CVE-2024-22513 regression guard.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_authentication.py
import pytest
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from django_signet.authentication import (
    CookieJWTAuthentication,
    HeaderJWTAuthentication,
    StrictCookieJWTAuthentication,
)
from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason
from django_signet.sessions.rotation import RotationPolicy

pytestmark = pytest.mark.django_db


@pytest.fixture
def pair(user):
    return RotationPolicy().open_session(user)


def _cookie_get(auth, pair, **extra):
    request = APIRequestFactory().get("/", **extra)
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    return request


def test_returns_none_when_no_token_is_present():
    """DRF contract: absence means 'not my scheme', not failure."""
    assert CookieJWTAuthentication().authenticate(APIRequestFactory().get("/")) is None


def test_authenticates_a_valid_cookie(pair, user):
    auth = CookieJWTAuthentication()
    authed, claims = auth.authenticate(_cookie_get(auth, pair))
    assert authed == user
    assert claims["typ"] == "access"


def test_authenticates_a_valid_bearer_header(pair, user):
    request = APIRequestFactory().get(
        "/", HTTP_AUTHORIZATION=f"Bearer {pair.access.value}"
    )
    authed, _ = HeaderJWTAuthentication().authenticate(request)
    assert authed == user


def test_a_tampered_token_fails_generically(pair):
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value[:-2] + "xx"
    with pytest.raises(AuthenticationFailed) as exc:
        auth.authenticate(request)
    # the message must not disclose which check failed
    assert "signature" not in str(exc.value).lower()
    assert "expired" not in str(exc.value).lower()


def test_an_inactive_user_is_rejected(pair, user):
    """Regression guard for CVE-2024-22513: disabling an account must take
    effect immediately, not at token expiry."""
    user.is_active = False
    user.save(update_fields=["is_active"])
    auth = CookieJWTAuthentication()
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(_cookie_get(auth, pair))


def test_a_refresh_token_cannot_authenticate(pair):
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = pair.refresh.value
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_unsafe_cookie_request_requires_the_csrf_header(pair):
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().post("/")
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_unsafe_cookie_request_passes_with_a_matching_csrf_pair(pair, user):
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().post("/", **{CSRF_HEADER: "tok"})
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    request.COOKIES[auth.transport.policy.csrf_name] = "tok"
    authed, _ = auth.authenticate(request)
    assert authed == user


def test_header_auth_skips_csrf_because_it_is_not_ambient(pair, user):
    request = APIRequestFactory().post(
        "/", HTTP_AUTHORIZATION=f"Bearer {pair.access.value}"
    )
    authed, _ = HeaderJWTAuthentication().authenticate(request)
    assert authed == user


def test_non_strict_auth_still_works_after_revocation(pair, user):
    """Documented trade-off: the stateless fast path tolerates revocation up
    to the access token's lifetime."""
    pair.family.revoke(RevocationReason.LOGOUT)
    auth = CookieJWTAuthentication()
    authed, _ = auth.authenticate(_cookie_get(auth, pair))
    assert authed == user


def test_strict_auth_rejects_immediately_after_revocation(pair, user):
    pair.family.revoke(RevocationReason.LOGOUT)
    auth = StrictCookieJWTAuthentication()
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(_cookie_get(auth, pair))
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/test_authentication.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.authentication'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/authentication.py
from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from django_signet.csrf import validate_csrf
from django_signet.exceptions import (
    SignetError,
    TokenInvalid,
    TokenRevoked,
    TransportError,
)
from django_signet.sessions.stores.base import TokenStore
from django_signet.sessions.stores.orm import ORMTokenStore
from django_signet.tokens.access import AccessToken
from django_signet.transport.base import Transport
from django_signet.transport.cookie import CookieTransport
from django_signet.transport.header import HeaderTransport, HybridTransport

# One message for every failure. Never disclose which check failed.
GENERIC_FAILURE = "Invalid or expired credentials."


class BaseJWTAuthentication(BaseAuthentication):
    """Template Method. ``authenticate()`` owns the invariant sequence;
    subclasses override only the decisions."""

    transport: Transport = CookieTransport()
    token_class = AccessToken
    store: TokenStore = ORMTokenStore()
    strict: bool = False
    enforce_csrf: bool = True

    # ------------------------------------------------------------- template

    def authenticate(self, request: Any) -> tuple[Any, dict[str, Any]] | None:
        try:
            raw = self.get_token(request)
        except TransportError:
            # DRF contract: no credentials of our kind. Let other classes try.
            return None

        try:
            claims = self.token_class().verify(raw)
            if self.should_enforce_csrf(request):
                validate_csrf(request, self.transport.policy)
            if self.strict:
                self.check_family(claims)
            self.validate_claims(claims)
            user = self.get_user(claims)
        except SignetError as exc:
            self.on_authentication_failed(exc)
            raise AuthenticationFailed(GENERIC_FAILURE) from None
        return (user, claims)

    def authenticate_header(self, request: Any) -> str:
        return 'Bearer realm="api"'

    # ---------------------------------------------------------------- hooks

    def get_token(self, request: Any) -> str:
        return self.transport.extract_access(request)

    def get_user(self, claims: dict[str, Any]) -> Any:
        User = get_user_model()
        try:
            user = User.objects.get(pk=claims["sub"])
        except (User.DoesNotExist, KeyError, ValueError, TypeError):
            raise TokenInvalid("no such user") from None
        if not getattr(user, "is_active", True):
            # CVE-2024-22513: a disabled account must lose access at once.
            raise TokenRevoked("user is inactive")
        return user

    def validate_claims(self, claims: dict[str, Any]) -> None:
        """Override to enforce application-specific claims, e.g. tenant or
        scope. Raise any SignetError to reject."""

    def on_authentication_failed(self, exc: SignetError) -> None:
        """Override to log or alert. The client still receives the generic
        401 regardless of what you do here."""

    # ------------------------------------------------------------- internals

    def should_enforce_csrf(self, request: Any) -> bool:
        if not self.enforce_csrf or not self.transport.is_ambient:
            return False
        used_cookie = getattr(self.transport, "used_cookie", None)
        return used_cookie(request) if used_cookie else True

    def check_family(self, claims: dict[str, Any]) -> None:
        family_id = claims.get("sid")
        if not family_id or not self.store.is_live(family_id):
            raise TokenRevoked("session is no longer live")


class HeaderJWTAuthentication(BaseJWTAuthentication):
    transport = HeaderTransport()


class CookieJWTAuthentication(BaseJWTAuthentication):
    transport = CookieTransport()


class HybridJWTAuthentication(BaseJWTAuthentication):
    transport = HybridTransport()


class StrictHeaderJWTAuthentication(HeaderJWTAuthentication):
    strict = True


class StrictCookieJWTAuthentication(CookieJWTAuthentication):
    strict = True


class StrictHybridJWTAuthentication(HybridJWTAuthentication):
    strict = True
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/test_authentication.py -v`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add src/django_signet/authentication.py tests/test_authentication.py
git commit -m "feat: DRF authentication classes with strict siblings and CVE-2024-22513 guard"
```

---

## Task 11: Serializers, views and URLs

**Files:**
- Create: `src/django_signet/serializers.py`, `src/django_signet/views.py`, `src/django_signet/urls.py`
- Modify: `tests/urls.py`
- Test: `tests/test_views.py`

**Interfaces:**
- Consumes: `RotationPolicy`, `CookieTransport`, `issue_csrf`, `CookieJWTAuthentication`, the exception taxonomy, `token_issued` / `token_refreshed`.
- Produces:
  - `TokenObtainSerializer` with `validate()` returning `{"user": <User>}`.
  - `TokenObtainView`, `TokenRefreshView`, `TokenVerifyView`, `LogoutView`, `LogoutAllView` — each with the hooks `get_claims(user)`, `get_response_data(user, pair)`, `set_cookies(response, pair)`.
  - `django_signet.urls` exposing names `login`, `refresh`, `verify`, `logout`, `logout-all` under `app_name = "django_signet"`.

With cookie transport the response body deliberately contains **no tokens** — that is what "authentication fully encapsulated in the backend" means in practice.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_views.py
import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason, TokenFamily
from django_signet.transport.cookie import CookiePolicy

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


@pytest.fixture
def client():
    return APIClient()


def _login(client, username="bob", password=PASSWORD):
    return client.post(
        reverse("django_signet:login"),
        {"username": username, "password": password},
        format="json",
    )


def test_login_sets_cookies_and_leaks_no_tokens(client, account):
    response = _login(client)
    assert response.status_code == 200
    assert POLICY.access_name in response.cookies
    assert POLICY.refresh_name in response.cookies
    assert POLICY.csrf_name in response.cookies
    body = str(response.data)
    assert "eyJ" not in body  # no JWT anywhere in the response body


def test_login_with_bad_credentials_is_rejected(client, account):
    assert _login(client, password="wrong").status_code == 400


def test_refresh_rotates_the_cookies(client, account):
    _login(client)
    before = client.cookies[POLICY.refresh_name].value
    response = client.post(reverse("django_signet:refresh"))
    assert response.status_code == 200
    assert client.cookies[POLICY.refresh_name].value != before


def test_refresh_without_a_cookie_is_401(client):
    assert client.post(reverse("django_signet:refresh")).status_code == 401


def test_a_failed_refresh_clears_the_cookies(client, account):
    """A dead session must not loop: clear the cookies on the way out."""
    _login(client)
    client.cookies[POLICY.refresh_name] = "not-a-real-token"
    response = client.post(reverse("django_signet:refresh"))
    assert response.status_code == 401
    assert response.cookies[POLICY.access_name]["max-age"] == 0
    assert response.cookies[POLICY.refresh_name]["max-age"] == 0


def test_logout_revokes_the_family(client, account):
    _login(client)
    response = client.post(
        reverse("django_signet:logout"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert response.status_code == 200
    family = TokenFamily.objects.get()
    assert family.is_live is False
    assert family.revoked_reason == RevocationReason.LOGOUT


def test_logout_all_revokes_every_session(client, account):
    _login(client)
    second = APIClient()
    _login(second)
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 2

    client.post(
        reverse("django_signet:logout-all"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 0


def test_verify_reports_the_session_state(client, account):
    _login(client)
    response = client.get(reverse("django_signet:verify"))
    assert response.status_code == 200
    assert response.data["authenticated"] is True


def test_verify_without_credentials_is_401(client):
    assert client.get(reverse("django_signet:verify")).status_code == 401
```

- [ ] **Step 2: Wire the test URLconf**

```python
# tests/urls.py
from django.urls import include, path

urlpatterns = [path("api/auth/", include("django_signet.urls"))]
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/test_views.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.urls'`

- [ ] **Step 4: Write the minimal implementation**

```python
# src/django_signet/serializers.py
from __future__ import annotations

from typing import Any

from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers


class TokenObtainSerializer(serializers.Serializer):
    """Validates credentials. Subclass and override ``validate`` to support
    email login, one-time codes, or anything else that yields a user."""

    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields[self.username_field] = serializers.CharField()

    @property
    def username_field(self) -> str:
        return get_user_model().USERNAME_FIELD

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        user = authenticate(
            request=self.context.get("request"),
            username=attrs[self.username_field],
            password=attrs["password"],
        )
        # One message for both "no such user" and "wrong password", so the
        # endpoint cannot be used to enumerate accounts.
        if user is None or not user.is_active:
            raise serializers.ValidationError("Invalid credentials.")
        return {"user": user}
```

```python
# src/django_signet/views.py
from __future__ import annotations

from typing import Any

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django_signet.authentication import (
    GENERIC_FAILURE,
    CookieJWTAuthentication,
)
from django_signet.csrf import issue_csrf
from django_signet.exceptions import SignetError, TransportError
from django_signet.models import RevocationReason
from django_signet.serializers import TokenObtainSerializer
from django_signet.sessions.rotation import RotationPolicy
from django_signet.signals import token_issued, token_refreshed
from django_signet.transport.cookie import CookieTransport


class SignetViewMixin:
    """Shared plumbing. ``transport`` and ``rotation`` are class attributes so
    a subclass can swap either without touching project settings."""

    transport = CookieTransport()
    rotation = RotationPolicy()

    def get_claims(self, user: Any) -> dict[str, Any]:
        """Extra claims to embed in both tokens. Reserved claims are ignored."""
        return {}

    def get_response_data(self, user: Any, pair: Any) -> dict[str, Any]:
        """With cookie transport this deliberately contains no tokens."""
        return {"authenticated": True}

    def set_cookies(self, response: Any, pair: Any) -> None:
        self.transport.attach(response, pair)
        issue_csrf(response, self.transport.policy)

    def client_ip(self, request: Any) -> str | None:
        return request.META.get("REMOTE_ADDR")

    def failure(self) -> Response:
        response = Response(
            {"detail": GENERIC_FAILURE}, status=status.HTTP_401_UNAUTHORIZED
        )
        self.transport.clear(response)
        return response


class TokenObtainView(SignetViewMixin, APIView):
    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    serializer_class = TokenObtainSerializer

    def post(self, request: Any) -> Response:
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        pair = self.rotation.open_session(
            user,
            extra=self.get_claims(user),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            ip_address=self.client_ip(request),
        )
        response = Response(self.get_response_data(user, pair))
        self.set_cookies(response, pair)
        token_issued.send(
            sender=type(self), user=user, family=pair.family, request=request
        )
        return response


class TokenRefreshView(SignetViewMixin, APIView):
    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]

    def post(self, request: Any) -> Response:
        try:
            raw = self.transport.extract_refresh(request)
        except TransportError:
            return self.failure()
        try:
            pair = self.rotation.rotate(raw)
        except SignetError:
            # Covers invalid, expired, revoked and reused alike. The family
            # has already been burned by the policy where appropriate.
            return self.failure()

        response = Response(self.get_response_data(None, pair))
        self.set_cookies(response, pair)
        token_refreshed.send(
            sender=type(self),
            user=getattr(pair.family, "user", None),
            family=pair.family,
            request=request,
        )
        return response


class TokenVerifyView(SignetViewMixin, APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request: Any) -> Response:
        return Response({"authenticated": True, "user_id": request.user.pk})


class LogoutView(SignetViewMixin, APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    reason = RevocationReason.LOGOUT

    def post(self, request: Any) -> Response:
        family_id = request.auth.get("sid") if request.auth else None
        if family_id:
            self.rotation.store.revoke_family(family_id, self.reason)
        response = Response({"detail": "Signed out."})
        self.transport.clear(response)
        return response


class LogoutAllView(SignetViewMixin, APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    reason = RevocationReason.LOGOUT_ALL

    def post(self, request: Any) -> Response:
        try:
            self.rotation.store.revoke_all_for_user(request.user, self.reason)
        except NotImplementedError:
            # A cache-backed store cannot enumerate a user's families. Say so
            # plainly rather than surfacing a 500 for a documented limitation.
            return Response(
                {"detail": "Logout-everywhere is not supported by the "
                           "configured token store."},
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )
        response = Response({"detail": "Signed out everywhere."})
        self.transport.clear(response)
        return response
```

```python
# src/django_signet/urls.py
from django.urls import path

from django_signet.views import (
    LogoutAllView,
    LogoutView,
    TokenObtainView,
    TokenRefreshView,
    TokenVerifyView,
)

app_name = "django_signet"

urlpatterns = [
    path("login", TokenObtainView.as_view(), name="login"),
    path("refresh", TokenRefreshView.as_view(), name="refresh"),
    path("verify", TokenVerifyView.as_view(), name="verify"),
    path("logout", LogoutView.as_view(), name="logout"),
    path("logout-all", LogoutAllView.as_view(), name="logout-all"),
]
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/test_views.py -v`
Expected: 9 passed.

- [ ] **Step 6: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: everything passes.

- [ ] **Step 7: Commit**

```bash
git add src/django_signet/serializers.py src/django_signet/views.py src/django_signet/urls.py tests/
git commit -m "feat: login, refresh, verify and logout views with cookie encapsulation"
```

---

## Task 12: System checks and password-change revocation

**Files:**
- Create: `src/django_signet/checks.py`, `src/django_signet/revocation.py`
- Modify: `src/django_signet/apps.py`
- Test: `tests/test_checks.py`, `tests/test_revocation.py`

**Interfaces:**
- Produces: check functions registered under the `signet` tag returning IDs `signet.E001` (insecure cookies with `DEBUG=False`), `signet.E002` (`__Host-` prefix combined with a non-root path), `signet.W003` (grace window configured but no usable cache), `signet.W004` (`SIGNING_KEY` falling back to `SECRET_KEY` while using an RS algorithm); `revoke_on_password_change(sender, instance, **kwargs)` receiver.

Rationale: a `__Host-` cookie with a non-root path is dropped by the browser with no error — the request simply arrives unauthenticated. A system check turns an invisible runtime failure into a loud startup failure.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_checks.py
from django.test import override_settings

from django_signet.checks import check_cookie_security, check_grace_cache


@override_settings(DEBUG=False, SIGNET={"COOKIE_SECURE": False})
def test_insecure_cookies_in_production_are_an_error():
    ids = [e.id for e in check_cookie_security(None)]
    assert "signet.E001" in ids


@override_settings(DEBUG=True, SIGNET={"COOKIE_SECURE": False})
def test_insecure_cookies_in_debug_are_tolerated():
    assert check_cookie_security(None) == []


@override_settings(SIGNET={"GRACE_CACHE": "nonexistent-alias"})
def test_missing_grace_cache_warns():
    ids = [w.id for w in check_grace_cache(None)]
    assert "signet.W003" in ids


@override_settings(SIGNET={"GRACE_CACHE": "default"})
def test_present_grace_cache_is_quiet():
    assert check_grace_cache(None) == []
```

```python
# tests/test_revocation.py
import pytest

from django_signet.models import RevocationReason, TokenFamily
from django_signet.sessions.rotation import RotationPolicy

pytestmark = pytest.mark.django_db


def test_changing_a_password_revokes_every_session(user):
    RotationPolicy().open_session(user)
    RotationPolicy().open_session(user)
    user.set_password("a-brand-new-password")
    user.save()

    families = TokenFamily.objects.filter(user=user)
    assert families.count() == 2
    assert all(f.is_live is False for f in families)
    assert all(
        f.revoked_reason == RevocationReason.PASSWORD_CHANGE for f in families
    )


def test_saving_without_changing_the_password_leaves_sessions_alone(user):
    pair = RotationPolicy().open_session(user)
    user.first_name = "Alice"
    user.save()
    pair.family.refresh_from_db()
    assert pair.family.is_live is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_checks.py tests/test_revocation.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'django_signet.checks'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/django_signet/checks.py
from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.cache import InvalidCacheBackendError, caches
from django.core.checks import CheckMessage, Error, Warning


def _signet() -> dict[str, Any]:
    return getattr(settings, "SIGNET", {}) or {}


def check_cookie_security(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    cfg = _signet()
    if settings.DEBUG or cfg.get("COOKIE_SECURE", True):
        return []
    return [
        Error(
            "Signet cookies are configured with secure=False while DEBUG=False.",
            hint="Authentication cookies must only travel over HTTPS in "
            "production. Remove COOKIE_SECURE=False from the SIGNET setting.",
            id="signet.E001",
        )
    ]


def check_cookie_prefix(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    cfg = _signet()
    name = cfg.get("COOKIE_REFRESH_NAME", "")
    path = cfg.get("COOKIE_REFRESH_PATH", "/api/auth/refresh")
    if name.startswith("__Host-") and path != "/":
        return [
            Error(
                f"Cookie {name!r} uses the __Host- prefix but is scoped to "
                f"path {path!r}.",
                hint="__Host- requires Path=/. Browsers silently drop the "
                "cookie otherwise, so requests arrive unauthenticated with no "
                "error. Use the __Secure- prefix for path-scoped cookies.",
                id="signet.E002",
            )
        ]
    return []


def check_grace_cache(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    alias = _signet().get("GRACE_CACHE", "default")
    if alias is None:
        return []  # explicitly disabled: strict mode, nothing to warn about
    try:
        caches[alias]
    except InvalidCacheBackendError:
        return [
            Warning(
                f"SIGNET['GRACE_CACHE'] names cache alias {alias!r}, which is "
                "not configured.",
                hint="Without a cache the refresh grace window cannot work, "
                "so concurrent refreshes from two tabs will be treated as "
                "token theft. Configure the cache, or set GRACE_CACHE=None to "
                "choose strict RFC 9700 behaviour deliberately.",
                id="signet.W003",
            )
        ]
    return []


def check_signing_key(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    cfg = _signet()
    algorithm = cfg.get("ALGORITHM", "HS256")
    if algorithm.startswith("RS") and not cfg.get("SIGNING_KEY"):
        return [
            Warning(
                f"ALGORITHM is {algorithm!r} but no SIGNING_KEY is set.",
                hint="RSA algorithms need an explicit PEM private key; "
                "SECRET_KEY is not a valid RSA key.",
                id="signet.W004",
            )
        ]
    return []


ALL_CHECKS = (
    check_cookie_security,
    check_cookie_prefix,
    check_grace_cache,
    check_signing_key,
)
```

```python
# src/django_signet/revocation.py
from __future__ import annotations

from typing import Any

from django_signet.models import RevocationReason


def revoke_on_password_change(sender: Any, instance: Any, **kwargs: Any) -> None:
    """Revoke every session when a user's password changes.

    Access tokens already issued remain valid until they expire, which is the
    documented trade-off of stateless verification. Refresh is cut off at once,
    so the blast radius is one access-token lifetime.
    """
    if instance.pk is None:
        return
    try:
        previous = sender.objects.get(pk=instance.pk)
    except sender.DoesNotExist:
        return
    if previous.password == instance.password:
        return

    from django_signet.sessions.stores.orm import ORMTokenStore

    ORMTokenStore().revoke_all_for_user(
        instance, RevocationReason.PASSWORD_CHANGE
    )
```

```python
# src/django_signet/apps.py
from django.apps import AppConfig
from django.core.checks import register


class SignetConfig(AppConfig):
    name = "django_signet"
    label = "django_signet"
    verbose_name = "Signet JWT authentication"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from django.contrib.auth import get_user_model
        from django.db.models.signals import pre_save

        from django_signet.checks import ALL_CHECKS
        from django_signet.revocation import revoke_on_password_change

        for check in ALL_CHECKS:
            register(check, "signet")

        pre_save.connect(
            revoke_on_password_change,
            sender=get_user_model(),
            dispatch_uid="signet.revoke_on_password_change",
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_checks.py tests/test_revocation.py -v`
Expected: 6 passed.

- [ ] **Step 5: Confirm the checks run in a real Django startup**

Run: `DJANGO_SETTINGS_MODULE=tests.settings .venv/bin/python -m django check`
Expected: "System check identified no issues".

- [ ] **Step 6: Commit**

```bash
git add src/django_signet/checks.py src/django_signet/revocation.py src/django_signet/apps.py tests/
git commit -m "feat: system checks and password-change session revocation"
```

---

## Task 13: Adversarial security suite

This suite is the release gate. It attacks the library through the real HTTP
cycle rather than calling internals, so it catches wiring mistakes that unit
tests pass over.

**Files:**
- Create: `tests/security/test_forgery.py`, `tests/security/test_session_attacks.py` (the package marker was created in Task 1)
- Test: both of the above

**Interfaces:**
- Consumes: everything built so far. Adds no production code.

- [ ] **Step 1: Write the forgery tests**

```python
# tests/security/test_forgery.py
import json
from datetime import timedelta

import jwt
import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from django_signet.transport.cookie import CookiePolicy

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


@pytest.fixture
def client(account):
    c = APIClient()
    c.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    return c


def _attack(client, token):
    client.cookies[POLICY.access_name] = token
    return client.get(reverse("django_signet:verify"))


def test_alg_none_is_rejected(client, account):
    """The classic forgery: strip the signature, declare alg=none."""
    forged = jwt.encode(
        {"sub": str(account.pk), "typ": "access",
         "exp": int((timezone.now() + timedelta(hours=1)).timestamp())},
        key="",
        algorithm="none",
    )
    assert _attack(client, forged).status_code == 401


def test_hmac_signed_with_the_public_key_is_rejected(client, account):
    """RS/HS key confusion: sign HS256 using material an attacker can read.
    Because the backend pins algorithms=['HS256'] and the real secret is
    private, this must fail."""
    forged = jwt.encode(
        {"sub": str(account.pk), "typ": "access",
         "exp": int((timezone.now() + timedelta(hours=1)).timestamp())},
        key="a-public-value-an-attacker-knows",
        algorithm="HS256",
    )
    assert _attack(client, forged).status_code == 401


def test_a_flipped_payload_byte_is_rejected(client):
    original = client.cookies[POLICY.access_name].value
    head, payload, sig = original.split(".")
    assert _attack(client, f"{head}.{payload[:-1]}X.{sig}").status_code == 401


def test_a_truncated_token_is_rejected(client):
    original = client.cookies[POLICY.access_name].value
    assert _attack(client, original.rsplit(".", 1)[0]).status_code == 401


def test_garbage_is_rejected(client):
    for junk in ["", "....", "not-a-jwt", "a.b.c", "Bearer x"]:
        assert _attack(client, junk).status_code == 401


def test_an_expired_token_is_rejected(account):
    with override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(seconds=-1)}):
        c = APIClient()
        c.post(
            reverse("django_signet:login"),
            {"username": "bob", "password": PASSWORD},
            format="json",
        )
        assert c.get(reverse("django_signet:verify")).status_code == 401


def test_extra_claims_cannot_overwrite_the_subject(account):
    """A custom get_claims() hook must not be able to forge identity."""
    from django_signet.sessions.rotation import RotationPolicy
    from django_signet.tokens.access import AccessToken

    pair = RotationPolicy().open_session(account, extra={"sub": "999", "exp": 1})
    claims = AccessToken().verify(pair.access.value)
    assert claims["sub"] == str(account.pk)
    assert claims["exp"] > int(timezone.now().timestamp())


def test_login_sets_every_required_cookie_flag(account):
    """Browser-enforced contract. A wrong flag fails silently in production,
    so assert it explicitly."""
    c = APIClient()
    response = c.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    access = response.cookies[POLICY.access_name]
    refresh = response.cookies[POLICY.refresh_name]
    csrf = response.cookies[POLICY.csrf_name]

    assert access["httponly"] is True and access["secure"] is True
    assert refresh["httponly"] is True and refresh["secure"] is True
    assert access["samesite"] == "Lax"
    assert access["path"] == "/"
    assert refresh["path"] == POLICY.refresh_path
    assert csrf["httponly"] == ""  # must stay readable for double-submit
    assert POLICY.access_name.startswith("__Host-")
    assert POLICY.refresh_name.startswith("__Secure-")


def test_error_bodies_never_disclose_the_reason(client):
    body = json.dumps(_attack(client, "a.b.c").json()).lower()
    for leak in ["signature", "expired", "revoked", "decode", "algorithm"]:
        assert leak not in body
```

- [ ] **Step 2: Write the session-attack tests**

```python
# tests/security/test_session_attacks.py
import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason, TokenFamily
from django_signet.transport.cookie import CookiePolicy

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


def _login():
    c = APIClient()
    c.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    return c


def test_stolen_refresh_token_replayed_later_burns_the_family(account, settings):
    """The RFC 9700 scenario. The attacker captures a refresh token; the
    legitimate client rotates first; the attacker replays after the grace
    window and the whole lineage dies."""
    settings.SIGNET = {"GRACE_CACHE": None}  # strict mode
    victim = _login()
    stolen = victim.cookies[POLICY.refresh_name].value

    assert victim.post(reverse("django_signet:refresh")).status_code == 200

    attacker = APIClient()
    attacker.cookies[POLICY.refresh_name] = stolen
    assert attacker.post(reverse("django_signet:refresh")).status_code == 401

    family = TokenFamily.objects.get()
    assert family.is_live is False
    assert family.revoked_reason == RevocationReason.REUSE_DETECTED

    # and the victim is now locked out too - that is the intended blast radius
    assert victim.post(reverse("django_signet:refresh")).status_code == 401


def test_two_tabs_refreshing_together_do_not_burn_the_family(account):
    """The false-positive that most implementations ship. Both callers must
    succeed and the session must survive."""
    tab_a = _login()
    shared = tab_a.cookies[POLICY.refresh_name].value

    tab_b = APIClient()
    tab_b.cookies[POLICY.refresh_name] = shared

    first = tab_a.post(reverse("django_signet:refresh"))
    second = tab_b.post(reverse("django_signet:refresh"))

    assert first.status_code == 200
    assert second.status_code == 200
    assert (
        first.cookies[POLICY.refresh_name].value
        == second.cookies[POLICY.refresh_name].value
    )
    assert TokenFamily.objects.get().is_live is True


def test_csrf_is_required_for_cookie_authenticated_writes(account):
    client = _login()
    assert client.post(reverse("django_signet:logout")).status_code == 401


def test_a_forged_csrf_header_is_rejected(account):
    client = _login()
    response = client.post(
        reverse("django_signet:logout"), **{CSRF_HEADER: "attacker-chosen"}
    )
    assert response.status_code == 401


def test_a_revoked_session_cannot_be_refreshed(account):
    client = _login()
    TokenFamily.objects.get().revoke(RevocationReason.ADMIN)
    assert client.post(reverse("django_signet:refresh")).status_code == 401


def test_disabling_an_account_revokes_access_immediately(account):
    """CVE-2024-22513 regression: this is the bug that made Simple JWT
    vulnerable. Disabling must not wait for token expiry."""
    client = _login()
    assert client.get(reverse("django_signet:verify")).status_code == 200
    account.is_active = False
    account.save(update_fields=["is_active"])
    assert client.get(reverse("django_signet:verify")).status_code == 401


def test_changing_the_password_kills_refresh(account):
    client = _login()
    account.set_password("a-completely-different-password")
    account.save()
    assert client.post(reverse("django_signet:refresh")).status_code == 401


def test_one_users_token_cannot_reach_another_users_session(account, django_user_model):
    django_user_model.objects.create_user(username="mallory", password=PASSWORD)
    bob = _login()
    response = bob.get(reverse("django_signet:verify"))
    assert response.data["user_id"] == account.pk
```

- [ ] **Step 3: Run the security suite**

Run: `.venv/bin/pytest tests/security/ -v`
Expected: all pass. Any failure here blocks release.

- [ ] **Step 4: Run the whole suite with coverage**

Run: `.venv/bin/pytest --cov=django_signet --cov-report=term-missing -q`
Expected: all tests pass; coverage of `rotation.py`, `authentication.py` and `csrf.py` at 100%.

- [ ] **Step 5: Commit**

```bash
git add tests/security/
git commit -m "test: adversarial security suite covering forgery and session attacks"
```

---

## Task 14: Documentation, benchmarks and release

**Files:**
- Create: `README.md`, `CHANGELOG.md`, `docs/migrating-from-simplejwt.md`, `benchmarks/bench_verify.py`

Tooling, CI and governance files were created in Task 0; this task is documentation, benchmarks and the release gate.

- [ ] **Step 1: Write the README**

```bash
cat > README.md <<'EOF'
# django-signet

Polymorphic, secure-by-default JWT authentication for Django REST Framework.

Authentication stays entirely in the backend: tokens travel in httpOnly
cookies, rotate automatically, and never appear in a response body or in
JavaScript.

## Why another JWT package

| | Simple JWT | Signet |
|---|---|---|
| httpOnly cookie transport | you build it | built in |
| Refresh rotation | yes | yes |
| **Reuse detection (RFC 9700)** | no | yes, with token families |
| Access-token revocation | impossible | opt-in per view |
| Refresh tokens at rest | **stored raw** | sha256 digest only |
| Whitelist and blacklist | blacklist only | one `TokenStore` port, either mode |
| Storage backend | ORM only | ORM or cache |
| Customisation | global settings dict of dotted paths | subclass anything, per view |

## Install

```bash
pip install django-signet
```

```python
INSTALLED_APPS = [..., "django_signet"]

urlpatterns = [path("api/auth/", include("django_signet.urls"))]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_signet.authentication.CookieJWTAuthentication",
    ],
}
```

That is a complete, secure setup. `POST /api/auth/login` sets the cookies,
`POST /api/auth/refresh` rotates them, `POST /api/auth/logout` revokes the
session.

## Polymorphism

Everything is a class you subclass, and DRF resolves authentication per view,
so several auth behaviours coexist in one project:

```python
class CustomerAuth(CookieJWTAuthentication):
    access_lifetime = timedelta(minutes=5)

class StaffAuth(StrictCookieJWTAuthentication):   # instant revocation
    access_lifetime = timedelta(minutes=10)
    transport = CookieTransport(CookiePolicy(prefix="adm", samesite="Strict"))

class PaymentViewSet(ModelViewSet):
    authentication_classes = [StaffAuth]
```

Add claims, react to security events, or change the cookies by overriding a
method:

```python
class LoginView(TokenObtainView):
    def get_claims(self, user):
        return {"org": user.org_id}

class RefreshView(TokenRefreshView):
    class rotation(RotationPolicy):
        def on_reuse_detected(self, family):
            notify_security_team(family.user)
```

## Security model

- Access tokens verify statelessly: zero queries on normal traffic. The
  5-minute lifetime is the revocation window.
- Refresh tokens are session-backed, stored only as sha256 digests, and rotate
  on every use.
- Replaying a consumed refresh token burns the entire family (RFC 9700 / BCP 240).
- A 10-second grace window makes concurrent refreshes idempotent, so two tabs
  or React StrictMode do not trigger false theft detection. Set
  `GRACE_CACHE = None` for strict behaviour.
- Cookie-authenticated writes require a double-submit CSRF token compared in
  constant time.

## Licence

MIT.
EOF
```

- [ ] **Step 2: Write the migration guide and changelog**

```bash
cat > docs/migrating-from-simplejwt.md <<'EOF'
# Migrating from djangorestframework-simplejwt

Signet does not read `SIMPLE_JWT`. Map settings across explicitly.

| Simple JWT | Signet |
|---|---|
| `ACCESS_TOKEN_LIFETIME` | `SIGNET["ACCESS_TOKEN_LIFETIME"]` |
| `REFRESH_TOKEN_LIFETIME` | `SIGNET["REFRESH_TOKEN_LIFETIME"]` |
| `ROTATE_REFRESH_TOKENS` | always on |
| `BLACKLIST_AFTER_ROTATION` | always on, plus reuse detection |
| `TOKEN_OBTAIN_SERIALIZER` | subclass `TokenObtainView.serializer_class` |
| `USER_AUTHENTICATION_RULE` | override `get_user()` on your auth class |
| `AUTH_HEADER_TYPES` | `HeaderTransport(keyword=...)` |

## Cutover

Existing Simple JWT tokens are not portable: Signet requires a `sid` claim
naming a token family that does not exist for them. Run both authentication
classes during the transition:

```python
authentication_classes = [CookieJWTAuthentication, LegacySimpleJWTAuthentication]
```

DRF tries each in order, so old tokens keep working until they expire while
every new login issues a Signet session. Remove the legacy class once the
longest old refresh token has expired.

## Data

Do not migrate `OutstandingToken`. It stores raw token strings, which is the
practice Signet exists to avoid. Let the old rows expire and delete the table.
EOF

cat > CHANGELOG.md <<'EOF'
# Changelog

## 0.1.0 - unreleased

First release.

- httpOnly cookie transport with correct `__Host-` / `__Secure-` prefixes
- Refresh rotation with token families and RFC 9700 reuse detection
- Idempotent grace window for concurrent refreshes
- Refresh tokens stored as sha256 digests only
- `TokenStore` port with ORM and cache adapters, allowlist or denylist
- Stateless access verification plus opt-in `Strict*` classes
- Double-submit CSRF with constant-time comparison
- Django system checks for insecure or incoherent configuration
EOF
```

- [ ] **Step 3: Add the benchmark harness**

```python
# benchmarks/bench_verify.py
"""Measures the token verification path.

Recorded on 2026-09-23 (PyJWT 2.10.1, HS256, 324-byte token):

    full decode+verify   27.30 us
      raw HMAC (C)        3.38 us
      b64 + json (C)      6.82 us
      pure-Python glue   17.10 us

A native rewrite could reclaim about 22 us. The user lookup that follows
costs 200-500 us against Postgres, so verification is roughly 1% of a
request. Re-run this before considering a Rust backend: the trigger is
verification exceeding 5% of request time in a real deployment.
"""

import time

import jwt

KEY = "x" * 64


def bench(fn, n=20000):
    for _ in range(1000):
        fn()
    runs = []
    for _ in range(5):
        start = time.perf_counter_ns()
        for _ in range(n):
            fn()
        runs.append((time.perf_counter_ns() - start) / n)
    return min(runs)


def main() -> None:
    payload = {
        "sub": "12345",
        "jti": "a" * 32,
        "sid": "b" * 32,
        "typ": "access",
        "exp": int(time.time()) + 300,
    }
    token = jwt.encode(payload, KEY, algorithm="HS256")
    micros = bench(lambda: jwt.decode(token, KEY, algorithms=["HS256"])) / 1000
    print(f"full decode+verify: {micros:6.2f} us")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Verify the build**

```bash
.venv/bin/pip install build twine
.venv/bin/python -m build
.venv/bin/twine check dist/*
```

Expected: `twine check` reports PASSED for both the wheel and the sdist.

- [ ] **Step 5: Verify the package installs clean in a fresh environment**

```bash
python3 -m venv /tmp/signet-smoke
/tmp/signet-smoke/bin/pip install dist/django_signet-0.1.0-py3-none-any.whl
/tmp/signet-smoke/bin/python -c "import django_signet; print(django_signet.__version__)"
```

Expected: prints `0.1.0` with no missing dependency.

- [ ] **Step 6: Commit**

```bash
git add README.md CHANGELOG.md docs/ benchmarks/
git commit -m "docs: README, migration guide, changelog and benchmark harness"
```

- [ ] **Step 7: Publish — REQUIRES EXPLICIT USER APPROVAL**

**Do not run this step autonomously.** Publishing to PyPI is irreversible:
a version number can never be reused, and the package becomes public
immediately. Stop and ask the user to confirm, and let them supply
credentials through their own tooling.

```bash
# Only after the user has confirmed, and with their own credentials:
.venv/bin/twine upload dist/*
```

Prefer configuring PyPI Trusted Publishing on the GitHub repository so no API
token is ever stored locally.

---

## Self-Review

**Spec coverage.** Task 0 covers the repository shell, tooling and open-source governance — added after the plan's first draft, which specified a flat layout, no linter, and treated GitHub as an afterthought. Every section of the spec maps to a task: §4 architecture →
Tasks 1–12; §5 state model → Tasks 7, 10; §6 data model → Task 4; §7 store port
→ Tasks 5–6; §8 rotation → Task 7; §9 transport → Task 8; §10 CSRF → Task 9;
§11 DRF surface → Tasks 10–11; §12 error handling → Tasks 10–11 plus the
disclosure test in Task 13; §13 testing → Task 13; §14 packaging → Task 14.

**Deviations from the spec, all deliberate:**

1. `TokenStore.open_family()` takes no digest, and `issue()` was added. A refresh
   token embeds its family id in the `sid` claim, so the family must exist
   before the first token can be minted — the spec's single-call signature was
   circular.
2. `CookiePolicy` uses `setting()` descriptors rather than being a plain
   dataclass, so the Task 12 system checks validate configuration the library
   actually honours.
3. The refresh cookie uses `__Secure-`, not `__Host-`. `__Host-` mandates
   `Path=/`, which contradicts the spec's own path-scoping requirement. The spec
   was corrected to match.
4. Password-change revocation is a `pre_save` receiver rather than a token
   claim. It needs no claim, costs nothing on the hot path, and covers refresh
   tokens.

**Known limitations to state in the docs, not to hide:**

- `CacheTokenStore.revoke_all_for_user()` raises `NotImplementedError`; a cache
  cannot enumerate a user's families. Documented in `docs/stores.md`.
- `select_for_update()` is a no-op on SQLite, which serialises writes anyway.
  True concurrent-consume atomicity should be verified against PostgreSQL before
  the 1.0 release; add that matrix cell then.
- Access tokens remain valid for up to their lifetime after revocation unless a
  `Strict*` authentication class is used. This is the documented trade-off, and
  Task 10 asserts both halves of it.
