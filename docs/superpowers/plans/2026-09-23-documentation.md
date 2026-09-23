# django-signet documentation — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a Read the Docs site for `django-signet` that is complete, accurate, and mechanically guarded against drifting from the code.

**Architecture:** Sphinx + MyST (Markdown) + Furo, organised by Diátaxis. Examples are real files under `docs/examples/`, exercised by pytest and rendered with `literalinclude`. A completeness test ties the settings and system-check reference pages to the source. Delivered as two PRs: infrastructure first, so the user can finish creating the Read the Docs project; content second.

**Tech Stack:** Sphinx 9.1, myst-parser 5.1, furo 2025.12.19, sphinx-copybutton 0.5.2, Python 3.13 on Read the Docs.

**Spec:** `docs/superpowers/specs/2026-09-23-documentation-design.md`

**A note on content tasks.** Tasks 2–5 are prose. Their steps specify each page's required content, its sources of truth, and how it is verified — not the finished text, which is the work itself. Task 1 is configuration and is specified in full; its code was proven in a scratch build (`sphinx-build -W` succeeded with `autodoc` importing the package).

## Global Constraints

- Branch protection on `main` requires CI; all work lands through pull requests.
- The build must pass `sphinx-build -W --keep-going` — warnings are errors. Do not pass `-n` (nitpicky): Django REST Framework publishes no Sphinx inventory, so type hints referencing DRF classes cannot resolve.
- `intersphinx` covers Python and Django only.
- `docs/superpowers/` (internal design records) is excluded from the build and must never be linked from a published page.
- **Every factual claim must be checked against the source.** A prior review found the README stating false things about the library and about Simple JWT. Where a page describes behaviour, cite the module; where an example exists, it must be a tested file under `docs/examples/`, not inline prose code.
- The library's public API is **not frozen until 1.0** — say so wherever stability is discussed.
- Existing gates still apply to any Python touched: `ruff format .`, `ruff check --fix .`, `mypy src/django_signet`, `lint-imports`, `pytest -q`. Never `# noqa`, `# type: ignore`, or a false `cast()`.
- Files under 500 lines.
- **Do not publish** to PyPI. **Do not run `pre-commit install`.**
- Commits carry the author's configured git identity and **no** `Co-Authored-By` trailer.

---

## Task 1: Infrastructure (PR 1)

**Files:**
- Create: `.readthedocs.yaml`, `docs/conf.py`, `docs/_django_settings.py`, `docs/index.md`
- Modify: `pyproject.toml` (add a `docs` extra), `.gitignore` (add `docs/_build/`), `.github/workflows/ci.yml` (add a `docs` job), `noxfile.py` (add a `docs` session)

**Interfaces:**
- Produces: a buildable site; the `docs` extra; a CI job named exactly `docs` (later added as a required check); `docs/index.md` with a root `toctree` that later tasks extend.

- [ ] **Step 1: Confirm the build fails before configuration exists**

Run: `.venv/bin/sphinx-build -W --keep-going -b html docs docs/_build/html`
Expected: FAIL — no `conf.py`.

- [ ] **Step 2: Add the `docs` extra to `pyproject.toml`**

Under `[project.optional-dependencies]`, beside `rsa`:

```toml
docs = [
    "sphinx>=9.1",
    "myst-parser>=5.1",
    "furo>=2025.12.19",
    "sphinx-copybutton>=0.5.2",
]
```

- [ ] **Step 3: Write `.readthedocs.yaml`**

The user's file, with `python.install` enabled and `fail_on_warning` added:

```yaml
# Read the Docs configuration file
# See https://docs.readthedocs.io/en/stable/config-file/v2.html for details

version: 2

build:
  os: ubuntu-24.04
  tools:
    python: "3.13"

sphinx:
  configuration: docs/conf.py
  # A broken reference fails the build rather than shipping.
  fail_on_warning: true

# autodoc imports django_signet, so the package itself must be installed.
python:
  install:
    - method: pip
      path: .
      extra_requirements:
        - docs
```

- [ ] **Step 4: Write `docs/_django_settings.py`**

```python
"""Minimal settings so autodoc can import django_signet. Not used at runtime."""

SECRET_KEY = "docs-build-only-not-a-secret"
USE_TZ = True
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "django_signet",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
```

- [ ] **Step 5: Write `docs/conf.py`**

```python
"""Sphinx configuration for the django-signet documentation."""

import os
import sys
from importlib.metadata import version as _version
from pathlib import Path

import django

# autodoc imports django_signet, and importing its models needs configured
# settings. The docs directory goes on the path so the settings stub resolves.
sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "_django_settings")
django.setup()

project = "django-signet"
author = "Aryan Hamedani"
copyright = "2026, django-signet contributors"
release = _version("django-signet")
version = ".".join(release.split(".")[:2])

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
]
source_suffix = {".md": "markdown"}
exclude_patterns = ["_build", "superpowers", "examples", "_django_settings.py"]

myst_enable_extensions = ["colon_fence", "deflist"]
myst_heading_anchors = 3

autodoc_typehints = "description"
autodoc_member_order = "bysource"

# Django REST Framework publishes no Sphinx inventory, so it cannot be linked.
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "django": (
        "https://docs.djangoproject.com/en/stable/",
        "https://docs.djangoproject.com/en/stable/_objects/",
    ),
}

html_theme = "furo"
html_title = f"django-signet {release}"
```

- [ ] **Step 6: Write `docs/index.md`**

A real landing page — the pitch from the README's opening, a short statement that this is authentication kept entirely in the backend via httpOnly cookies, a link to the repository, and a root `toctree` listing the two existing pages. Later tasks extend this `toctree`. No "coming soon" text.

```markdown
# django-signet

Polymorphic, secure-by-default JWT authentication for Django REST Framework.

Authentication stays entirely in the backend: tokens travel in httpOnly
cookies, rotate on every refresh, and never appear in a response body or in
JavaScript.

Source code: <https://github.com/AryanHamedani/django-signet>

```{toctree}
:maxdepth: 2

stores
migrating-from-simplejwt
```
```

- [ ] **Step 7: Ignore build output**

Append `docs/_build/` to `.gitignore`.

- [ ] **Step 8: Run the build and confirm it passes**

Run: `.venv/bin/pip install -e ".[docs]" && .venv/bin/sphinx-build -W --keep-going -b html docs docs/_build/html`
Expected: `build succeeded.`, pages `index.html`, `stores.html`, `migrating-from-simplejwt.html`.

- [ ] **Step 9: Add the `docs` job to `.github/workflows/ci.yml`**

A new job alongside `quality`, `test` and `security-gate`:

```yaml
  docs:
    name: docs
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
          cache: pip
      - run: pip install -e ".[docs]"
      - name: build the documentation, warnings are errors
        run: sphinx-build -W --keep-going -b html docs docs/_build/html
```

- [ ] **Step 10: Add a `docs` session to `noxfile.py`**

`CONTRIBUTING.md` promises `nox` mirrors CI, so the new job needs a session:

```python
@nox.session(python="3.13")
def docs(session: nox.Session) -> None:
    """Build the documentation with warnings treated as errors, as CI does."""
    session.install("-e", ".[docs]")
    session.run(
        "sphinx-build", "-W", "--keep-going", "-b", "html", "docs", "docs/_build/html"
    )
```

Add `"docs"` to `nox.options.sessions`.

- [ ] **Step 11: Run every gate**

`ruff format .`, `ruff check --fix .`, `mypy src/django_signet`, `lint-imports`, `pytest -q`, and the Step 8 build. Validate `ci.yml` and `.readthedocs.yaml` parse as YAML.

- [ ] **Step 12: Commit**

```bash
git add .readthedocs.yaml docs/conf.py docs/_django_settings.py docs/index.md pyproject.toml .gitignore .github/workflows/ci.yml noxfile.py docs/superpowers/
git commit -m "docs: Read the Docs configuration and a buildable Sphinx site"
```

**After Task 1:** open PR 1, wait for CI including the new `docs` job, merge, and add `docs` to the required checks on `main`. The user then finishes creating the Read the Docs project.

---

## Task 2: Reference, docstrings and the completeness guard (PR 2)

**Files:**
- Create: `docs/reference/index.md`, `docs/reference/settings.md`, `docs/reference/checks.md`, `docs/reference/authentication.md`, `docs/reference/views.md`, `docs/reference/transport.md`, `docs/reference/sessions.md`, `docs/reference/signals.md`, `docs/reference/exceptions.md`, `docs/reference/commands.md`, `docs/reference/api.md`
- Create: `tests/docs/__init__.py`, `tests/docs/test_reference_complete.py`
- Modify: public modules under `src/django_signet/` — docstrings only; `docs/index.md` toctree

**Interfaces:**
- Produces: `reference/*` pages that later tasks link to by these paths.

- [ ] **Step 1: Write the failing completeness test**

`tests/docs/test_reference_complete.py` — derives the lists from source so it maintains itself:

```python
"""The reference pages must cover every setting and every system check.

The lists come from the source, so adding a setting or a check without
documenting it fails CI.
"""

import re
from pathlib import Path

import pytest

from django_signet.conf import DEFAULTS

ROOT = Path(__file__).resolve().parents[2]
SETTINGS_PAGE = ROOT / "docs" / "reference" / "settings.md"
CHECKS_PAGE = ROOT / "docs" / "reference" / "checks.md"
CHECK_IDS = sorted(
    set(
        re.findall(
            r"signet\.[EW]\d{3}",
            (ROOT / "src" / "django_signet" / "checks.py").read_text(),
        )
    )
)


@pytest.mark.parametrize("key", sorted(DEFAULTS))
def test_every_setting_is_documented(key):
    assert f"`{key}`" in SETTINGS_PAGE.read_text(), (
        f"{key} missing from {SETTINGS_PAGE.name}"
    )


@pytest.mark.parametrize("check_id", CHECK_IDS)
def test_every_system_check_is_documented(check_id):
    assert f"`{check_id}`" in CHECKS_PAGE.read_text(), (
        f"{check_id} missing from {CHECKS_PAGE.name}"
    )


def test_the_check_list_is_not_empty():
    """Guards the regex itself: an empty list would make the test above vacuous."""
    assert len(CHECK_IDS) >= 10
```

Run it; expect FAIL (pages absent).

- [ ] **Step 2: Write `docs/reference/settings.md`**

One entry per key in `conf.DEFAULTS` (21 keys): its type, default, meaning, and how a class attribute overrides it. Source: `src/django_signet/conf.py`. Explain the resolution order of the `setting()` descriptor — a subclass literal, then the `SIGNET` dict, then the default — and that nothing is cached. The `COOKIE_*` defaults and their browser-enforced prefix rules come from `transport/cookie.py`.

- [ ] **Step 3: Write `docs/reference/checks.md`**

One entry per ID found in `checks.py` (10 IDs): level, what triggers it, why it matters, and how to fix it. Source: `src/django_signet/checks.py`. Note the design rule that a check never raises, and the stated limitation that checks read the `SIGNET` dict, not class-level overrides.

- [ ] **Step 4: Run the completeness test**

Expect PASS.

- [ ] **Step 5: Write the component reference pages**

`authentication.md`, `views.md` (including the URL names and `signet_urls(realm, namespace)`), `transport.md` (including `CookiePolicy`), `sessions.md` (`RotationPolicy`, the `TokenStore` port, `get_store()`, both adapters), `signals.md` (the four signals and their arguments, including that `token_reuse_detected` carries `request=None`), `exceptions.md`, `commands.md` (`signet_purge`). Each page: a short prose overview, then `autodoc` directives for that component.

Avoid documenting an object twice: `django_signet.models` re-exports `TokenFamily`, `IssuedToken` and `RevocationReason` from `sessions.models`, and documenting both paths triggers a duplicate-object warning, which `-W` turns into a failure. Document the canonical module and refer to it from the other.

- [ ] **Step 6: Fill the public docstrings**

79 of 171 public classes and functions lack a docstring. Write one for every name the reference pages render. Docstrings explain *why* and the contract, matching the existing style — plain prose, not Google or NumPy style. Do not document private helpers.

- [ ] **Step 7: `docs/reference/api.md` and the reference index**

`api.md`: the full `automodule` listing. `reference/index.md`: a `toctree` of the reference pages. Add `reference/index` to the root `toctree` in `docs/index.md`.

- [ ] **Step 8: Build, gates, commit**

Build with `-W`; every gate; commit.

---

## Task 3: Tutorial, client guides, and the example harness (PR 2)

**Files:**
- Create: `docs/tutorial/quickstart.md`, `docs/howto/index.md`, `docs/howto/spa.md`, `docs/howto/header-clients.md`, `docs/howto/deploying.md`
- Create: `docs/examples/__init__.py`, `docs/examples/quickstart_settings.py`, `docs/examples/quickstart_urls.py`, `docs/examples/client.js`
- Create: `tests/docs/conftest.py`, `tests/docs/test_examples.py`

**Interfaces:**
- Consumes: `reference/*` page paths from Task 2.
- Produces: the example harness — `tests/docs/conftest.py` puts `docs/` on `sys.path` so examples import as `examples.<name>`. Tasks 4 and 5 add examples to it.

- [ ] **Step 1: Write the harness and a failing example test**

`tests/docs/conftest.py` puts the `docs/` directory on `sys.path`. `tests/docs/test_examples.py` imports `examples.quickstart_urls`, points `ROOT_URLCONF` at it with `override_settings`, and runs login → refresh (with the CSRF header) → verify → logout through `APIClient`. Run; expect FAIL (examples absent).

- [ ] **Step 2: Write the quickstart example files, then pass the test**

`quickstart_settings.py` and `quickstart_urls.py` hold exactly what the tutorial tells a reader to add. Pass the test.

- [ ] **Step 3: Write `docs/examples/client.js` and pin it**

The frontend half: login, refresh with `X-CSRF-Token` read from the CSRF cookie, logout, all with `credentials: "include"`. JavaScript cannot run under pytest, so add a test asserting the file uses the header name the server actually checks and the cookie name the server actually sets — derived from `django_signet.csrf.CSRF_HEADER` and `CookiePolicy().csrf_name`, not hardcoded in the test.

- [ ] **Step 4: Write `docs/tutorial/quickstart.md`**

Install → settings → URLs → a first login, refresh and logout, including the client calls. Render every code block with `literalinclude` from `docs/examples/`. State the resolved cookie names and the CSRF-on-refresh requirement.

- [ ] **Step 5: Write the client-facing how-to guides**

- `spa.md`: an SPA on the same site and cross-origin — `COOKIE_SAMESITE="None"`, CORS with credentials, and why CSRF enforcement matters more there.
- `header-clients.md`: mobile and service clients with `HeaderTransport`; that `HybridTransport` is cookie-first and does not serve mobile clients; that a header logout returns 401 on a repeat and clients should drop tokens on 401.
- `deploying.md`: HTTPS as a requirement, `COOKIE_DOMAIN` and what it does to the `__Host-` prefix, the refresh path matching the URL mount (`signet.E008`), and not mounting other endpoints under the refresh path.

Every example backed by a file under `docs/examples/` with a test. `howto/index.md` holds the how-to `toctree`; add `tutorial/quickstart` and `howto/index` to the root `toctree`.

- [ ] **Step 6: Build, gates, commit**

---

## Task 4: Server-side how-to guides (PR 2)

**Files:**
- Create: `docs/howto/realms.md`, `docs/howto/custom-claims.md`, `docs/howto/reuse-detection.md`, `docs/howto/rs256.md`, `docs/howto/purging.md`
- Move: `docs/stores.md` → `docs/howto/choosing-a-store.md`, `docs/migrating-from-simplejwt.md` → `docs/howto/migrating-from-simplejwt.md`. Update every reference to the old paths — **including the root `toctree` in `docs/index.md`, which lists both by their old names since Task 1, and would otherwise fail the `-W` build** — and every link in `README.md`.
- Create: an example file and test per guide under `docs/examples/` and `tests/docs/`

- [ ] **Step 1: One tested example per guide, written test-first**

- **Realms:** a realm declared once with `signet_urls`, a shared `CookiePolicy`, and a permission class — state plainly that realms are not an authorization boundary by themselves.
- **Custom claims:** `get_claims(user)` surviving a refresh.
- **Reuse detection:** an `on_reuse_detected` override; a test proving it fires on a replay.
- **RS256:** a key pair generated in the test, `ALGORITHM`, `SIGNING_KEY`, `VERIFYING_KEY`, and `signet.E004`. Commit no key material.
- **Purging:** `signet_purge` and when to schedule it.

- [ ] **Step 2: Write the guides around the examples**

- [ ] **Step 3: Move and update the two existing pages; add all to `howto/index.md`**

- [ ] **Step 4: Build, gates, commit**

---

## Task 5: Explanation, project pages, landing page and README (PR 2)

**Files:**
- Create: `docs/explanation/index.md`, `docs/explanation/security-model.md`, `docs/explanation/architecture.md`, `docs/explanation/limitations.md`, `docs/explanation/comparison.md`, `docs/changelog.md`, `docs/contributing.md`, `docs/security.md`
- Modify: `docs/index.md`, `README.md`, `pyproject.toml`

- [ ] **Step 1: Explanation pages**

- `security-model.md`: token families, atomic consume, reuse detection, the grace window and why it exists, CSRF double-submit and proof of origin before deleting cookies, cookie prefixes, digest-only storage, and RFC 9700. Source: `sessions/`, `csrf.py`, `transport/cookie.py`, `views.py`.
- `architecture.md`: the layers and the five import-linter contracts in `pyproject.toml`, the `setting()` descriptor, the `TokenStore` port with its Protocols, and polymorphism by subclassing.
- `limitations.md`: every limitation the README currently states, plus the false-theft-alarm race documented in `RotationPolicy._redeem`.
- `comparison.md`: the Simple JWT comparison. Every claim must be verifiable from Simple JWT's docs or source; the prior review corrected two — keep the corrected versions.

- [ ] **Step 2: Project pages**

`changelog.md`, `contributing.md` and `security.md` each pull in the root file with MyST's `{include}` directive, so each fact has one home.

- [ ] **Step 3: The landing page**

Rewrite `docs/index.md`: what the library is, who it is for, a three-line install, a map of the four sections, and the root `toctree` in order — tutorial, how-to, reference, explanation, project.

- [ ] **Step 4: Slim the README**

Keep the pitch, the comparison table and a short quickstart; replace the depth with links to the relevant docs pages on `https://django-signet.readthedocs.io`. Add a docs badge. Every claim that moves out of the README must exist in the docs.

- [ ] **Step 5: Point the `Documentation` URL in `pyproject.toml` at `https://django-signet.readthedocs.io`**

- [ ] **Step 6: Build, gates, commit**

**After Task 5:** open PR 2, wait for CI, merge.

---

## Self-review

- **Spec coverage.** Tooling, `.readthedocs.yaml`, `conf.py` → Task 1. Diátaxis structure → Tasks 2–5. Tested examples → Tasks 3–4. Completeness test → Task 2. Docs CI job → Task 1, made required after PR 1. Docstrings → Task 2. README → Task 5. Two-PR delivery → the "after" notes on Tasks 1 and 5.
- **Placeholders.** None in Task 1. Tasks 2–5 specify required content and sources rather than finished prose, as stated in the header.
- **Consistency.** Page paths used in later tasks match those created earlier; the harness from Task 3 is the one Tasks 4 and 5 extend; `signet_urls(realm, namespace)` matches `urls.py`.
