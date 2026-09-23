# django-signet documentation — design

- **Date:** 2026-09-23
- **Status:** approved in conversation; implementation proceeding
- **Host:** Read the Docs, expected slug `django-signet` (derived from the
  repository name; the project was not yet created when this was written)

## Goal

A documentation site that lets someone decide whether to adopt the library,
get a secure setup working, solve specific problems, look up exact behaviour,
and understand the security model — and that **stays true** as the code
changes.

## Tooling

- **Sphinx**, as specified by the user's `.readthedocs.yaml`. `autodoc` builds
  the API reference from docstrings, which is Sphinx's strength for a library.
  MkDocs Material was considered and rejected: the user's config already chose
  Sphinx.
- **MyST-Parser** — pages are Markdown, matching the README and the existing
  `docs/*.md`.
- **Furo** theme.
- Extensions: `sphinx.ext.autodoc`, `sphinx.ext.intersphinx` (Python and
  Django — DRF publishes no Sphinx inventory, so it cannot be linked), `sphinx_copybutton`.
- Dependencies declared as a `docs` optional extra in `pyproject.toml`.

### `.readthedocs.yaml`

The user's file, with two changes, both of which the file's own comments
invite:

1. `python.install` enabled, installing the package with the `docs` extra —
   `autodoc` must import `django_signet`, so the build fails without it.
2. `sphinx.fail_on_warning: true` — a broken reference fails the build rather
   than shipping.

### `docs/conf.py`

Configures a minimal Django settings module before `autodoc` imports anything,
since importing the library's models requires configured settings. Excludes
`superpowers/` (internal design records) from the build. Reads the version
from the installed package.

## Structure (Diátaxis)

| Section | Pages |
|---|---|
| Tutorial | Quickstart: install → login → refresh → logout, including the frontend `fetch` calls with the CSRF header |
| How-to | SPA integration (incl. cross-origin `SameSite=None`), mobile and header clients, multiple realms with `signet_urls`, custom claims, reacting to token theft, choosing a store, RS256 keys, deploying, purging expired sessions, migrating from Simple JWT |
| Reference | Settings, system checks, authentication classes, views and URLs, transports and `CookiePolicy`, rotation policy and stores, signals, exceptions, management commands, API (autodoc) |
| Explanation | Security model, architecture and polymorphism, limitations and trade-offs, comparison with Simple JWT |
| Project | Changelog, contributing, security policy |

## Keeping the docs true

A final review in the build found a README example that looked correct and
silently failed. The documentation is therefore guarded mechanically:

1. **Tested examples.** Every non-trivial example lives as a real file under
   `docs/examples/`, is exercised by pytest, and is rendered into pages with
   `literalinclude`. An example that stops working fails CI.
2. **Reference-completeness test.** Fails if any key in `conf.DEFAULTS`, or any
   system-check ID, is absent from the reference pages.
3. **Docs CI job.** Builds with `-W` (warnings are errors). Proposed as a
   required check on `main`.
4. **Docstrings.** The public API is documented at the source, because the
   reference is generated from it. 79 of 171 public names currently lack one.

## README

Slimmed to a landing page: the pitch, the comparison table, a short quickstart,
and a link to the docs. Depth moves to the site so each fact has one home.

## Delivery

Two pull requests, because `main` is protected and the Read the Docs wizard
needs `.readthedocs.yaml` on `main` before project creation can finish:

1. **Infrastructure** — config, a minimal buildable site built from the two
   existing pages, and the docs CI job. Merged first so
   the user can finish creating the project and get a green first build.
2. **Content** — docstrings, reference, the example-test harness and the
   reference-completeness test (both check pages this PR creates), tutorial,
   how-to guides, explanation, README.

## Out of scope

Versioned-docs policy beyond Read the Docs' defaults, translations, and a
custom domain.
