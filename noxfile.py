"""Development task runner.

The CI matrix mirrors these sessions, so `nox` locally reproduces CI.
"""

import nox

nox.options.sessions = ["lint", "typecheck", "architecture", "tests", "docs"]

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
    session.install("-e", ".[rsa]")
    session.run("pytest", "-q")


@nox.session(python="3.13")
def docs(session: nox.Session) -> None:
    """Build the documentation with warnings treated as errors, as CI does."""
    session.install("-e", ".[docs]")
    session.run(
        "sphinx-build", "-W", "--keep-going", "-b", "html", "docs", "docs/_build/html"
    )
