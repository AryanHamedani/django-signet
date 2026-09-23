"""Make the documentation's examples importable, and run the quickstart.

The pages render these files with ``literalinclude``; the tests in this
directory import and run them, so an example that stops working fails CI.

``docs/`` goes on the path so examples import as ``examples.<name>``.
``docs/examples/`` goes on it too, so the example app imports as ``notes``,
exactly as it does in the reader's project.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest
from django.test import override_settings

DOCS = Path(__file__).resolve().parents[2] / "docs"

for entry in (DOCS, DOCS / "examples"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

# examples/spa_settings.py imports django-cors-headers, which this project
# does not depend on. When it is not installed, stand in for its one import
# with the value django-cors-headers 4.9.0 defines (corsheaders/defaults.py).
if importlib.util.find_spec("corsheaders") is None:
    _defaults = types.ModuleType("corsheaders.defaults")
    _defaults.default_headers = (
        "accept",
        "authorization",
        "content-type",
        "user-agent",
        "x-csrftoken",
        "x-requested-with",
    )
    sys.modules["corsheaders"] = types.ModuleType("corsheaders")
    sys.modules["corsheaders.defaults"] = _defaults


@pytest.fixture
def quickstart(monkeypatch):
    """The project the quickstart builds: its settings and its URLconf."""
    from examples import quickstart_settings
    from notes.views import NotesView

    from tests.docs.helpers import settings_of, use_rest_framework_defaults

    with override_settings(
        ROOT_URLCONF="examples.quickstart_urls", **settings_of(quickstart_settings)
    ):
        use_rest_framework_defaults(monkeypatch, NotesView)
        yield
