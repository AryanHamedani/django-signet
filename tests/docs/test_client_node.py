"""Run ``docs/examples/client.js`` in Node against a live server.

The static tests in ``test_examples.py`` pin the names ``client.js`` uses.
This one runs its logic: the tutorial's console session
(``docs/examples/try_it.js``) line by line, then a shared refresh, a retry
after the access cookie expires, a single retry for a 401 that persists,
and no retry once the session is gone. ``tests/docs/js/browser.mjs``
stands in for the browser's cookie jar.

Skipped when ``node`` is not on ``PATH``.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from examples import local_settings

from django_signet.transport.cookie import CookiePolicy
from tests.docs.helpers import settings_of

HERE = Path(__file__).resolve().parent
EXAMPLES = HERE.parents[1] / "docs" / "examples"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not on PATH")


def client_js_with_csrf_cookie(name, directory):
    """``client.js`` as the reader edits it: only ``CSRF_COOKIE`` changes."""
    source = (EXAMPLES / "client.js").read_text()
    edited, replaced = re.subn(
        r'^const CSRF_COOKIE = "[^"]*";',
        f'const CSRF_COOKIE = "{name}";',
        source,
        flags=re.MULTILINE,
    )
    assert replaced == 1
    module = directory / "client.mjs"
    module.write_text(edited)
    return module


@pytest.mark.parametrize(
    "extra_settings",
    [pytest.param({}, id="default"), pytest.param(local_settings, id="local-http")],
)
def test_client_js_against_a_live_server(
    extra_settings, quickstart, live_server, transactional_db, tmp_path
):
    overrides = settings_of(extra_settings) if extra_settings else {}
    with override_settings(**overrides):
        get_user_model().objects.create_user("alice", password="your-password")
        # The value the page tells the reader to set, for these settings.
        module = client_js_with_csrf_cookie(CookiePolicy().csrf_name, tmp_path)
        completed = subprocess.run(
            [
                NODE,
                HERE / "js" / "run_client.mjs",
                live_server.url,
                module,
                EXAMPLES / "try_it.js",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    context = result.pop("requests")  # shown when an assertion fails

    assert len(result["tryIt"]) == 7
    for step in result["tryIt"]:
        assert step["actual"] == step["expected"], (step["line"], context)

    assert result["concurrentRefresh"] == [True, True, True]
    assert result["refreshRequests"] == 1
    assert result["postAfterExpiry"] == 201
    assert result["persistent401"] == 401
    assert result["requestsForPersistent401"] == [
        "POST /always-401 401",
        "POST /api/auth/refresh 200",
        "POST /always-401 401",
    ]
    assert result["postWithoutSession"] == 401
    assert result["requestsWithoutSession"] == [
        "POST /api/notes 401",
        "POST /api/auth/refresh 401",
    ]
