"""Adversarial suite, part 5: ``on_reuse_detected`` cannot undo a burn.

The hook runs after the reuse burn is written but, under
``ATOMIC_REQUESTS``, before it is committed. It used to propagate its
exceptions, so a hook that raised - an alerting call that timed out - took
the request's transaction down with it: refresh, logout and logout-all
answered 500 and the replayed family stayed live, with ``revoked_reason``
still ``None``. A detected theft left the thief's session working.

The hook's exceptions are now logged and ignored, like a signal
receiver's, and the replay is refused with ``TokenReused`` as usual.
"""

from __future__ import annotations

import logging

import pytest
from django.core.cache import cache
from django.db import connection
from django.urls import include, path, reverse
from rest_framework.test import APIClient

from django_signet.csrf import CSRF_HEADER
from django_signet.exceptions import TokenReused
from django_signet.models import RevocationReason, TokenFamily
from django_signet.sessions.rotation import RotationPolicy
from django_signet.transport.cookie import CookiePolicy
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


class _AlertingOutageError(Exception):
    """What a flaky alerting call raises."""


class _PagingPolicy(RotationPolicy):
    grace_cache = None  # every replay is reuse

    def on_reuse_detected(self, family):
        raise _AlertingOutageError("the pager is down")


class _PagingRealm(SignetViewMixin):
    rotation = _PagingPolicy()


urlpatterns = [path("api/auth/", include(signet_urls(_PagingRealm)))]


@pytest.fixture(autouse=True)
def _clean_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


@pytest.fixture
def atomic_requests(monkeypatch):
    """``ATOMIC_REQUESTS=True`` for the default database. Django reads it
    from the connection's settings on every request."""
    monkeypatch.setitem(connection.settings_dict, "ATOMIC_REQUESTS", True)


def _post(endpoint, refresh_value, csrf_value):
    client = APIClient(raise_request_exception=False)
    client.cookies[POLICY.refresh_name] = refresh_value
    client.cookies[POLICY.csrf_name] = csrf_value
    return client.post(
        reverse(f"django_signet:{endpoint}"), **{CSRF_HEADER: csrf_value}
    )


def _spent_token():
    """Log in and refresh once: the first refresh token is now spent, and
    presenting it again is reuse."""
    client = APIClient()
    client.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    spent = client.cookies[POLICY.refresh_name].value
    csrf_value = client.cookies[POLICY.csrf_name].value
    assert _post("refresh", spent, csrf_value).status_code == 200
    return spent, csrf_value


@pytest.mark.urls(__name__)
@pytest.mark.usefixtures("atomic_requests")
@pytest.mark.parametrize("endpoint", ["refresh", "logout", "logout-all"])
def test_a_raising_reuse_hook_does_not_roll_back_the_burn(account, endpoint, caplog):
    spent, csrf_value = _spent_token()

    with caplog.at_level(logging.ERROR, logger="django_signet.sessions.rotation"):
        response = _post(endpoint, spent, csrf_value)

    # The security half first: the replayed family is burned as reuse.
    family = TokenFamily.objects.get()
    assert family.revoked_reason == RevocationReason.REUSE_DETECTED
    # Answered exactly as reuse is with no hook at all: logout is
    # idempotent for a cookie credential, refresh and logout-all refuse.
    assert response.status_code == (200 if endpoint == "logout" else 401)
    records = [r for r in caplog.records if "on_reuse_detected" in r.getMessage()]
    assert len(records) == 1
    assert records[0].exc_info is not None
    assert isinstance(records[0].exc_info[1], _AlertingOutageError)


def test_a_raising_reuse_hook_still_refuses_the_replay(account):
    """Called directly, ``rotate()`` still raises ``TokenReused`` - not
    the hook's exception - and the family is burned."""
    policy = _PagingPolicy()
    first = policy.open_session(account)
    policy.rotate(first.refresh.value)

    with pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)

    first.family.refresh_from_db()
    assert first.family.revoked_reason == RevocationReason.REUSE_DETECTED
