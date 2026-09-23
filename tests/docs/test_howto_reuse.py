"""``docs/howto/reuse-detection.md``: alerting on refresh-token reuse, with
the ``on_reuse_detected`` hook or the ``token_reuse_detected`` signal."""

import logging
import time
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection
from django.test import override_settings
from django.urls import reverse
from examples import reuse_detection
from examples.reuse_detection import AlertingRotationPolicy, alert_on_reuse
from rest_framework.test import APIClient

from django_signet.csrf import CSRF_HEADER
from django_signet.exceptions import TokenReused
from django_signet.models import RevocationReason, TokenFamily
from django_signet.signals import token_reuse_detected
from django_signet.transport.cookie import CookiePolicy
from tests.docs.helpers import wire_header

CREDENTIALS = {"username": "alice", "password": "pw-not-used-in-assertions"}
POLICY = CookiePolicy()
STRICT = {"GRACE_CACHE": None}  # no grace window: every replay is reuse


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def alerts(caplog):
    """The alerts ``send_reuse_alert`` has logged."""
    caplog.set_level(logging.CRITICAL, logger="security")

    def logged():
        return [r for r in caplog.records if r.name == "security"]

    return logged


@pytest.fixture
def alerting_realm():
    with override_settings(ROOT_URLCONF="examples.reuse_detection"):
        yield


def _post(endpoint, refresh, csrf):
    client = APIClient(raise_request_exception=False)
    client.cookies[POLICY.refresh_name] = refresh
    client.cookies[POLICY.csrf_name] = csrf
    return client.post(
        reverse(f"django_signet:{endpoint}"), headers={wire_header(CSRF_HEADER): csrf}
    )


def _spent_token():
    """Log in and refresh once. The login's refresh token is now spent."""
    client = APIClient()
    client.post(reverse("django_signet:login"), CREDENTIALS, format="json")
    spent = client.cookies[POLICY.refresh_name].value
    csrf = client.cookies[POLICY.csrf_name].value
    assert _post("refresh", spent, csrf).status_code == 200
    return spent, csrf


@pytest.mark.django_db
@pytest.mark.usefixtures("alerting_realm")
def test_the_hook_alerts_on_a_replay_outside_the_grace_window(user, alerts):
    with override_settings(SIGNET={"GRACE_WINDOW": timedelta(seconds=1)}):
        spent, csrf = _spent_token()

        # Inside the window a replay is a retry: the same pair, no alert.
        assert _post("refresh", spent, csrf).status_code == 200
        assert alerts() == []

        time.sleep(1.1)  # the grace entry expires with the window
        assert _post("refresh", spent, csrf).status_code == 401

    family = TokenFamily.objects.get()
    assert family.revoked_reason == RevocationReason.REUSE_DETECTED
    [alert] = alerts()
    assert alert.levelno == logging.CRITICAL
    assert str(family.id) in alert.getMessage()
    assert "127.0.0.1" in alert.getMessage()  # the IP the session was opened from


@pytest.mark.django_db
@pytest.mark.usefixtures("alerting_realm")
@pytest.mark.parametrize(
    ("endpoint", "status"), [("refresh", 401), ("logout", 200), ("logout-all", 401)]
)
def test_reuse_is_detected_at_every_refresh_credential_endpoint(
    user, alerts, endpoint, status
):
    with override_settings(SIGNET=STRICT):
        spent, csrf = _spent_token()
        assert _post(endpoint, spent, csrf).status_code == status
    assert len(alerts()) == 1
    assert TokenFamily.objects.get().revoked_reason == RevocationReason.REUSE_DETECTED


@pytest.mark.django_db
@pytest.mark.usefixtures("alerting_realm")
@pytest.mark.parametrize("atomic_requests", [False, True])
def test_a_failing_alert_cannot_undo_the_burn(
    user, monkeypatch, caplog, atomic_requests
):
    def pager_down(family):
        raise TimeoutError("the paging API timed out")

    monkeypatch.setattr(reuse_detection, "send_reuse_alert", pager_down)
    monkeypatch.setitem(connection.settings_dict, "ATOMIC_REQUESTS", atomic_requests)
    with override_settings(SIGNET=STRICT):
        spent, csrf = _spent_token()
        with caplog.at_level(logging.ERROR, logger="django_signet.sessions.rotation"):
            response = _post("refresh", spent, csrf)

    assert response.status_code == 401
    assert TokenFamily.objects.get().revoked_reason == RevocationReason.REUSE_DETECTED
    [record] = [
        r for r in caplog.records if r.name == "django_signet.sessions.rotation"
    ]
    assert record.levelno == logging.ERROR
    assert isinstance(record.exc_info[1], TimeoutError)


class _WritingPolicy(AlertingRotationPolicy):
    def on_reuse_detected(self, family):
        # A database write that fails: the username is taken.
        get_user_model().objects.create(username=family.user.username)


@pytest.mark.django_db(transaction=True)
def test_a_failing_database_write_in_the_hook_rolls_back_the_burn(monkeypatch, user):
    """Pins a limitation the page states: under ``ATOMIC_REQUESTS`` a hook
    whose database write fails marks the request's transaction for
    rollback, and the burn goes with it, although the exception is caught.
    A ``token_reuse_detected`` receiver runs under a savepoint instead."""
    monkeypatch.setattr(reuse_detection.AppRealm, "rotation", _WritingPolicy())
    monkeypatch.setitem(connection.settings_dict, "ATOMIC_REQUESTS", True)
    with override_settings(ROOT_URLCONF="examples.reuse_detection", SIGNET=STRICT):
        spent, csrf = _spent_token()
        assert _post("refresh", spent, csrf).status_code == 401  # still refused
    assert TokenFamily.objects.get().revoked_reason is None  # but not burned


@pytest.mark.django_db
def test_the_hook_sees_the_family_as_it_was_before_the_burn(user):
    seen = []

    class Recording(AlertingRotationPolicy):
        def on_reuse_detected(self, family):
            seen.append(family.revoked_at)

    policy = Recording()
    first = policy.open_session(user)
    policy.rotate(first.refresh.value)
    with override_settings(SIGNET=STRICT), pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    assert seen == [None]
    assert not policy.store.is_live(first.family.id)  # ask the store instead


@pytest.mark.django_db
def test_without_the_burn_the_replay_is_still_refused_and_reported(user, alerts):
    class Detecting(AlertingRotationPolicy):
        burn_family_on_reuse = False

    policy = Detecting()
    first = policy.open_session(user)
    second = policy.rotate(first.refresh.value)
    with override_settings(SIGNET=STRICT), pytest.raises(TokenReused):
        policy.rotate(first.refresh.value)
    assert len(alerts()) == 1
    assert policy.store.is_live(first.family.id)
    assert policy.rotate(second.refresh.value)  # the family refreshes on


@pytest.mark.django_db
def test_the_receiver_alerts_for_the_stock_endpoints(user, alerts):
    """``tests.urls`` mounts the stock views: no realm, no custom policy."""
    token_reuse_detected.connect(alert_on_reuse)
    try:
        with override_settings(SIGNET=STRICT):
            spent, csrf = _spent_token()
            assert _post("refresh", spent, csrf).status_code == 401
    finally:
        token_reuse_detected.disconnect(alert_on_reuse)
    [alert] = alerts()
    assert str(TokenFamily.objects.get().id) in alert.getMessage()
