"""Adversarial suite, part 4: a signal receiver cannot change an outcome.

Signals exist for observability - logging, metrics, alerting. Every one of
them used to be sent with ``Signal.send()``, which propagates a receiver's
exception to the caller. ``family_revoked`` fires inside the transaction
``RotationPolicy._redeem`` opens around the consume and the revocation, so
a receiver that raised rolled both back: logout answered 500, the family
stayed live, and the next refresh succeeded. A flaky alerting hook defeated
logout. ``token_issued`` fires after login has created the session, so a
raising receiver turned a successful login into a 500 with a live session
behind it.

Every test here connects a receiver that raises and asserts the
authentication outcome is exactly what it would be with no receiver at
all. Red on revert of ``django_signet.signals.send`` to ``Signal.send``.
"""

from __future__ import annotations

import contextlib
import logging

import pytest
from django.core.cache import cache
from django.urls import reverse
from rest_framework.test import APIClient

from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason, TokenFamily
from django_signet.signals import (
    family_revoked,
    token_issued,
    token_refreshed,
    token_reuse_detected,
)
from django_signet.transport.cookie import CookiePolicy

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"
_CACHE_STORE = "django_signet.sessions.stores.cache.CacheTokenStore"


class _AlertingOutageError(Exception):
    """What a flaky alerting hook raises."""


def _flaky_receiver(sender, **kwargs):
    raise _AlertingOutageError("the pager is down")


@pytest.fixture(autouse=True)
def _clean_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


@contextlib.contextmanager
def _raising(signal):
    signal.connect(_flaky_receiver, dispatch_uid="signet-test-flaky")
    try:
        yield
    finally:
        signal.disconnect(dispatch_uid="signet-test-flaky")


def _client():
    """A client that reports a server error as a 500, as a browser sees
    it, instead of re-raising the view's exception into the test."""
    return APIClient(raise_request_exception=False)


def _login(client=None):
    client = client or _client()
    response = client.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    return client, response


def _present(endpoint, refresh_value, csrf_value):
    client = _client()
    client.cookies[POLICY.refresh_name] = refresh_value
    client.cookies[POLICY.csrf_name] = csrf_value
    return client.post(
        reverse(f"django_signet:{endpoint}"), **{CSRF_HEADER: csrf_value}
    )


def _credentials(client):
    return (
        client.cookies[POLICY.refresh_name].value,
        client.cookies[POLICY.csrf_name].value,
    )


def test_a_raising_family_revoked_receiver_does_not_undo_a_logout(account):
    """The probed defect: the receiver raised inside ``_redeem``'s
    transaction, rolling back the consume and the revocation together.
    Logout must still answer 200, the family must be revoked as a logout,
    and the refresh token that was logged out must no longer refresh."""
    client, _ = _login()
    refresh, csrf_value = _credentials(client)

    with _raising(family_revoked):
        response = _present("logout", refresh, csrf_value)

    # The security half first, so a regression reports the live session
    # rather than only the 500 in front of it.
    family = TokenFamily.objects.get()
    assert family.revoked_reason == RevocationReason.LOGOUT
    assert _present("refresh", refresh, csrf_value).status_code == 401
    assert response.status_code == 200


def test_a_raising_family_revoked_receiver_does_not_fail_a_cache_store_logout(
    account, settings
):
    """``CacheTokenStore`` sends ``family_revoked`` itself, from its own
    ``revoke_family``. Its revocation marker is written before the signal
    and no transaction covers the cache, so the session did die - but the
    logout still answered 500."""
    settings.SIGNET = {"STORE": _CACHE_STORE}
    client, _ = _login()
    refresh, csrf_value = _credentials(client)

    with _raising(family_revoked):
        response = _present("logout", refresh, csrf_value)

    assert _present("refresh", refresh, csrf_value).status_code == 401
    assert response.status_code == 200


def test_a_raising_family_revoked_receiver_does_not_undo_a_logout_all(account):
    """Logout-all revokes every family inside the same ``_redeem``
    transaction, one ``family_revoked`` per family: the first raise used to
    roll back every revocation, not only its own."""
    client, _ = _login()
    _login()
    refresh, csrf_value = _credentials(client)

    with _raising(family_revoked):
        response = _present("logout-all", refresh, csrf_value)

    assert TokenFamily.objects.count() == 2
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 0
    assert response.status_code == 200


def test_a_raising_family_revoked_receiver_does_not_block_password_revocation(
    account,
):
    """Password-change revocation runs in a ``pre_save`` receiver that
    revokes each family in turn. A raising ``family_revoked`` receiver
    used to escape it after the first family, leaving the rest live and
    refusing the password change."""
    _login()
    _login()

    with _raising(family_revoked):
        account.set_password("a-new-password-entirely")
        account.save()

    account.refresh_from_db()
    assert account.check_password("a-new-password-entirely")
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 0


def test_a_raising_token_issued_receiver_does_not_fail_a_login(account):
    """``token_issued`` fires after the session exists: a raise here used
    to answer 500 with a live session behind it that the client was never
    handed."""
    with _raising(token_issued):
        _, response = _login()

    assert response.status_code == 200
    assert POLICY.refresh_name in response.cookies
    assert TokenFamily.objects.get().is_live is True


def test_a_raising_token_refreshed_receiver_does_not_fail_a_refresh(account):
    """``token_refreshed`` fires after the old token is consumed and its
    successor issued: a raise here used to withhold the successor, so the
    client's next refresh presented a spent token."""
    client, _ = _login()
    refresh, csrf_value = _credentials(client)

    with _raising(token_refreshed):
        response = _present("refresh", refresh, csrf_value)

    assert response.status_code == 200
    successor = response.cookies[POLICY.refresh_name].value
    assert successor != refresh
    assert _present("refresh", successor, csrf_value).status_code == 200


def test_a_raising_token_reuse_detected_receiver_does_not_fail_detection(account):
    """``token_reuse_detected`` fires during the burn: a raise here used to
    skip the ``on_reuse_detected`` hook and turn the replay's 401 into a
    500. The family must be burned and the replay refused as usual."""
    client, _ = _login()
    old, csrf_value = _credentials(client)
    assert _present("refresh", old, csrf_value).status_code == 200
    cache.clear()  # the grace window has passed

    with _raising(token_reuse_detected):
        response = _present("refresh", old, csrf_value)

    assert response.status_code == 401
    family = TokenFamily.objects.get()
    assert family.revoked_reason == RevocationReason.REUSE_DETECTED


def test_a_raising_receiver_is_logged_with_its_traceback(account, caplog):
    """Swallowing the exception is only safe if it is not also silent: it
    is logged at ``error``, naming the signal and the receiver, with the
    receiver's own traceback attached."""
    with (
        caplog.at_level(logging.ERROR, logger="django_signet.signals"),
        _raising(token_issued),
    ):
        _login()

    records = [r for r in caplog.records if r.name == "django_signet.signals"]
    assert len(records) == 1
    record = records[0]
    assert record.levelno == logging.ERROR
    message = record.getMessage()
    assert "token_issued" in message
    assert f"{__name__}._flaky_receiver" in message
    assert record.exc_info is not None
    assert isinstance(record.exc_info[1], _AlertingOutageError)
    assert record.exc_info[2] is not None
