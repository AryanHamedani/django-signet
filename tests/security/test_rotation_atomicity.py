"""Adversarial suite, part 6: a refresh that fails cannot spend its token.

``rotate()`` used to consume the refresh token and only then sign and
issue the successor. A failure in between - a verify-only deployment with
no ``SIGNING_KEY`` sharing the store, or a failed ``issue()`` - left the
token consumed with no successor ever handed out. The client's retry at a
working server was then a replay of a spent token, and burned its whole
session as reuse. The successor is now signed first, and the consume and
the issue share one transaction.
"""

from __future__ import annotations

import pytest
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError

from django_signet.models import TokenFamily
from django_signet.sessions.rotation import RotationPolicy
from django_signet.sessions.stores.orm import ORMTokenStore
from django_signet.tokens.access import AccessToken

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clean_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password="unused")


class _CannotSign(AccessToken):
    """What a verify-only deployment looks like to ``rotate()``."""

    def mint(self, *args, **kwargs):
        raise ImproperlyConfigured("no SIGNING_KEY on this deployment")


class _VerifyOnlyPolicy(RotationPolicy):
    access_token_class = _CannotSign


def test_a_refresh_that_cannot_sign_leaves_the_token_redeemable(account):
    first = RotationPolicy().open_session(account)

    with pytest.raises(ImproperlyConfigured):
        _VerifyOnlyPolicy().rotate(first.refresh.value)

    # The retry at a server that can sign is a first redemption, not reuse.
    second = RotationPolicy().rotate(first.refresh.value)
    assert second.refresh.value != first.refresh.value
    assert TokenFamily.objects.get().is_live is True


def test_a_failed_issue_rolls_the_consume_back(account, monkeypatch):
    first = RotationPolicy().open_session(account)

    def failing_issue(self, *args, **kwargs):
        raise DatabaseError("the database went away")

    with monkeypatch.context() as patch:
        patch.setattr(ORMTokenStore, "issue", failing_issue)
        with pytest.raises(DatabaseError):
            RotationPolicy().rotate(first.refresh.value)

    second = RotationPolicy().rotate(first.refresh.value)
    assert second.refresh.value != first.refresh.value
    assert TokenFamily.objects.get().is_live is True
