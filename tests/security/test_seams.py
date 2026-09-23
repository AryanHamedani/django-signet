"""Adversarial suite, part 3: the seams between correct components.

Every module this library ships passed its own review in isolation. The
defects pinned here lived *between* them - the refresh path that never
asked the authentication layer's question ("is this user still active?"),
the store chosen three different ways in three different modules, the
logout endpoint that could not see the credential it needed to revoke.

Same rule as parts 1 and 2: each test names the production line that,
reverted, turns it red - and each was confirmed red by actually reverting
that line, not by reasoning about it.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from django_signet.csrf import CSRF_HEADER
from django_signet.models import TokenFamily
from django_signet.transport.cookie import CookiePolicy

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


def _login(username="bob", password=PASSWORD):
    c = APIClient()
    c.post(
        reverse("django_signet:login"),
        {"username": username, "password": password},
        format="json",
    )
    return c


def _refresh(client, refresh_value, csrf_value):
    """Present an explicit refresh/CSRF pair, independent of whatever the
    client's cookie jar was left holding by an earlier response."""
    client.cookies[POLICY.refresh_name] = refresh_value
    client.cookies[POLICY.csrf_name] = csrf_value
    return client.post(reverse("django_signet:refresh"), **{CSRF_HEADER: csrf_value})


# ------------------------------------------------ Group A: C3 (Critical)


def test_refresh_for_a_disabled_account_is_rejected_and_burns_the_family(account):
    """CVE-2024-22513 at the *issuance* layer. The access-token half of
    this bug is pinned by ``test_disabling_an_account_revokes_access_
    immediately``; this is the half nobody was checking. Before the fix,
    ``RotationPolicy.rotate()`` never loaded the user at all, so a
    disabled account's refresh returned 200 with a freshly signed access
    token - which any verifier outside this library's authentication
    classes (an RS256 consumer in another service) would accept.

    The second half pins the ruling that the family is burned, not merely
    refused: reactivating the account must not revive the old session.
    The original refresh value is re-presented explicitly, because the
    401 above cleared the client's cookie jar and a cleared cookie would
    fail for the wrong reason.

    Red on revert of: the ``self._active_user(claims)`` call in
    ``RotationPolicy.rotate`` (first assertion flips to 200), and of the
    ``_revoke_named_family`` call inside ``_active_user`` (the family
    stays live and the post-reactivation refresh succeeds).
    """
    client = _login()
    refresh_value = client.cookies[POLICY.refresh_name].value
    csrf_value = client.cookies[POLICY.csrf_name].value

    account.is_active = False
    account.save(update_fields=["is_active"])
    assert _refresh(client, refresh_value, csrf_value).status_code == 401
    assert TokenFamily.objects.get().is_live is False

    account.is_active = True
    account.save(update_fields=["is_active"])
    assert _refresh(client, refresh_value, csrf_value).status_code == 401
