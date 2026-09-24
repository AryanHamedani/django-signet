"""``docs/howto/realms.md``, "Bind a session to its realm": the claim a
realm stamps, checked at refresh and in the realm's views, and its limits.
"""

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import resolve, reverse
from examples.realm_binding_urls import (
    STAFF_COOKIES,
    StaffCookieAuthentication,
    StaffRealm,
)
from rest_framework.test import APIClient

from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason, TokenFamily
from django_signet.tokens.access import AccessToken
from django_signet.transport.cookie import CookiePolicy
from django_signet.urls import signet_urls
from tests.docs.helpers import wire_header

PASSWORD = "pw-not-used-in-assertions"
STAFF = STAFF_COOKIES.policy
DEFAULT = CookiePolicy()
REPORTS = "/staff/api/reports"


@pytest.fixture(autouse=True)
def bound_realm():
    cache.clear()
    with override_settings(ROOT_URLCONF="examples.realm_binding_urls"):
        yield
    cache.clear()


@pytest.fixture
def staff_user(db):
    return get_user_model().objects.create_user(
        username="sam", password=PASSWORD, is_staff=True
    )


def _login(namespace):
    client = APIClient()
    response = client.post(
        reverse(f"{namespace}:login"),
        {"username": "sam", "password": PASSWORD},
        format="json",
    )
    assert response.status_code == 200
    return client, response


def _csrf(value):
    return {wire_header(CSRF_HEADER): value}


@pytest.mark.django_db
def test_a_staff_session_works_and_keeps_its_claim(staff_user):
    client, _ = _login("staff")
    assert AccessToken().verify(client.cookies[STAFF.access_name].value)["realm"] == (
        "staff"
    )
    assert client.get(REPORTS).status_code == 200
    csrf = client.cookies[STAFF.csrf_name].value
    assert client.post(reverse("staff:refresh"), headers=_csrf(csrf)).status_code == 200
    assert client.get(REPORTS).status_code == 200


@pytest.mark.django_db
def test_a_default_access_token_is_refused_at_the_staff_view(staff_user):
    _, login = _login("django_signet")
    client = APIClient()
    client.cookies[STAFF.access_name] = login.cookies[DEFAULT.access_name].value
    assert client.get(REPORTS).status_code == 401


@pytest.mark.django_db
def test_a_default_refresh_token_is_refused_and_its_session_burned(staff_user):
    """Limit 1: ``get_user`` refusing burns the presented session as admin."""
    _, login = _login("django_signet")
    client = APIClient()
    client.cookies[STAFF.refresh_name] = login.cookies[DEFAULT.refresh_name].value
    client.cookies[STAFF.csrf_name] = "t"
    assert client.post(reverse("staff:refresh"), headers=_csrf("t")).status_code == 401
    assert TokenFamily.objects.get().revoked_reason == RevocationReason.ADMIN


@pytest.mark.django_db
def test_staff_verify_still_accepts_a_default_token(staff_user):
    """Limit 2: ``TokenVerifyView`` does not run the realm's
    ``validate_claims``."""
    _, login = _login("django_signet")
    client = APIClient()
    client.cookies[STAFF.access_name] = login.cookies[DEFAULT.access_name].value
    assert client.get(reverse("staff:verify")).status_code == 200


def test_the_realm_sets_no_authentication_classes():
    """Limit 3: a realm attribute reaches all five endpoints, login and
    refresh included, so the check lives on the views' class instead."""
    assert "authentication_classes" not in vars(StaffRealm)
    login = resolve(reverse("staff:login")).func.view_class
    assert login.authentication_classes == ()

    class Misconfigured(StaffRealm):
        authentication_classes = (StaffCookieAuthentication,)

    patterns, _ = signet_urls(Misconfigured, namespace="misconfigured")
    for pattern in patterns:  # login and refresh would authenticate too
        view = pattern.callback.view_class
        assert view.authentication_classes == (StaffCookieAuthentication,)


@pytest.mark.django_db
def test_the_binding_is_one_way(staff_user):
    """The default realm checks nothing: a staff access token copied into
    the default cookie authenticates there."""
    _, login = _login("staff")
    client = APIClient()
    client.cookies[DEFAULT.access_name] = login.cookies[STAFF.access_name].value
    assert client.get(reverse("django_signet:verify")).status_code == 200
