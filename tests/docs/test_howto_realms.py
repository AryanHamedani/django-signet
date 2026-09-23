"""``docs/howto/realms.md``: a staff realm, and what does and does not
separate it from the default one.

The last group of tests pins the page's boundary findings. Each shows a
token issued by one realm being accepted by another, or refused only by
the permission class, so a change to that behaviour fails here and sends
the reader's attention back to the page.
"""

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from examples.realms_urls import STAFF_COOKIES, StaffCookieAuthentication, StaffRealm
from rest_framework.permissions import IsAdminUser
from rest_framework.test import APIClient

from django_signet.checks import check_refresh_cookie_path
from django_signet.csrf import CSRF_HEADER
from django_signet.models import TokenFamily
from django_signet.tokens.access import AccessToken
from django_signet.transport.cookie import CookiePolicy
from tests.docs.helpers import wire_header

PASSWORD = "pw-not-used-in-assertions"  # the root conftest's `user` fixture
CREDENTIALS = {"username": "alice", "password": PASSWORD}
STAFF = STAFF_COOKIES.policy
REPORTS = "/staff/api/reports"


@pytest.fixture(autouse=True)
def realms():
    cache.clear()
    with override_settings(ROOT_URLCONF="examples.realms_urls"):
        yield
    cache.clear()


@pytest.fixture
def staff_user(db):
    return get_user_model().objects.create_user(
        username="sam", password=PASSWORD, is_staff=True
    )


def _csrf(value):
    return {wire_header(CSRF_HEADER): value}


def _login(namespace, username="alice"):
    client = APIClient()
    response = client.post(
        reverse(f"{namespace}:login"),
        {"username": username, "password": PASSWORD},
        format="json",
    )
    assert response.status_code == 200
    return client, response


# ------------------------------------------------------------ the example


def test_the_realm_and_the_authentication_class_share_one_transport():
    assert StaffRealm.transport is STAFF_COOKIES
    assert StaffCookieAuthentication.transport is STAFF_COOKIES
    assert (STAFF.access_name, STAFF.refresh_name, STAFF.csrf_name) == (
        "__Host-staff-access",
        "__Secure-staff-refresh",
        "__Host-staff-csrf",
    )


@pytest.mark.django_db
def test_the_staff_realm_sets_its_own_cookies(staff_user):
    _, login = _login("staff", "sam")
    assert set(login.cookies) == {
        STAFF.access_name,
        STAFF.refresh_name,
        STAFF.csrf_name,
    }
    assert login.cookies[STAFF.refresh_name]["path"] == "/staff/auth/"
    assert login.cookies[STAFF.access_name]["path"] == "/"
    assert login.cookies[STAFF.csrf_name]["path"] == "/"


def test_policy_fields_you_do_not_pass_follow_the_settings():
    with override_settings(SIGNET={"COOKIE_SECURE": False}):
        assert STAFF.access_name == "staff-access"
    # An explicit name is used verbatim by every policy that does not pass
    # its own, so it would give both realms the same access cookie.
    with override_settings(SIGNET={"COOKIE_ACCESS_NAME": "session"}):
        assert STAFF.access_name == CookiePolicy().access_name == "session"


@pytest.mark.django_db
def test_staff_views_read_the_staff_cookies(staff_user):
    client, _ = _login("staff", "sam")
    assert client.get(REPORTS).status_code == 200

    default_only, _ = _login("django_signet", "sam")
    assert default_only.get(REPORTS).status_code == 401  # no staff cookie


@pytest.mark.django_db
def test_the_permission_class_refuses_a_non_staff_user(user):
    """Login at the staff realm does not check ``is_staff``: the permission
    class on the view does, on every request."""
    client, _ = _login("staff")
    assert client.get(reverse("staff:verify")).status_code == 200
    assert client.get(REPORTS).status_code == 403


@pytest.mark.django_db
def test_the_permission_reads_the_user_as_it_is_now(staff_user):
    client, _ = _login("staff", "sam")
    assert client.get(REPORTS).status_code == 200
    get_user_model().objects.filter(pk=staff_user.pk).update(is_staff=False)
    assert client.get(REPORTS).status_code == 403  # same, unexpired token


def test_the_reports_view_pairs_the_realm_with_a_permission_class():
    from examples.realms_urls import StaffReportView

    assert StaffReportView.authentication_classes == (StaffCookieAuthentication,)
    assert StaffReportView.permission_classes == (IsAdminUser,)


@pytest.mark.django_db
def test_each_realm_checks_its_own_csrf_cookie(staff_user):
    client, staff_login = _login("staff", "sam")
    _, default_login = _login("django_signet", "sam")
    wrong = default_login.cookies[CookiePolicy().csrf_name].value
    right = staff_login.cookies[STAFF.csrf_name].value
    assert (
        client.post(reverse("staff:refresh"), headers=_csrf(wrong)).status_code == 403
    )
    assert (
        client.post(reverse("staff:refresh"), headers=_csrf(right)).status_code == 200
    )


def test_the_staff_mount_matches_its_own_refresh_path():
    assert check_refresh_cookie_path(None) == []


# -------------------------------------------- what does not separate realms


@pytest.mark.django_db
def test_a_default_token_under_the_staff_name_authenticates(user, staff_user):
    """Cookie names separate what a browser sends, not what verifies."""
    for username, reports in (("alice", 403), ("sam", 200)):
        _, login = _login("django_signet", username)
        client = APIClient()
        client.cookies[STAFF.access_name] = login.cookies[
            CookiePolicy().access_name
        ].value
        assert client.get(reverse("staff:verify")).status_code == 200
        assert client.get(REPORTS).status_code == reports  # the permission decides


@pytest.mark.django_db
def test_a_default_refresh_token_redeems_at_the_staff_realm(user):
    """One store for every realm: the session opened at the default realm
    is refreshed at the staff realm, and comes back as staff cookies."""
    _, login = _login("django_signet")
    client = APIClient()
    client.cookies[STAFF.refresh_name] = login.cookies[
        CookiePolicy().refresh_name
    ].value
    client.cookies[STAFF.csrf_name] = "t"
    refreshed = client.post(reverse("staff:refresh"), headers=_csrf("t"))
    assert refreshed.status_code == 200
    assert STAFF.access_name in refreshed.cookies
    assert TokenFamily.objects.count() == 1  # the same session, not a new one
    assert client.get(REPORTS).status_code == 403  # alice is not staff


@pytest.mark.django_db
def test_the_audience_is_one_setting_for_every_realm(user):
    with override_settings(SIGNET={"AUDIENCE": "api.example.com"}):
        _, login = _login("django_signet")
        access = login.cookies[CookiePolicy().access_name].value
        assert AccessToken().verify(access)["aud"] == "api.example.com"
        client = APIClient()
        client.cookies[STAFF.access_name] = access
        assert client.get(reverse("staff:verify")).status_code == 200


@pytest.mark.django_db
def test_a_header_view_accepts_any_realms_access_token(user):
    """``HeaderJWTAuthentication`` reads ``Authorization: Bearer``, whichever
    realm minted the token - here the cookie realm of the header example."""
    with override_settings(ROOT_URLCONF="examples.header_urls"):
        _, login = _login("django_signet")
        access = login.cookies[CookiePolicy().access_name].value
        me = APIClient().get(
            reverse("me"), headers={"Authorization": f"Bearer {access}"}
        )
        assert me.status_code == 200


@pytest.mark.django_db
def test_logout_all_at_one_realm_ends_the_sessions_of_every_realm(user):
    _login("django_signet")
    client, staff_login = _login("staff")
    csrf = staff_login.cookies[STAFF.csrf_name].value
    assert (
        client.post(reverse("staff:logout-all"), headers=_csrf(csrf)).status_code == 200
    )
    assert [family.is_live for family in TokenFamily.objects.all()] == [False, False]
