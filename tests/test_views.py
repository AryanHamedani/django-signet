import pytest
from django.urls import reverse
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason, TokenFamily
from django_signet.sessions.rotation import RotationPolicy
from django_signet.sessions.stores.cache import CacheTokenStore
from django_signet.tokens.access import AccessToken
from django_signet.transport.cookie import CookiePolicy
from django_signet.views import LogoutAllView, TokenObtainView, TokenRefreshView

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


@pytest.fixture
def client():
    return APIClient()


def _login(client, username="bob", password=PASSWORD):
    return client.post(
        reverse("django_signet:login"),
        {"username": username, "password": password},
        format="json",
    )


def test_login_sets_cookies_and_leaks_no_tokens(client, account):
    response = _login(client)
    assert response.status_code == 200
    assert POLICY.access_name in response.cookies
    assert POLICY.refresh_name in response.cookies
    assert POLICY.csrf_name in response.cookies
    body = str(response.data)
    assert "eyJ" not in body  # no JWT anywhere in the response body


def test_login_with_bad_credentials_is_rejected(client, account):
    assert _login(client, password="wrong").status_code == 400


def test_unknown_username_and_wrong_password_are_indistinguishable(client, account):
    """A weaker test would only check that both are 400 - which a broken
    implementation that used two different messages (e.g. "no such user"
    vs. "wrong password") would still pass, defeating the anti-enumeration
    guarantee. Compare the bodies for equality, not just the status code."""
    unknown_user = _login(client, username="not-a-real-user", password="whatever")
    wrong_password = _login(client, password="wrong")
    assert unknown_user.status_code == wrong_password.status_code == 400
    assert unknown_user.data == wrong_password.data


def test_refresh_rotates_the_cookies(client, account):
    _login(client)
    before = client.cookies[POLICY.refresh_name].value
    # Round-1 security-review fix: refresh is CSRF-protected now (see
    # tests/security/test_session_attacks.py), so a matching header is
    # needed to reach the rotation this test actually checks.
    response = client.post(
        reverse("django_signet:refresh"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert response.status_code == 200
    assert client.cookies[POLICY.refresh_name].value != before


def test_refresh_without_a_cookie_is_401(client):
    assert client.post(reverse("django_signet:refresh")).status_code == 401


def test_a_failed_refresh_clears_the_cookies(client, account):
    """A dead session must not loop: clear the cookies on the way out.

    Checking status_code == 401 alone would pass a broken implementation
    that never cleared anything. Checking max-age == 0 alone would still
    pass one that cleared the right names at the wrong path - which the
    browser silently ignores for a __Host--prefixed cookie, or which
    simply never matches for the path-scoped refresh cookie - so the
    "clear" would be a no-op in a real browser despite looking correct
    here. Assert both the max-age and the path together.
    """
    _login(client)
    csrf_token = client.cookies[POLICY.csrf_name].value
    client.cookies[POLICY.refresh_name] = "not-a-real-token"
    # Round-1 security-review fix: refresh is CSRF-protected now; a
    # matching header is needed to reach the invalid-credential path this
    # test actually checks, rather than being turned away by CSRF first.
    response = client.post(
        reverse("django_signet:refresh"), **{CSRF_HEADER: csrf_token}
    )
    assert response.status_code == 401
    assert response.cookies[POLICY.access_name]["max-age"] == 0
    assert response.cookies[POLICY.access_name]["path"] == "/"
    assert response.cookies[POLICY.refresh_name]["max-age"] == 0
    assert response.cookies[POLICY.refresh_name]["path"] == POLICY.refresh_path


def test_logout_revokes_the_family(client, account):
    _login(client)
    response = client.post(
        reverse("django_signet:logout"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert response.status_code == 200
    family = TokenFamily.objects.get()
    assert family.is_live is False
    assert family.revoked_reason == RevocationReason.LOGOUT


def test_logout_without_csrf_header_is_401(client, account):
    """Logout is a state-changing, cookie-authenticated POST - exactly the
    shape CSRF exists to protect. Every other logout test in this file
    sends a correct CSRF_HEADER and only ever exercises the success path;
    this one omits it so a regression that stopped this endpoint going
    through CSRF-checked authentication (e.g. enforce_csrf=False on a
    subclass, or swapping CookieJWTAuthentication for something CSRF-blind)
    would be caught here rather than leaving every test in this file green.
    """
    _login(client)
    response = client.post(reverse("django_signet:logout"))
    assert response.status_code == 401
    assert TokenFamily.objects.get().is_live is True


def test_logout_all_without_csrf_header_is_401(client, account):
    _login(client)
    response = client.post(reverse("django_signet:logout-all"))
    assert response.status_code == 401
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 1


def test_logout_all_revokes_every_session(client, account):
    _login(client)
    second = APIClient()
    _login(second)
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 2

    client.post(
        reverse("django_signet:logout-all"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 0


def test_verify_reports_the_session_state(client, account):
    _login(client)
    response = client.get(reverse("django_signet:verify"))
    assert response.status_code == 200
    assert response.data["authenticated"] is True


def test_verify_without_credentials_is_401(client):
    assert client.get(reverse("django_signet:verify")).status_code == 401


def test_logout_all_returns_501_when_the_store_cannot_enumerate(account):
    """``CacheTokenStore.revoke_all_for_user`` raises ``NotImplementedError``
    by design - a documented limitation, not a crash. A checked-only-for-
    200/404 test would miss the difference between a clean 501 and an
    unhandled 500 leaking a traceback, so assert the exact status."""

    class _CacheBackedRotation(RotationPolicy):
        store = CacheTokenStore()

    class _CacheBackedLogoutAllView(LogoutAllView):
        rotation = _CacheBackedRotation()

    request = APIRequestFactory().post("/")
    force_authenticate(request, user=account)
    response = _CacheBackedLogoutAllView.as_view()(request)
    assert response.status_code == 501


# ------------------------------------------- final review, Group A: I2


class _OrgClaims:
    """Shared by the login and refresh views below, exactly as a project
    would share one ``get_claims`` between the two endpoints."""

    def get_claims(self, user):
        return {"org": "acme"}


class _ClaimsLoginView(_OrgClaims, TokenObtainView):
    pass


class _ClaimsRefreshView(_OrgClaims, TokenRefreshView):
    pass


def test_a_custom_claim_survives_a_refresh(account):
    """I2: ``get_claims()`` used to run only at login, so every custom
    claim silently vanished from the access token after the first
    refresh. The refresh path must re-derive claims from the user it
    loads, not drop them. Red on revert of the ``get_claims=`` argument
    ``TokenRefreshView.post`` passes to ``RotationPolicy.rotate``."""
    factory = APIRequestFactory()
    login = _ClaimsLoginView.as_view()(
        factory.post("/", {"username": "bob", "password": PASSWORD}, format="json")
    )
    assert AccessToken().verify(login.cookies[POLICY.access_name].value)["org"] == (
        "acme"
    )

    csrf_value = login.cookies[POLICY.csrf_name].value
    request = factory.post("/", **{CSRF_HEADER: csrf_value})
    request.COOKIES[POLICY.refresh_name] = login.cookies[POLICY.refresh_name].value
    request.COOKIES[POLICY.csrf_name] = csrf_value
    refreshed = _ClaimsRefreshView.as_view()(request)

    assert refreshed.status_code == 200
    claims = AccessToken().verify(refreshed.cookies[POLICY.access_name].value)
    assert claims["org"] == "acme"
