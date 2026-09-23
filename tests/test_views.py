import pytest
from django.urls import reverse
from rest_framework.test import APIClient, APIRequestFactory

from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason, TokenFamily
from django_signet.sessions.rotation import RotationPolicy
from django_signet.sessions.stores.cache import CacheTokenStore
from django_signet.tokens.access import AccessToken
from django_signet.transport.cookie import CookiePolicy, CookieTransport
from django_signet.transport.header import HeaderTransport
from django_signet.views import (
    LogoutAllView,
    LogoutView,
    TokenObtainView,
    TokenRefreshView,
    TokenVerifyView,
)

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


def test_logout_without_csrf_header_is_403(client, account):
    """Logout is a state-changing POST carrying an ambient cookie - exactly
    the shape CSRF exists to protect. Every other logout test in this file
    sends a correct CSRF_HEADER and only ever exercises the success path;
    this one omits it so a regression that stopped this endpoint running
    the CSRF check would be caught here rather than leaving every test in
    this file green.

    Final-review change (C1): 401 -> 403. Logout now reads the refresh
    credential through the same ``read_refresh_credential`` refresh uses,
    and so answers a failed CSRF check the way refresh does - 403, cookies
    left in place. The session surviving is asserted as before.
    """
    _login(client)
    response = client.post(reverse("django_signet:logout"))
    assert response.status_code == 403
    assert TokenFamily.objects.get().is_live is True
    assert POLICY.refresh_name not in response.cookies


def test_logout_all_without_csrf_header_is_403(client, account):
    """Final-review change (C1): 401 -> 403, for the reason given on
    ``test_logout_without_csrf_header_is_403``."""
    _login(client)
    response = client.post(reverse("django_signet:logout-all"))
    assert response.status_code == 403
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
    unhandled 500 leaking a traceback, so assert the exact status.

    Final-review change (C1): logout-all no longer authenticates through
    the access token, so ``force_authenticate`` cannot reach it any more;
    the request now carries a real refresh credential from a session
    opened in the cache-backed store it is revoked against.

    Second pass (R1): logout-all now *consumes* the token it is handed, so
    the store is refused before that happens - otherwise the 501 would
    leave the client a spent token whose next refresh reads as theft. The
    final rotation pins that; red on revert of the
    ``supports_revoke_all_for_user`` guard in ``RotationPolicy.revoke_all``."""

    class _CacheBackedRotation(RotationPolicy):
        store = CacheTokenStore()

    class _CacheBackedLogoutAllView(LogoutAllView):
        rotation = _CacheBackedRotation()

    pair = _CacheBackedRotation().open_session(account)
    request = APIRequestFactory().post("/", **{CSRF_HEADER: "t"})
    request.COOKIES[POLICY.refresh_name] = pair.refresh.value
    request.COOKIES[POLICY.csrf_name] = "t"
    response = _CacheBackedLogoutAllView.as_view()(request)
    assert response.status_code == 501
    assert _CacheBackedRotation().rotate(pair.refresh.value).replayed is False


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


# ------------------------------------------- final review, Group C: C1


def test_logout_all_without_an_access_cookie_revokes_every_session(client, account):
    """Logout-all acts on the refresh credential too, so an expired access
    cookie no longer turns it into a silent 401."""
    _login(client)
    _login(APIClient())
    del client.cookies[POLICY.access_name]
    response = client.post(
        reverse("django_signet:logout-all"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert response.status_code == 200
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 0
    assert response.cookies[POLICY.refresh_name]["max-age"] == 0


def test_logout_all_with_a_dead_session_revokes_nothing_else(client, account):
    """An old refresh token from an already-revoked family must not be
    able to log its user out everywhere - replaying it at refresh only
    ever burns its own family."""
    _login(client)
    other = APIClient()
    _login(other)
    TokenFamily.objects.filter(
        pk=AccessToken().verify(client.cookies[POLICY.access_name].value)["sid"]
    ).get().revoke(RevocationReason.ADMIN)

    response = client.post(
        reverse("django_signet:logout-all"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert response.status_code == 401
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 1


class _HeaderLogoutView(LogoutView):
    transport = HeaderTransport()


def test_a_header_transport_client_logs_out_with_its_refresh_token(account):
    """No cookies, no CSRF: a mobile client presents its refresh token as
    a Bearer credential, and that is enough to revoke its session."""
    pair = RotationPolicy().open_session(account)
    request = APIRequestFactory().post(
        "/", HTTP_AUTHORIZATION=f"Bearer {pair.refresh.value}"
    )
    response = _HeaderLogoutView.as_view()(request)
    assert response.status_code == 200
    assert TokenFamily.objects.get().is_live is False


def test_a_header_logout_with_an_access_token_is_401(account):
    """Second pass, minor: an access token presented to header logout
    revoked nothing yet answered 200 "Signed out." A header client has no
    cookies for the response to clear, so that 200 was a false report.
    Red on revert of the non-ambient 401 in ``LogoutView.post``."""
    pair = RotationPolicy().open_session(account)
    request = APIRequestFactory().post(
        "/", HTTP_AUTHORIZATION=f"Bearer {pair.access.value}"
    )
    response = _HeaderLogoutView.as_view()(request)
    assert response.status_code == 401
    assert TokenFamily.objects.get().is_live is True


# ------------------------------------------- final review, Group D: I1, I3

ADM_POLICY = CookiePolicy(prefix="adm")


class _AdmLoginView(TokenObtainView):
    transport = CookieTransport(ADM_POLICY)


class _AdmVerifyView(TokenVerifyView):
    transport = CookieTransport(ADM_POLICY)


def test_verify_authenticates_through_its_own_transport(account):
    """I1: ``TokenVerifyView`` hardcoded ``CookieJWTAuthentication``, which
    reads the *default* cookie names - so a project that customised the
    login view's ``CookiePolicy`` got a 401 from verify for a perfectly
    good session. The view's authenticators are now bound to the view's
    own transport. Red on revert of ``TokenVerifyView.get_authenticators``.
    """
    factory = APIRequestFactory()
    login = _AdmLoginView.as_view()(
        factory.post("/", {"username": "bob", "password": PASSWORD}, format="json")
    )
    request = factory.get("/")
    request.COOKIES[ADM_POLICY.access_name] = login.cookies[
        ADM_POLICY.access_name
    ].value
    assert _AdmVerifyView.as_view()(request).status_code == 200


class _HeaderLoginView(TokenObtainView):
    transport = HeaderTransport()


def test_header_transport_on_a_plain_login_view_works(account):
    """I3, exactly as the migration guide recommends it: ``transport =
    HeaderTransport()`` on the login view. ``set_cookies`` assumed every
    transport carries a CSRF policy and raised ``AttributeError`` - a
    500. The CSRF cookie is now issued only for an ambient transport."""
    response = _HeaderLoginView.as_view()(
        APIRequestFactory().post(
            "/", {"username": "bob", "password": PASSWORD}, format="json"
        )
    )
    assert response.status_code == 200
    assert {"access", "refresh"} <= set(response.data)
    assert not response.cookies
