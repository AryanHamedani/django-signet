"""Final review, Group D: configuration has one source of truth (I1, I3).

A "realm" is one ``SignetViewMixin`` subclass - transport, rotation policy
and hooks declared once - and ``signet_urls()`` builds the five endpoints
from it, so they cannot disagree with each other.
"""

from __future__ import annotations

import pytest
from django.core.cache import cache
from django.test import override_settings
from django.urls import include, path, reverse
from rest_framework.test import APIClient, APIRequestFactory

from django_signet.checks import check_refresh_cookie_path
from django_signet.csrf import CSRF_HEADER
from django_signet.models import TokenFamily
from django_signet.tokens.access import AccessToken
from django_signet.transport.cookie import CookiePolicy, CookieTransport
from django_signet.transport.header import HeaderTransport, HybridTransport
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin

pytestmark = pytest.mark.django_db
PASSWORD = "correct-horse-battery-staple"
STAFF_POLICY = CookiePolicy(prefix="adm", refresh_path="/api/auth/staff/")


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


class StaffRealm(SignetViewMixin):
    transport = CookieTransport(STAFF_POLICY)

    def get_claims(self, user):
        return {"realm": "staff"}


class MobileRealm(SignetViewMixin):
    transport = HeaderTransport()


def _urlconf(*patterns, default_at="api/auth/"):
    """A throwaway ROOT_URLCONF: any hashable object with ``urlpatterns``."""
    default = path(default_at, include("django_signet.urls"))
    return type("URLConf", (), {"urlpatterns": [default, *patterns]})


STAFF_URLS = _urlconf(
    path("api/auth/staff/", include(signet_urls(StaffRealm, namespace="staff")))
)
MOBILE_URLS = _urlconf(
    path("api/mobile/", include(signet_urls(MobileRealm, namespace="mobile")))
)


def _credentials():
    return {"username": "bob", "password": PASSWORD}


# ------------------------------------------------------ I1: one realm


def test_signet_urls_builds_every_endpoint_from_one_realm():
    patterns, namespace = signet_urls(StaffRealm, namespace="staff")
    assert namespace == "staff"
    assert [p.name for p in patterns] == [
        "login",
        "refresh",
        "verify",
        "logout",
        "logout-all",
    ]
    for pattern in patterns:
        view_class = pattern.callback.view_class
        assert issubclass(view_class, StaffRealm)
        assert view_class.transport is StaffRealm.transport


def test_the_default_urls_are_the_stock_views_unchanged():
    """Zero-config stays zero-config: no realm, no generated classes."""
    from django_signet import urls, views

    assert [p.callback.view_class for p in urls.urlpatterns] == [
        views.TokenObtainView,
        views.TokenRefreshView,
        views.TokenVerifyView,
        views.LogoutView,
        views.LogoutAllView,
    ]
    assert urls.app_name == "django_signet"


@override_settings(ROOT_URLCONF=STAFF_URLS)
def test_a_custom_realm_works_end_to_end(account):
    """Declared once, it cannot drift: login, refresh, verify and logout of
    the staff realm all use the adm- cookies, and the realm's
    ``get_claims`` survives the refresh."""
    client = APIClient()
    assert (
        client.post(reverse("staff:login"), _credentials(), format="json").status_code
        == 200
    )
    assert STAFF_POLICY.access_name in client.cookies
    csrf = {CSRF_HEADER: client.cookies[STAFF_POLICY.csrf_name].value}

    assert client.post(reverse("staff:refresh"), **csrf).status_code == 200
    claims = AccessToken().verify(client.cookies[STAFF_POLICY.access_name].value)
    assert claims["realm"] == "staff"
    assert client.get(reverse("staff:verify")).status_code == 200

    # refresh rotated the CSRF cookie too; echo the current one
    csrf = {CSRF_HEADER: client.cookies[STAFF_POLICY.csrf_name].value}
    assert client.post(reverse("staff:logout"), **csrf).status_code == 200
    assert TokenFamily.objects.get().is_live is False


# -------------------------------------------- I1: refresh_path vs mount


@override_settings(ROOT_URLCONF=STAFF_URLS)
def test_a_refresh_path_matching_every_mount_is_quiet():
    assert check_refresh_cookie_path(None) == []


@override_settings(ROOT_URLCONF=_urlconf(default_at="auth/"))
def test_mounting_the_default_urls_off_the_refresh_path_is_an_error():
    """Mounting at ``/auth/`` with the default ``/api/auth/`` refresh path
    means a real browser never sends the refresh cookie to refresh or
    logout - silent refresh failures in production. Caught at startup."""
    messages = check_refresh_cookie_path(None)
    assert {m.id for m in messages} == {"signet.E008"}
    assert len(messages) == 3  # refresh, logout, logout-all
    assert "/auth/refresh" in " ".join(m.msg for m in messages)


@override_settings(
    ROOT_URLCONF=_urlconf(
        path("api/staff/", include(signet_urls(StaffRealm, namespace="staff")))
    )
)
def test_mounting_a_realm_off_its_own_refresh_path_is_an_error():
    messages = check_refresh_cookie_path(None)
    assert [m.id for m in messages] == ["signet.E008"] * 3
    assert all("StaffRealm" in m.msg for m in messages)


@pytest.mark.parametrize(("mount", "errors"), [("api/authn/", 3), ("api/auth/", 0)])
def test_a_refresh_path_covers_urls_only_at_a_path_boundary(settings, mount, errors):
    """Browsers match a cookie's ``Path`` at ``/`` boundaries (RFC 6265
    5.1.4): ``Path=/api/auth`` reaches ``/api/auth/refresh`` but not
    ``/api/authn/refresh``, although the string is a prefix of both. E008
    used ``str.startswith`` and called the second mount covered."""
    settings.ROOT_URLCONF = _urlconf(default_at=mount)
    settings.SIGNET = {"COOKIE_REFRESH_PATH": "/api/auth"}
    assert [m.id for m in check_refresh_cookie_path(None)] == ["signet.E008"] * errors


@override_settings(ROOT_URLCONF=MOBILE_URLS)
def test_a_header_realm_has_no_cookie_path_to_check():
    assert check_refresh_cookie_path(None) == []


# --------------------------------------------------- I3: header mode


def _bearer(value):
    return {"HTTP_AUTHORIZATION": f"Bearer {value}"}


@override_settings(ROOT_URLCONF=MOBILE_URLS)
def test_header_mode_login_returns_tokens_and_sets_no_cookies(account):
    """I3: ``set_cookies`` assumed every transport has a CSRF policy, so a
    ``HeaderTransport`` login raised ``AttributeError`` - a 500. The CSRF
    cookie is now issued only for an ambient transport."""
    response = APIClient().post(reverse("mobile:login"), _credentials(), format="json")
    assert response.status_code == 200
    assert {"access", "refresh"} <= set(response.data)
    assert not response.cookies


@override_settings(ROOT_URLCONF=MOBILE_URLS)
def test_header_mode_refresh_rotates_through_the_body(account):
    client = APIClient()
    tokens = client.post(reverse("mobile:login"), _credentials(), format="json").data
    response = client.post(reverse("mobile:refresh"), **_bearer(tokens["refresh"]))
    assert response.status_code == 200
    assert response.data["refresh"] != tokens["refresh"]
    assert not response.cookies


@override_settings(ROOT_URLCONF=MOBILE_URLS)
def test_header_mode_verify_and_logout_work(account):
    client = APIClient()
    tokens = client.post(reverse("mobile:login"), _credentials(), format="json").data
    assert (
        client.get(reverse("mobile:verify"), **_bearer(tokens["access"])).status_code
        == 200
    )

    response = client.post(reverse("mobile:logout"), **_bearer(tokens["refresh"]))
    assert response.status_code == 200
    assert TokenFamily.objects.get().is_live is False


# ----------------------------------------------- Group F: I4, hybrid


class HybridRealm(SignetViewMixin):
    transport = HybridTransport()


def test_a_hybrid_header_refresh_returns_its_successor_only_as_a_cookie(account):
    """I4 pins the actual behaviour, which the docstring used to overstate
    ("serves a browser SPA and a mobile app"). A header-based refresh
    through ``HybridTransport`` consumes the presented token and writes
    the successor only into ``Set-Cookie`` - which a mobile client never
    reads - so that client's session is gone. Hybrid is a cookie transport
    that also *reads* a header for authentication; mobile and service
    clients belong on ``HeaderTransport``. If full mobile support lands in
    hybrid later, this test is the one that has to change."""
    from django_signet.hashing import token_digest
    from django_signet.models import IssuedToken
    from django_signet.sessions.rotation import RotationPolicy

    pair = RotationPolicy().open_session(account)
    request = APIRequestFactory().post(
        "/", HTTP_AUTHORIZATION=f"Bearer {pair.refresh.value}"
    )
    patterns, _ = signet_urls(HybridRealm, namespace="hybrid")
    response = patterns[1].callback(request)  # refresh

    assert response.status_code == 200
    assert "refresh" not in response.data
    assert "access" not in response.data
    assert HybridRealm.transport.cookie.policy.refresh_name in response.cookies
    consumed = IssuedToken.objects.get(digest=token_digest(pair.refresh.value))
    assert consumed.consumed_at is not None
