"""``docs/howto/custom-claims.md``: ``get_claims`` on a realm, re-derived at
every refresh, and what happens to a claim that collides with a reserved one.
"""

import pytest
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.test import override_settings
from django.urls import resolve, reverse
from examples.claims_urls import AppRealm
from rest_framework.test import APIClient

from django_signet.checks import check_refresh_cookie_path
from django_signet.csrf import CSRF_HEADER
from django_signet.exceptions import TokenInvalid
from django_signet.sessions.rotation import RotationPolicy
from django_signet.tokens.access import AccessToken
from django_signet.tokens.refresh import RefreshToken
from django_signet.transport.cookie import CookiePolicy
from tests.docs.helpers import wire_header

CREDENTIALS = {"username": "alice", "password": "pw-not-used-in-assertions"}
POLICY = CookiePolicy()


@pytest.fixture(autouse=True)
def claims_realm():
    cache.clear()
    with override_settings(ROOT_URLCONF="examples.claims_urls"):
        yield
    cache.clear()


def _refresh(client):
    csrf = client.cookies[POLICY.csrf_name].value
    return client.post(
        reverse("django_signet:refresh"), headers={wire_header(CSRF_HEADER): csrf}
    )


def _claims(client):
    return AccessToken().verify(client.cookies[POLICY.access_name].value)


@pytest.mark.django_db
def test_a_claim_changes_at_the_next_refresh(user):
    client = APIClient()
    client.post(reverse("django_signet:login"), CREDENTIALS, format="json")
    assert client.get("/api/groups").json() == {"groups": []}

    user.groups.add(Group.objects.create(name="editors"))
    # The access token already issued still carries the old value...
    assert client.get("/api/groups").json() == {"groups": []}

    # ...and the next refresh derives it again, from the user as it is now.
    assert _refresh(client).status_code == 200
    assert client.get("/api/groups").json() == {"groups": ["editors"]}
    refresh = RefreshToken().verify(client.cookies[POLICY.refresh_name].value)
    assert refresh["groups"] == ["editors"]  # both tokens carry it


@pytest.mark.django_db
def test_a_grace_window_retry_returns_the_first_refreshs_claims(user):
    client = APIClient()
    client.post(reverse("django_signet:login"), CREDENTIALS, format="json")
    spent = client.cookies[POLICY.refresh_name].value
    csrf = client.cookies[POLICY.csrf_name].value
    assert _refresh(client).status_code == 200
    first = client.cookies[POLICY.access_name].value

    user.groups.add(Group.objects.create(name="editors"))
    retry = APIClient()
    retry.cookies[POLICY.refresh_name] = spent
    retry.cookies[POLICY.csrf_name] = csrf
    assert _refresh(retry).status_code == 200
    assert retry.cookies[POLICY.access_name].value == first
    assert _claims(retry)["groups"] == []


@pytest.mark.django_db
def test_a_token_minted_without_the_claim_is_answered_with_a_default(user):
    """Tokens issued before the realm existed carry no ``groups`` claim."""
    client = APIClient()
    client.cookies[POLICY.access_name] = (
        RotationPolicy().open_session(user).access.value
    )
    assert client.get("/api/groups").json() == {"groups": []}


def test_the_realm_mount_matches_the_default_refresh_path():
    assert check_refresh_cookie_path(None) == []


def test_login_and_refresh_share_the_realms_get_claims():
    for name in ("login", "refresh"):
        view = resolve(reverse(f"django_signet:{name}")).func.view_class
        assert issubclass(view, AppRealm)
        assert view.get_claims is AppRealm.get_claims


# ------------------------------------------------------------ reserved claims


@pytest.mark.django_db
def test_reserved_claims_cannot_be_overwritten(user):
    extra = {"sub": "999", "typ": "refresh", "jti": "x", "iat": 0, "nbf": 0, "exp": 0}
    pair = RotationPolicy().open_session(user, extra={**extra, "sid": "x"})
    claims = AccessToken().verify(pair.access.value)
    assert claims["sub"] == str(user.pk)
    assert claims["typ"] == "access"
    assert claims["sid"] == str(pair.family.id)
    for name, value in extra.items():
        assert claims[name] != value, name


@pytest.mark.django_db
def test_an_aud_claim_without_audience_makes_every_token_fail(user):
    pair = RotationPolicy().open_session(user, extra={"aud": "reports"})
    assert pair.access.claims["aud"] == "reports"  # signed in...
    with pytest.raises(TokenInvalid):
        AccessToken().verify(pair.access.value)  # ...and then refused


@pytest.mark.django_db
def test_an_iss_claim_without_issuer_is_signed_as_given(user):
    pair = RotationPolicy().open_session(user, extra={"iss": "someone-else"})
    assert AccessToken().verify(pair.access.value)["iss"] == "someone-else"


@pytest.mark.django_db
def test_with_audience_and_issuer_set_theirs_win(user):
    with override_settings(SIGNET={"AUDIENCE": "api", "ISSUER": "auth"}):
        pair = RotationPolicy().open_session(user, extra={"aud": "x", "iss": "y"})
        claims = AccessToken().verify(pair.access.value)
    assert (claims["aud"], claims["iss"]) == ("api", "auth")
