"""The two pages moved under ``howto/``: ``choosing-a-store.md`` and
``migrating-from-simplejwt.md``."""

import contextlib
import uuid
from pathlib import Path

import pytest
from django.core.cache import cache, caches
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.module_loading import import_string
from examples import cache_store_settings, simplejwt_transition_settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIClient, APIRequestFactory

from django_signet.authentication import (
    CookieJWTAuthentication,
    HeaderJWTAuthentication,
)
from django_signet.checks import check_token_store
from django_signet.csrf import CSRF_HEADER
from django_signet.exceptions import TokenReused
from django_signet.hashing import token_digest
from django_signet.sessions.rotation import RotationPolicy
from django_signet.sessions.stores.cache import CacheTokenStore
from django_signet.sessions.stores.factory import get_store
from django_signet.signals import token_issued
from django_signet.transport.cookie import CookiePolicy
from tests.docs.helpers import settings_of, wire_header

DOCS = Path(__file__).resolve().parents[2] / "docs"


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def cache_store():
    with override_settings(**settings_of(cache_store_settings)):
        yield


# ------------------------------------------------------------ choosing a store


@pytest.mark.usefixtures("cache_store")
def test_the_setting_builds_an_allowlist_cache_store():
    store = get_store()
    assert isinstance(store, CacheTokenStore)
    assert store.deny_by_default is False
    assert store.alias == "default"


@pytest.mark.usefixtures("cache_store")
def test_the_cache_store_is_warned_w007_with_a_link_to_this_page():
    [warning] = check_token_store(None)
    assert warning.id == "signet.W007"
    url = "https://django-signet.readthedocs.io/en/latest/howto/choosing-a-store.html"
    assert warning.hint.endswith(url)
    assert (DOCS / "howto" / "choosing-a-store.md").is_file()


@pytest.mark.parametrize(("deny_by_default", "live"), [(False, False), (True, True)])
def test_the_modes_differ_on_a_session_the_cache_does_not_hold(deny_by_default, live):
    signet = {
        **cache_store_settings.SIGNET,
        "STORE_OPTIONS": {"deny_by_default": deny_by_default},
    }
    with override_settings(SIGNET=signet):
        assert get_store().is_live(uuid.uuid4()) is live


# What one refresh costs: the page's table states these counts.

CREDENTIALS = {"username": "alice", "password": "pw-not-used-in-assertions"}
POLICY = CookiePolicy()
_TRANSACTION_CONTROL = ("SAVEPOINT", "RELEASE", "ROLLBACK", "BEGIN", "COMMIT")


def _login_and_refresh(measure):
    client = APIClient()
    with measure():
        client.post(reverse("django_signet:login"), CREDENTIALS, format="json")
    csrf = client.cookies[POLICY.csrf_name].value
    with measure():
        response = client.post(
            reverse("django_signet:refresh"), headers={wire_header(CSRF_HEADER): csrf}
        )
    assert response.status_code == 200


def _statements(queries):
    return [
        q["sql"].split()[0]
        for q in queries
        if not q["sql"].startswith(_TRANSACTION_CONTROL)
    ]


@pytest.mark.django_db
def test_an_orm_refresh_runs_five_statements(user):
    captured = []

    @contextlib.contextmanager
    def measure():
        with CaptureQueriesContext(connection) as queries:
            yield
        captured.append(queries.captured_queries)

    _login_and_refresh(measure)
    refresh = [
        q["sql"] for q in captured[-1] if not q["sql"].startswith(_TRANSACTION_CONTROL)
    ]
    assert [(sql.split()[0], sql.split('"')[1]) for sql in refresh] == [
        ("SELECT", "auth_user"),  # load the user
        ("SELECT", "django_signet_issuedtoken"),  # the token, with its session
        ("UPDATE", "django_signet_issuedtoken"),  # claim it
        ("UPDATE", "django_signet_tokenfamily"),  # the session's last use
        ("INSERT", "django_signet_issuedtoken"),  # the successor
    ]


@pytest.mark.django_db
def test_a_cache_refresh_runs_one_query_and_seven_cache_calls(user, monkeypatch):
    calls = []
    store_cache = caches["default"]
    for name in ("get", "set", "add", "delete"):
        original = getattr(store_cache, name)

        def recording(key, *args, _name=name, _original=original, **kwargs):
            calls.append((_name, key.split(":")[1]))
            return _original(key, *args, **kwargs)

        monkeypatch.setattr(store_cache, name, recording)

    phases = []

    @contextlib.contextmanager
    def measure():
        calls.clear()
        with CaptureQueriesContext(connection) as queries:
            yield
        phases.append((list(calls), _statements(queries.captured_queries)))

    with override_settings(**settings_of(cache_store_settings)):
        _login_and_refresh(measure)
    (login_calls, _), (refresh_calls, refresh_queries) = phases

    writes = ("set", "add")
    assert [c for c in login_calls if c[0] in writes] == [
        ("set", "fam"),
        ("set", "tok"),
    ]
    assert refresh_queries == ["SELECT"]  # the user
    assert refresh_calls == [
        ("get", "tok"),
        ("get", "fam"),
        ("get", "rev"),
        ("add", "used"),
        ("get", "rev"),
        ("set", "tok"),
        ("set", "grace"),  # GRACE_CACHE, the same cache here
    ]


@pytest.mark.django_db
@pytest.mark.parametrize("deny_by_default", [False, True])
def test_an_evicted_consumed_marker_lets_a_spent_token_redeem(user, deny_by_default):
    """Reuse detection needs the consumed marker. Evict it and a spent
    refresh token is LIVE again: the replay forks the session instead of
    burning it, in allowlist and denylist mode alike."""
    signet = {
        **cache_store_settings.SIGNET,
        "STORE_OPTIONS": {"deny_by_default": deny_by_default},
        "GRACE_CACHE": None,
    }
    with override_settings(SIGNET=signet):
        policy = RotationPolicy()
        first = policy.open_session(user)
        policy.rotate(first.refresh.value)
        with pytest.raises(TokenReused):
            policy.rotate(first.refresh.value)  # detected while the marker lives
        assert not policy.store.is_live(first.family.id)

        again = policy.open_session(user)
        policy.rotate(again.refresh.value)
        cache.delete(f"signet:used:{token_digest(again.refresh.value)}")  # evicted
        forked = policy.rotate(again.refresh.value)  # no TokenReused
        assert forked.family.id == again.family.id
        assert policy.store.is_live(again.family.id)


# ---------------------------------------------------- migrating from Simple JWT


def test_the_transition_lists_signet_first_then_simple_jwt():
    first, second = simplejwt_transition_settings.REST_FRAMEWORK[
        "DEFAULT_AUTHENTICATION_CLASSES"
    ]
    assert import_string(first) is CookieJWTAuthentication
    assert second == "rest_framework_simplejwt.authentication.JWTAuthentication"


def test_a_request_without_a_signet_cookie_passes_to_the_next_class():
    """Absence is not failure: DRF then asks the next class in the list."""
    request = APIRequestFactory().get("/", headers={"Authorization": "Bearer legacy"})
    assert CookieJWTAuthentication().authenticate(request) is None


# The header cutover: a keyword of Signet's own, so each class passes the
# other's token on instead of refusing it.


def _auth(header):
    from examples.simplejwt_header_cutover import SignetHeaderAuthentication

    request = APIRequestFactory().get("/", headers={"Authorization": header})
    return SignetHeaderAuthentication().authenticate(request)


def test_signet_header_class_passes_a_bearer_token_on():
    assert _auth("Bearer simple-jwt-token") is None


def test_the_stock_header_class_refuses_a_bearer_token_it_cannot_verify():
    """Why the cutover needs a keyword: the stock class claims every Bearer
    header and refuses a Simple JWT token outright."""
    request = APIRequestFactory().get(
        "/", headers={"Authorization": "Bearer simple-jwt-token"}
    )
    with pytest.raises(AuthenticationFailed):
        HeaderJWTAuthentication().authenticate(request)


@pytest.mark.django_db
def test_signet_header_clients_use_their_own_keyword(user):
    with override_settings(ROOT_URLCONF="examples.simplejwt_header_cutover"):
        client = APIClient()
        tokens = client.post(reverse("mobile:login"), CREDENTIALS, format="json").json()
        refreshed = client.post(
            reverse("mobile:refresh"),
            headers={"Authorization": f"Signet {tokens['refresh']}"},
        )
        assert refreshed.status_code == 200
        bearer = client.post(
            reverse("mobile:refresh"),
            headers={"Authorization": f"Bearer {refreshed.json()['refresh']}"},
        )
        assert bearer.status_code == 401  # not Signet's keyword any more
    user_, claims = _auth(f"Signet {refreshed.json()['access']}")
    assert user_ == user
    assert claims["sub"] == str(user.pk)


@pytest.mark.django_db
def test_a_token_issued_receiver_records_last_login(user):
    from examples.last_login import record_last_login

    assert user.last_login is None
    token_issued.connect(record_last_login)
    try:
        APIClient().post(reverse("django_signet:login"), CREDENTIALS, format="json")
    finally:
        token_issued.disconnect(record_last_login)
    user.refresh_from_db()
    assert user.last_login is not None


@pytest.mark.django_db
def test_signet_login_alone_leaves_last_login_unset(user):
    APIClient().post(reverse("django_signet:login"), CREDENTIALS, format="json")
    user.refresh_from_db()
    assert user.last_login is None
