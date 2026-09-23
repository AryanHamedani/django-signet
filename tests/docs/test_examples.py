"""The documentation's examples, run as code.

Every non-trivial code block in the docs is rendered with ``literalinclude``
from a file under ``docs/examples/``. The tests here import and exercise
those files, so an example that stops working fails CI rather than
shipping.

A settings example is applied with ``override_settings`` from its own
upper-case names (``settings_of``), so what the page shows is what runs.
"""

import re
from pathlib import Path

import pytest
from django.test import override_settings
from django.urls import reverse
from examples import (
    deploy_settings,
    local_settings,
    quickstart_settings,
    spa_settings,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework.views import APIView

from django_signet.authentication import GENERIC_FAILURE, CookieJWTAuthentication
from django_signet.checks import check_cookie_security, check_refresh_cookie_path
from django_signet.csrf import CSRF_HEADER, SAFE_METHODS
from django_signet.transport.cookie import CookiePolicy

EXAMPLES = Path(__file__).resolve().parents[2] / "docs" / "examples"
PASSWORD = "pw-not-used-in-assertions"  # the root conftest's `user` fixture
CREDENTIALS = {"username": "alice", "password": PASSWORD}


def settings_of(module):
    """The settings a settings example defines: its upper-case names."""
    return {k: v for k, v in vars(module).items() if k.isupper()}


def wire_header(meta_key):
    """A WSGI ``META`` key as the header name a client sends.

    ``HTTP_X_CSRF_TOKEN`` -> ``X-CSRF-TOKEN``. Header names are
    case-insensitive on the wire, so callers compare them lower-cased.
    """
    assert meta_key.startswith("HTTP_")
    return meta_key.removeprefix("HTTP_").replace("_", "-")


def test_wire_header_conversion_is_the_one_django_applies():
    request = APIRequestFactory().post("/", headers={wire_header(CSRF_HEADER): "t"})
    assert request.META[CSRF_HEADER] == "t"


# ---------------------------------------------------------------- quickstart


@pytest.fixture
def quickstart():
    with override_settings(
        ROOT_URLCONF="examples.quickstart_urls",
        **settings_of(quickstart_settings),
    ):
        yield


@pytest.mark.django_db
def test_quickstart_login_refresh_verify_logout(quickstart, user):
    policy = CookiePolicy()
    csrf_header = wire_header(CSRF_HEADER)
    client = APIClient()

    login = client.post(reverse("django_signet:login"), CREDENTIALS, format="json")
    assert login.status_code == 200
    assert login.json() == {"authenticated": True}  # no token in the body

    # The names and flags the tutorial states.
    access = login.cookies["__Host-signet-access"]
    refresh = login.cookies["__Secure-signet-refresh"]
    csrf = login.cookies["__Host-signet-csrf"]
    assert (policy.access_name, policy.refresh_name, policy.csrf_name) == (
        "__Host-signet-access",
        "__Secure-signet-refresh",
        "__Host-signet-csrf",
    )
    assert (access["path"], refresh["path"], csrf["path"]) == ("/", "/api/auth/", "/")
    assert access["httponly"]
    assert refresh["httponly"]
    assert not csrf["httponly"]  # the page's JavaScript must read it
    for cookie in (access, refresh, csrf):
        assert cookie["secure"]

    # Refresh without the header is refused and the token is left intact.
    assert client.post(reverse("django_signet:refresh")).status_code == 403
    refreshed = client.post(
        reverse("django_signet:refresh"), headers={csrf_header: csrf.value}
    )
    assert refreshed.status_code == 200
    assert refreshed.json() == {"authenticated": True}
    new_csrf = refreshed.cookies[policy.csrf_name].value
    assert new_csrf != csrf.value  # every rotation issues a new CSRF token

    assert client.get(reverse("django_signet:verify")).status_code == 200

    spent_refresh = client.cookies[policy.refresh_name].value
    logout = client.post(
        reverse("django_signet:logout"), headers={csrf_header: new_csrf}
    )
    assert logout.status_code == 200
    assert logout.json() == {"detail": "Signed out."}
    for name in (policy.access_name, policy.refresh_name, policy.csrf_name):
        assert logout.cookies[name].value == ""
        assert logout.cookies[name]["max-age"] == 0

    # The session is gone: its refresh token no longer refreshes.
    client.cookies[policy.refresh_name] = spent_refresh
    client.cookies[policy.csrf_name] = new_csrf
    denied = client.post(
        reverse("django_signet:refresh"), headers={csrf_header: new_csrf}
    )
    assert denied.status_code == 401

    # A browser logout stays idempotent: a dead cookie still answers 200.
    client.cookies[policy.refresh_name] = spent_refresh
    client.cookies[policy.csrf_name] = new_csrf
    again = client.post(
        reverse("django_signet:logout"), headers={csrf_header: new_csrf}
    )
    assert again.status_code == 200


@pytest.mark.django_db
def test_quickstart_logout_is_idempotent_for_a_browser(quickstart):
    assert APIClient().post(reverse("django_signet:logout")).status_code == 200


@pytest.mark.django_db
def test_quickstart_login_accepts_json_only(quickstart, user):
    response = APIClient().post(reverse("django_signet:login"), CREDENTIALS)
    assert response.status_code == 415


def test_quickstart_mount_is_covered_by_the_refresh_cookie_path(quickstart):
    assert check_refresh_cookie_path(None) == []


@pytest.mark.django_db
def test_quickstart_default_authentication_protects_your_views(quickstart, user):
    default_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    assert default_classes == [CookieJWTAuthentication]

    class Notes(APIView):
        # Read at class creation, inside the override, as the reader's own
        # views read it at import.
        authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
        permission_classes = (IsAuthenticated,)

        def get(self, request):
            return Response({"user": request.user.get_username()})

        def post(self, request):
            return Response(status=201)

    client = APIClient()
    client.post(reverse("django_signet:login"), CREDENTIALS, format="json")
    csrf = client.cookies[CookiePolicy().csrf_name].value
    factory = APIRequestFactory()
    factory.cookies = client.cookies
    view = Notes.as_view()

    assert view(factory.get("/notes")).data == {"user": "alice"}
    # No CSRF header: the authenticator's generic 401, not refresh's 403.
    refused = view(factory.post("/notes"))
    assert refused.status_code == 401
    assert refused.data == {"detail": GENERIC_FAILURE}
    assert (
        view(factory.post("/notes", headers={wire_header(CSRF_HEADER): csrf}))
    ).status_code == 201


# ------------------------------------------------------------ local http dev


@pytest.mark.django_db
def test_local_settings_drop_secure_and_the_prefixes(user):
    with override_settings(ROOT_URLCONF="examples.quickstart_urls"):
        with override_settings(**settings_of(local_settings)):
            policy = CookiePolicy()
            assert (policy.access_name, policy.refresh_name, policy.csrf_name) == (
                "signet-access",
                "signet-refresh",
                "signet-csrf",
            )
            login = APIClient().post(
                reverse("django_signet:login"), CREDENTIALS, format="json"
            )
            for name in (policy.access_name, policy.refresh_name, policy.csrf_name):
                assert not login.cookies[name]["secure"]
            assert check_cookie_security(None) == []  # tolerated under DEBUG
        with override_settings(**{**settings_of(local_settings), "DEBUG": False}):
            assert [m.id for m in check_cookie_security(None)] == ["signet.E001"]


# ------------------------------------------------------------------ client.js


def _client_js():
    return (EXAMPLES / "client.js").read_text()


def _js_functions(source):
    """``{name: body}`` for every top-level ``export async function``."""
    parts = re.split(r"^export async function (\w+)", source, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def _js_const(source, name):
    match = re.search(rf'^const {name} = "([^"]*)";$', source, flags=re.MULTILINE)
    assert match, f"client.js defines no {name}"
    return match.group(1)


def test_client_js_reads_the_cookie_the_server_sets():
    assert _js_const(_client_js(), "CSRF_COOKIE") == CookiePolicy().csrf_name


def test_client_js_sends_the_header_the_server_checks():
    sent = _js_const(_client_js(), "CSRF_HEADER")
    assert sent.lower() == wire_header(CSRF_HEADER).lower()


def test_client_js_treats_the_servers_safe_methods_as_safe():
    match = re.search(
        r"^const SAFE_METHODS = new Set\(\[(.*)\]\);$", _client_js(), re.M
    )
    assert match
    assert set(re.findall(r'"(\w+)"', match.group(1))) == SAFE_METHODS


def test_client_js_includes_credentials_on_every_call():
    source = _client_js()
    calls = source.count("fetch(")
    assert calls >= 5
    lines = re.findall(r'^\s+credentials: "include",$', source, flags=re.MULTILINE)
    assert len(lines) == calls


def test_client_js_calls_the_quickstart_urls(quickstart):
    functions = _js_functions(_client_js())
    for name in ("login", "refresh", "verify", "logout"):
        assert f"${{API}}{reverse(f'django_signet:{name}')}`" in functions[name]


def test_client_js_sends_csrf_on_refresh_and_logout_but_not_login():
    functions = _js_functions(_client_js())
    for name in ("refresh", "logout"):
        assert "[CSRF_HEADER]: readCookie(CSRF_COOKIE)" in functions[name]
        assert 'method: "POST"' in functions[name]
    assert "CSRF_HEADER" not in functions["login"]
    assert '"Content-Type": "application/json"' in functions["login"]


# ------------------------------------------------------------------------ SPA


def test_spa_cors_settings_allow_credentials_from_named_origins_only():
    assert spa_settings.CORS_ALLOW_CREDENTIALS is True
    assert not hasattr(spa_settings, "CORS_ALLOW_ALL_ORIGINS")
    assert spa_settings.CORS_ALLOWED_ORIGINS
    for origin in spa_settings.CORS_ALLOWED_ORIGINS:
        assert origin != "*"
        assert origin.startswith("https://")


def test_spa_cors_settings_allow_the_csrf_header():
    allowed = {h.lower() for h in spa_settings.CORS_ALLOW_HEADERS}
    assert wire_header(CSRF_HEADER).lower() in allowed
    assert "content-type" in allowed  # login posts JSON


@pytest.mark.django_db
def test_spa_settings_share_a_readable_csrf_cookie_across_the_site(user):
    with override_settings(
        ROOT_URLCONF="examples.quickstart_urls", **settings_of(spa_settings)
    ):
        policy = CookiePolicy()
        assert (policy.access_name, policy.refresh_name, policy.csrf_name) == (
            "__Secure-signet-access",
            "__Secure-signet-refresh",
            "__Secure-signet-csrf",
        )
        assert policy.samesite == "Lax"
        client = APIClient()
        login = client.post(reverse("django_signet:login"), CREDENTIALS, format="json")
        csrf = login.cookies[policy.csrf_name]
        assert csrf["domain"] == "example.com"
        assert not csrf["httponly"]
        assert login.json() == {"authenticated": True}  # the token is cookie-only
        refreshed = client.post(
            reverse("django_signet:refresh"),
            headers={wire_header(CSRF_HEADER): csrf.value},
        )
        assert refreshed.status_code == 200


# ------------------------------------------------------------ header clients


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def header_realm():
    with override_settings(ROOT_URLCONF="examples.header_urls"):
        yield


@pytest.mark.django_db
def test_header_client_flow(header_realm, user):
    client = APIClient()
    login = client.post(reverse("mobile:login"), CREDENTIALS, format="json")
    assert login.status_code == 200
    pair = login.json()
    assert set(pair) == {"authenticated", "access", "refresh"}
    assert not login.cookies  # nothing ambient, so no CSRF either

    me = client.get(reverse("me"), headers=_bearer(pair["access"]))
    assert me.json() == {"user": "alice"}

    refreshed = client.post(reverse("mobile:refresh"), headers=_bearer(pair["refresh"]))
    assert refreshed.status_code == 200
    new = refreshed.json()
    assert new["refresh"] != pair["refresh"]

    # A retry inside the grace window gets the same pair back.
    retry = client.post(reverse("mobile:refresh"), headers=_bearer(pair["refresh"]))
    assert retry.json() == new

    verify = client.get(reverse("mobile:verify"), headers=_bearer(new["access"]))
    assert verify.status_code == 200

    logout = client.post(reverse("mobile:logout"), headers=_bearer(new["refresh"]))
    assert logout.status_code == 200
    assert logout.json() == {"detail": "Signed out."}

    # A repeat is not a sign-out: the client is told its token is dead.
    repeat = client.post(reverse("mobile:logout"), headers=_bearer(new["refresh"]))
    assert repeat.status_code == 401
    assert repeat.json() == {"detail": GENERIC_FAILURE}
    gone = client.post(reverse("mobile:refresh"), headers=_bearer(new["refresh"]))
    assert gone.status_code == 401

    # With no credential at all there is nothing to revoke.
    assert client.post(reverse("mobile:logout")).status_code == 200


def test_header_realm_mount_passes_the_refresh_path_check(header_realm):
    assert check_refresh_cookie_path(None) == []


# ------------------------------------------------------------------ deploying


def test_deploy_mount_matches_its_refresh_cookie_path():
    with override_settings(
        ROOT_URLCONF="examples.deploy_urls", **settings_of(deploy_settings)
    ):
        assert check_refresh_cookie_path(None) == []


def test_deploy_mount_without_the_setting_fails_e008():
    with override_settings(ROOT_URLCONF="examples.deploy_urls"):
        errors = check_refresh_cookie_path(None)
    assert errors
    assert {e.id for e in errors} == {"signet.E008"}
