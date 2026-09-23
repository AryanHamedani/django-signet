import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from django_signet.exceptions import TransportError
from django_signet.transport.cookie import CookiePolicy, CookieTransport

# test_attach_... opens a real session, so the whole module needs the database.
pytestmark = pytest.mark.django_db


@pytest.fixture
def transport():
    return CookieTransport()


def test_host_prefix_on_the_root_scoped_access_cookie(transport):
    assert transport.policy.access_name.startswith("__Host-")


def test_refresh_cookie_uses_secure_prefix_because_it_is_path_scoped(transport):
    """__Host- mandates Path=/. The refresh cookie is deliberately scoped to
    the refresh endpoint, so it must use __Secure- instead."""
    assert transport.policy.refresh_name.startswith("__Secure-")
    assert not transport.policy.refresh_name.startswith("__Host-")


def test_insecure_policy_drops_both_prefixes():
    policy = CookiePolicy(secure=False)
    assert not policy.access_name.startswith("__")
    assert not policy.refresh_name.startswith("__")
    assert not policy.csrf_name.startswith("__")


def test_project_settings_drive_the_policy():
    from django.test import override_settings

    with override_settings(SIGNET={"COOKIE_PREFIX": "acme"}):
        assert CookiePolicy().access_name == "__Host-acme-access"


def test_a_constructor_keyword_outranks_project_settings():
    from django.test import override_settings

    with override_settings(SIGNET={"COOKIE_PREFIX": "acme"}):
        assert CookiePolicy(prefix="own").access_name == "__Host-own-access"


def test_an_unknown_field_is_rejected():
    with pytest.raises(TypeError):
        CookiePolicy(nonsense=True)


def test_setting_a_domain_drops_only_the_host_prefix():
    policy = CookiePolicy(domain="example.com")
    assert not policy.access_name.startswith("__Host-")
    assert policy.access_name.startswith("__Secure-")
    assert policy.refresh_name.startswith("__Secure-")


# --- The decision table, spelled out explicitly rather than just probed via
# startswith(). A resolved_name() that e.g. always emits "__Secure-" (never
# "__Host-"), or that ignores `domain` entirely, would still pass narrower
# startswith assertions on some of these but not the exact names below.


def test_default_settings_name_table():
    policy = CookiePolicy()
    assert policy.access_name == "__Host-signet-access"
    assert policy.refresh_name == "__Secure-signet-refresh"
    assert policy.csrf_name == "__Host-signet-csrf"


def test_insecure_name_table():
    policy = CookiePolicy(secure=False)
    assert policy.access_name == "signet-access"
    assert policy.refresh_name == "signet-refresh"
    assert policy.csrf_name == "signet-csrf"


def test_domain_set_name_table():
    policy = CookiePolicy(domain="example.com")
    assert policy.access_name == "__Secure-signet-access"
    assert policy.refresh_name == "__Secure-signet-refresh"
    assert policy.csrf_name == "__Secure-signet-csrf"


def test_explicit_names_bypass_prefix_derivation():
    policy = CookiePolicy(
        explicit_access_name="my-access",
        explicit_refresh_name="my-refresh",
        explicit_csrf_name="my-csrf",
    )
    assert policy.access_name == "my-access"
    assert policy.refresh_name == "my-refresh"
    assert policy.csrf_name == "my-csrf"


def test_attach_sets_both_cookies_with_the_right_flags(transport, user):
    from django_signet.sessions.rotation import RotationPolicy

    pair = RotationPolicy().open_session(user)
    response = HttpResponse()
    transport.attach(response, pair)

    access = response.cookies[transport.policy.access_name]
    refresh = response.cookies[transport.policy.refresh_name]

    assert access["httponly"] is True
    assert access["secure"] is True
    assert access["samesite"] == "Lax"
    assert access["path"] == "/"
    assert refresh["path"] == transport.policy.refresh_path


def test_attach_sets_cookie_values_from_the_pair(transport, user):
    """A broken attach() that swaps which token goes into which cookie, or
    that writes the same value into both, would still satisfy the flag-only
    assertions above."""
    from django_signet.sessions.rotation import RotationPolicy

    pair = RotationPolicy().open_session(user)
    response = HttpResponse()
    transport.attach(response, pair)

    access = response.cookies[transport.policy.access_name]
    refresh = response.cookies[transport.policy.refresh_name]

    assert access.value == pair.access.value
    assert refresh.value == pair.refresh.value
    assert access.value != refresh.value


def test_extract_reads_the_cookie(transport):
    request = RequestFactory().get("/")
    request.COOKIES[transport.policy.access_name] = "a.b.c"
    assert transport.extract_access(request) == "a.b.c"


def test_extract_raises_when_absent(transport):
    with pytest.raises(TransportError):
        transport.extract_access(RequestFactory().get("/"))


def test_extract_refresh_reads_its_own_cookie_not_the_access_one(transport):
    """extract_refresh must read policy.refresh_name, not access_name - a
    copy-paste bug that reused the access cookie name would still pass a
    test that only ever populates one cookie."""
    request = RequestFactory().get("/")
    request.COOKIES[transport.policy.access_name] = "wrong-token"
    request.COOKIES[transport.policy.refresh_name] = "right-token"
    assert transport.extract_refresh(request) == "right-token"


def test_clear_expires_both_cookies(transport):
    response = HttpResponse()
    transport.clear(response)
    assert response.cookies[transport.policy.access_name]["max-age"] == 0
    assert response.cookies[transport.policy.refresh_name]["max-age"] == 0


def test_clear_also_expires_the_csrf_cookie(transport):
    response = HttpResponse()
    transport.clear(response)
    assert response.cookies[transport.policy.csrf_name]["max-age"] == 0
