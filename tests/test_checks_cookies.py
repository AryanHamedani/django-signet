"""signet.E002: every explicitly named cookie keeps its prefix's contract."""

import pytest
from django.test import override_settings

from django_signet.checks import check_cookie_prefix, check_cookie_samesite


@pytest.mark.parametrize(
    ("overrides", "setting_name", "requirement"),
    [
        (
            {"COOKIE_ACCESS_NAME": "__Host-access", "COOKIE_SECURE": False},
            "COOKIE_ACCESS_NAME",
            "Secure",
        ),
        (
            {"COOKIE_ACCESS_NAME": "__Host-access", "COOKIE_DOMAIN": "example.com"},
            "COOKIE_ACCESS_NAME",
            "no Domain",
        ),
        (
            {"COOKIE_CSRF_NAME": "__Host-csrf", "COOKIE_SECURE": False},
            "COOKIE_CSRF_NAME",
            "Secure",
        ),
        (
            {"COOKIE_CSRF_NAME": "__Host-csrf", "COOKIE_DOMAIN": "example.com"},
            "COOKIE_CSRF_NAME",
            "no Domain",
        ),
        (
            {
                "COOKIE_REFRESH_NAME": "__Host-refresh",
                "COOKIE_REFRESH_PATH": "/",
                "COOKIE_SECURE": False,
            },
            "COOKIE_REFRESH_NAME",
            "Secure",
        ),
        (
            {
                "COOKIE_REFRESH_NAME": "__Host-refresh",
                "COOKIE_REFRESH_PATH": "/api/auth/",
            },
            "COOKIE_REFRESH_NAME",
            "Path=/",
        ),
        (
            {
                "COOKIE_REFRESH_NAME": "__Host-refresh",
                "COOKIE_REFRESH_PATH": "/",
                "COOKIE_DOMAIN": "example.com",
            },
            "COOKIE_REFRESH_NAME",
            "no Domain",
        ),
        (
            {"COOKIE_ACCESS_NAME": "__Secure-access", "COOKIE_SECURE": False},
            "COOKIE_ACCESS_NAME",
            "Secure",
        ),
        (
            {"COOKIE_REFRESH_NAME": "__Secure-refresh", "COOKIE_SECURE": False},
            "COOKIE_REFRESH_NAME",
            "Secure",
        ),
        (
            {"COOKIE_CSRF_NAME": "__Secure-csrf", "COOKIE_SECURE": False},
            "COOKIE_CSRF_NAME",
            "Secure",
        ),
        # Browsers match the prefixes case-insensitively, so these are
        # dropped just the same.
        (
            {"COOKIE_ACCESS_NAME": "__host-access", "COOKIE_SECURE": False},
            "COOKIE_ACCESS_NAME",
            "Secure",
        ),
        (
            {"COOKIE_REFRESH_NAME": "__SECURE-refresh", "COOKIE_SECURE": False},
            "COOKIE_REFRESH_NAME",
            "Secure",
        ),
    ],
)
def test_each_violated_prefix_requirement_of_each_cookie_is_an_error(
    settings, overrides, setting_name, requirement
):
    """L3: signet.E002 inspected only ``COOKIE_REFRESH_NAME``, and only its
    Path and Domain. The browser enforces the prefix contract on every
    cookie - ``__Host-`` needs Secure, Path=/ and no Domain; ``__Secure-``
    needs Secure - and silently drops one that breaks it. Each message
    names the setting, the cookie and the one requirement it breaks."""
    settings.SIGNET = overrides
    messages = check_cookie_prefix(None)

    assert [m.id for m in messages] == ["signet.E002"]
    assert setting_name in messages[0].msg
    assert overrides[setting_name] in messages[0].msg
    assert f"requires {requirement}" in messages[0].msg


@override_settings(
    SIGNET={
        "COOKIE_ACCESS_NAME": "__Host-access",
        "COOKIE_SECURE": False,
        "COOKIE_DOMAIN": "example.com",
    }
)
def test_every_violated_requirement_is_reported_separately():
    messages = check_cookie_prefix(None)

    assert [m.id for m in messages] == ["signet.E002", "signet.E002"]
    assert "requires Secure" in messages[0].msg
    assert "requires no Domain" in messages[1].msg


@pytest.mark.parametrize(
    "overrides",
    [
        # __Host- at Path=/ with Secure and no Domain, for all three.
        # The access and CSRF cookies are always set at "/", whatever
        # COOKIE_REFRESH_PATH says.
        {
            "COOKIE_ACCESS_NAME": "__Host-access",
            "COOKIE_CSRF_NAME": "__Host-csrf",
            "COOKIE_REFRESH_NAME": "__Host-refresh",
            "COOKIE_REFRESH_PATH": "/",
        },
        {"COOKIE_ACCESS_NAME": "__Host-access", "COOKIE_REFRESH_PATH": "/api/auth/"},
        # __Secure- needs only Secure: a Domain and a narrow path are fine.
        {
            "COOKIE_ACCESS_NAME": "__Secure-access",
            "COOKIE_CSRF_NAME": "__Secure-csrf",
            "COOKIE_REFRESH_NAME": "__Secure-refresh",
            "COOKIE_DOMAIN": "example.com",
        },
        # A derived name (None) is never flagged: CookiePolicy only
        # derives a prefix the cookie's attributes satisfy.
        {"COOKIE_SECURE": False, "COOKIE_DOMAIN": "example.com"},
        # An unprefixed explicit name has no browser-enforced contract.
        {"COOKIE_ACCESS_NAME": "access", "COOKIE_SECURE": False},
    ],
)
def test_explicit_names_that_keep_their_prefix_contract_are_quiet(settings, overrides):
    settings.SIGNET = overrides
    assert check_cookie_prefix(None) == []


# ------------------------------------------ signet.W012: SameSite=None + !Secure


@pytest.mark.parametrize("samesite", ["None", "none", "NONE"])
def test_samesite_none_without_secure_warns(settings, samesite):
    """Browsers drop a SameSite=None cookie that is not Secure, silently.
    Matched case-insensitively, as browsers read the attribute."""
    settings.SIGNET = {"COOKIE_SAMESITE": samesite, "COOKIE_SECURE": False}
    messages = check_cookie_samesite(None)

    assert [m.id for m in messages] == ["signet.W012"]
    assert not messages[0].is_serious()


@pytest.mark.parametrize(
    "overrides",
    [
        {"COOKIE_SAMESITE": "None"},  # Secure by default
        {"COOKIE_SAMESITE": "None", "COOKIE_SECURE": True},
        {"COOKIE_SAMESITE": "Lax", "COOKIE_SECURE": False},
        {"COOKIE_SECURE": False},  # Lax by default
        {"COOKIE_SAMESITE": None, "COOKIE_SECURE": False},  # wrong type: quiet
    ],
)
def test_samesite_none_with_secure_or_another_samesite_is_quiet(settings, overrides):
    settings.SIGNET = overrides
    assert check_cookie_samesite(None) == []
