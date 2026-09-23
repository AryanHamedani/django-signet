from django.test import override_settings

from django_signet.checks import (
    check_cookie_prefix,
    check_cookie_security,
    check_grace_cache,
    check_setting_types,
    check_signet_setting_shape,
    check_signing_key,
)


@override_settings(DEBUG=False, SIGNET={"COOKIE_SECURE": False})
def test_insecure_cookies_in_production_are_an_error():
    ids = [e.id for e in check_cookie_security(None)]
    assert "signet.E001" in ids


@override_settings(DEBUG=True, SIGNET={"COOKIE_SECURE": False})
def test_insecure_cookies_in_debug_are_tolerated():
    assert check_cookie_security(None) == []


@override_settings(
    SIGNET={
        "COOKIE_REFRESH_NAME": "__Host-refresh",
        "COOKIE_REFRESH_PATH": "/api/auth/refresh",
    }
)
def test_host_prefix_with_non_root_path_is_an_error():
    ids = [e.id for e in check_cookie_prefix(None)]
    assert "signet.E002" in ids


@override_settings(SIGNET={"COOKIE_REFRESH_NAME": "__Secure-refresh"})
def test_secure_prefix_with_non_root_path_is_quiet():
    assert check_cookie_prefix(None) == []


@override_settings(SIGNET={"GRACE_CACHE": "nonexistent-alias"})
def test_missing_grace_cache_warns():
    ids = [w.id for w in check_grace_cache(None)]
    assert "signet.W003" in ids


@override_settings(SIGNET={"GRACE_CACHE": "default"})
def test_present_grace_cache_is_quiet():
    assert check_grace_cache(None) == []


@override_settings(
    SIGNET={"ALGORITHM": "RS256", "SIGNING_KEY": None, "VERIFYING_KEY": None}
)
def test_rs_algorithm_without_keys_is_an_error():
    ids = [e.id for e in check_signing_key(None)]
    assert "signet.E004" in ids


@override_settings(
    SIGNET={"ALGORITHM": "RS256", "SIGNING_KEY": "priv", "VERIFYING_KEY": None}
)
def test_rs_algorithm_missing_only_verifying_key_is_an_error():
    ids = [e.id for e in check_signing_key(None)]
    assert "signet.E004" in ids


@override_settings(
    SIGNET={"ALGORITHM": "RS256", "SIGNING_KEY": None, "VERIFYING_KEY": "pub"}
)
def test_rs_algorithm_missing_only_signing_key_is_an_error():
    ids = [e.id for e in check_signing_key(None)]
    assert "signet.E004" in ids


@override_settings(
    SIGNET={"ALGORITHM": "RS256", "SIGNING_KEY": "priv", "VERIFYING_KEY": "pub"}
)
def test_rs_algorithm_with_both_keys_is_quiet():
    assert check_signing_key(None) == []


@override_settings(
    SIGNET={"ALGORITHM": "HS256", "SIGNING_KEY": None, "VERIFYING_KEY": None}
)
def test_hs_algorithm_without_keys_is_quiet():
    assert check_signing_key(None) == []


# ------------------------------------------------------- signet.E005: shape


def test_signet_not_present_is_quiet():
    assert check_signet_setting_shape(None) == []


@override_settings(SIGNET={"COOKIE_SECURE": True})
def test_signet_a_dict_is_quiet():
    assert check_signet_setting_shape(None) == []


@override_settings(SIGNET=["not", "a", "dict"])
def test_signet_not_a_dict_is_an_error():
    ids = [e.id for e in check_signet_setting_shape(None)]
    assert "signet.E005" in ids


@override_settings(SIGNET=["not", "a", "dict"])
def test_malformed_signet_does_not_crash_the_other_checks():
    """A non-dict SIGNET must not raise out of any other check - only
    ``check_signet_setting_shape`` names the real problem; every other
    check degrades to its no-override behaviour instead of crashing."""
    assert check_cookie_security(None) == []
    assert check_cookie_prefix(None) == []
    assert check_grace_cache(None) == []
    assert check_signing_key(None) == []
    assert check_setting_types(None) == []


# ----------------------------------------------- crash-proofing: wrong types
#
# These confirm the *dereferencing* checks survive a wrong-typed setting
# (fall back to a safe default, never raise) - see the signet.E006 section
# below for the check that reports the wrong type as a real problem instead
# of silently tolerating it.


@override_settings(SIGNET={"ALGORITHM": 256})
def test_non_string_algorithm_does_not_crash_and_is_quiet():
    assert check_signing_key(None) == []


@override_settings(SIGNET={"COOKIE_REFRESH_NAME": 12345})
def test_non_string_refresh_name_does_not_crash_and_is_quiet():
    assert check_cookie_prefix(None) == []


@override_settings(SIGNET={"GRACE_CACHE": ["unhashable"]})
def test_unhashable_grace_cache_warns_instead_of_crashing():
    ids = [w.id for w in check_grace_cache(None)]
    assert "signet.W003" in ids


# --------------------------------------------- signet.E006: wrong-typed value


@override_settings(SIGNET={"ALGORITHM": 123})
def test_non_string_algorithm_is_an_error():
    ids = [e.id for e in check_setting_types(None)]
    assert "signet.E006" in ids


@override_settings(SIGNET={"ALGORITHM": "HS256"})
def test_string_algorithm_is_quiet():
    assert check_setting_types(None) == []


def test_absent_algorithm_is_quiet():
    assert check_setting_types(None) == []


@override_settings(SIGNET={"COOKIE_REFRESH_NAME": 999})
def test_non_string_refresh_name_is_an_error():
    ids = [e.id for e in check_setting_types(None)]
    assert "signet.E006" in ids


@override_settings(SIGNET={"COOKIE_REFRESH_NAME": None})
def test_none_refresh_name_is_quiet():
    """None is the legitimate "derive it from COOKIE_PREFIX" sentinel, not
    a wrong type - it must not be flagged."""
    assert check_setting_types(None) == []


@override_settings(SIGNET={"COOKIE_REFRESH_NAME": "signet-refresh"})
def test_string_refresh_name_is_quiet():
    assert check_setting_types(None) == []


@override_settings(SIGNET={"COOKIE_ACCESS_NAME": 999})
def test_non_string_access_name_is_an_error():
    ids = [e.id for e in check_setting_types(None)]
    assert "signet.E006" in ids


@override_settings(SIGNET={"COOKIE_ACCESS_NAME": None})
def test_none_access_name_is_quiet():
    assert check_setting_types(None) == []


@override_settings(SIGNET={"COOKIE_CSRF_NAME": 999})
def test_non_string_csrf_name_is_an_error():
    ids = [e.id for e in check_setting_types(None)]
    assert "signet.E006" in ids


@override_settings(SIGNET={"COOKIE_CSRF_NAME": None})
def test_none_csrf_name_is_quiet():
    assert check_setting_types(None) == []


@override_settings(SIGNET={"COOKIE_REFRESH_PATH": 42})
def test_non_string_refresh_path_is_an_error():
    """Unlike the cookie-name settings, COOKIE_REFRESH_PATH has no None
    sentinel - a wrong-typed value here is written straight into the
    cookie's Path attribute (Path=42), which every browser silently
    declines to match, rather than falling back to a working default."""
    ids = [e.id for e in check_setting_types(None)]
    assert "signet.E006" in ids


@override_settings(SIGNET={"COOKIE_REFRESH_PATH": "/api/auth/refresh"})
def test_string_refresh_path_is_quiet():
    assert check_setting_types(None) == []


@override_settings(SIGNET={"ALGORITHM": 123, "COOKIE_REFRESH_NAME": 999})
def test_multiple_wrong_typed_settings_each_reported():
    """Both problems are reported - one E006 finding doesn't swallow the
    other, unlike the single-message shape check for signet.E005."""
    ids = [e.id for e in check_setting_types(None)]
    assert ids == ["signet.E006", "signet.E006"]


# ------------------------------------------- signet.E002: path AND domain


@override_settings(
    SIGNET={"COOKIE_REFRESH_NAME": "__Host-refresh", "COOKIE_REFRESH_PATH": "/"}
)
def test_host_prefix_with_root_path_and_no_domain_is_quiet():
    """Discriminates against a path-blind implementation that fires on the
    __Host- prefix alone: this is a *valid* __Host- cookie (Path=/, no
    Domain) and must not be flagged."""
    assert check_cookie_prefix(None) == []


@override_settings(
    SIGNET={
        "COOKIE_REFRESH_NAME": "__Host-refresh",
        "COOKIE_REFRESH_PATH": "/",
        "COOKIE_DOMAIN": "example.com",
    }
)
def test_host_prefix_with_domain_is_an_error_even_at_root_path():
    ids = [e.id for e in check_cookie_prefix(None)]
    assert "signet.E002" in ids
