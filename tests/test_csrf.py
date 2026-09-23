from __future__ import annotations

import hmac
from unittest.mock import patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from django_signet.csrf import (
    CSRF_HEADER,
    SAFE_METHODS,
    issue_csrf,
    new_csrf_token,
    validate_csrf,
)
from django_signet.exceptions import CSRFFailed
from django_signet.transport.cookie import CookiePolicy

POLICY = CookiePolicy()


def _request(
    method: str = "POST", cookie: str | None = None, header: str | None = None
):
    request = getattr(RequestFactory(), method.lower())("/")
    if cookie is not None:
        request.COOKIES[POLICY.csrf_name] = cookie
    if header is not None:
        request.META[CSRF_HEADER] = header
    return request


def test_tokens_are_unpredictable():
    assert new_csrf_token() != new_csrf_token()
    assert len(new_csrf_token()) >= 32


def test_issue_sets_a_javascript_readable_cookie():
    response = HttpResponse()
    token = issue_csrf(response, POLICY)
    cookie = response.cookies[POLICY.csrf_name]
    assert cookie.value == token
    assert cookie["httponly"] == ""  # readable: the client must echo it


def test_issue_sets_the_cookie_at_root_path():
    """POLICY.csrf_name resolves to __Host-signet-csrf under these default,
    secure settings, and a __Host- cookie is silently dropped by the browser
    unless it carries Path=/ - no error, the cookie just never arrives, and
    every legitimate request then fails the double-submit check. A version
    of issue_csrf that forgot path="/" (letting Django default to the
    request path, or using some other path) would still pass the
    value/httponly assertions above, exactly the "asserted max-age but
    never path" failure mode this project's cookie-clearing tests already
    tripped over. Assert path explicitly."""
    response = HttpResponse()
    issue_csrf(response, POLICY)
    cookie = response.cookies[POLICY.csrf_name]
    assert cookie["path"] == "/"


def test_issue_uses_the_provided_token_instead_of_generating_one():
    response = HttpResponse()
    token = issue_csrf(response, POLICY, token="fixed-token")
    assert token == "fixed-token"
    assert response.cookies[POLICY.csrf_name].value == "fixed-token"


def test_matching_cookie_and_header_passes():
    validate_csrf(_request(cookie="tok", header="tok"), POLICY)


@pytest.mark.parametrize("method", sorted(SAFE_METHODS))
def test_safe_methods_are_exempt(method):
    validate_csrf(_request(method), POLICY)


def test_unsafe_methods_are_all_checked():
    """A guard that only special-cases POST (rather than checking against
    SAFE_METHODS) would still pass every other test in this file, since
    they all exercise POST. PUT/PATCH/DELETE must be rejected too when the
    double-submit values are absent."""
    for method in ("PUT", "PATCH", "DELETE"):
        with pytest.raises(CSRFFailed):
            validate_csrf(_request(method), POLICY)


@pytest.mark.parametrize(
    ("cookie", "header"),
    [("tok", "other"), ("tok", None), (None, "tok"), (None, None), ("", "")],
)
def test_mismatch_or_absence_is_rejected(cookie, header):
    with pytest.raises(CSRFFailed):
        validate_csrf(_request(cookie=cookie, header=header), POLICY)


def test_comparison_is_constant_time_not_a_short_circuiting_equality():
    """Behaviourally, hmac.compare_digest and `==` agree on every case
    above: there is no return value or exception here that distinguishes a
    constant-time comparison from an ordinary one, since both are correct
    on the merits. The only way to prove the check cannot degrade into a
    timing oracle is to prove hmac.compare_digest is the function actually
    doing the comparing, so this patches it (wrapping the real
    implementation, so behaviour is unchanged) and asserts it fires with
    the raw cookie/header values on both a matching and a mismatched
    request. An implementation using `==` instead would leave the spy
    uncalled and fail this test, even though validate_csrf's return value
    and raised exception would look identical either way."""
    with patch(
        "django_signet.csrf.hmac.compare_digest", wraps=hmac.compare_digest
    ) as spy:
        validate_csrf(_request(cookie="tok", header="tok"), POLICY)
    spy.assert_called_once_with("tok", "tok")

    with (
        patch(
            "django_signet.csrf.hmac.compare_digest", wraps=hmac.compare_digest
        ) as spy,
        pytest.raises(CSRFFailed),
    ):
        validate_csrf(_request(cookie="tok", header="other"), POLICY)
    spy.assert_called_once_with("tok", "other")
