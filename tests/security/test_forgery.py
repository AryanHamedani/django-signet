"""Adversarial suite, part 1: token forgery.

Every test here asks one question: what single line in the library could
be deleted and still leave this test green? Where the honest answer is
"none" - because PyJWT, or the shape of the endpoint, already rules the
attack out on its own - that is written down rather than shipped as a
test that only *looks* like it proves something. See the module-level
notes on ``test_alg_none_is_rejected`` and
``test_an_algorithm_substitution_with_the_real_secret_is_rejected`` for
two cases where that distinction mattered.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

import jwt
import pytest
from django.conf import settings as django_settings
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework.views import APIView

from django_signet.authentication import CookieJWTAuthentication
from django_signet.checks import check_cookie_prefix
from django_signet.csrf import CSRF_HEADER
from django_signet.transport.cookie import CookiePolicy

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


@pytest.fixture
def client(account):
    c = APIClient()
    c.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    return c


def _attack(client, token):
    client.cookies[POLICY.access_name] = token
    return client.get(reverse("django_signet:verify"))


def _future_exp() -> int:
    return int((timezone.now() + timedelta(hours=1)).timestamp())


# ------------------------------------------------------------------- forgery


def test_alg_none_is_rejected(client, account):
    """The classic forgery: strip the signature, declare alg=none.

    Honesty check, same one ``tests/tokens/test_backends.py`` already
    documents for the unit-level equivalent: this does NOT isolate
    algorithm pinning as the cause. PyJWT independently refuses to verify
    ``alg=none`` unless ``key=None`` is passed to ``decode()`` - which
    ``HMACBackend._decode`` never does, pinning or not - so this would
    still pass with `algorithms=[self.algorithm]` deleted from
    ``_decode()``. It stays in this suite anyway because it proves the
    thing an attacker actually cares about - an unsigned forgery never
    authenticates a real cookie-protected endpoint - end to end through
    the real HTTP cycle, which the unit-level version cannot: it never
    touches ``CookieTransport``, the view, or DRF's authentication
    pipeline. The line that specifically isolates algorithm pinning is in
    ``test_an_algorithm_substitution_with_the_real_secret_is_rejected``
    below.
    """
    forged = jwt.encode(
        {"sub": str(account.pk), "typ": "access", "exp": _future_exp()},
        key="",
        algorithm="none",
    )
    assert _attack(client, forged).status_code == 401


def test_an_algorithm_substitution_with_the_real_secret_is_rejected(client, account):
    """Algorithm pinning, isolated from "wrong key" and from PyJWT's own
    independent protections.

    The brief's classic "sign HS256 with a value the attacker knows"
    version of this test does not actually reach this codebase's pinning
    at all: with a different key, the signature simply fails to verify -
    the exact same outcome a byte-flipped token produces, and already
    covered by ``test_a_flipped_payload_byte_is_rejected`` below. A more
    literal RS/HS key-confusion attempt (sign HS256 using the server's own
    RS256 *public* key, which is not secret, as the HMAC key) was tried
    and rejected for this suite: PyJWT >=2.10 - the floor this project
    already depends on - refuses in ``HMACAlgorithm.prepare_key()`` to use
    any PEM/DER/SSH-shaped value as an HMAC secret at all, regardless of
    what ``algorithms=[...]`` allows. Verified by hand against this
    project's pinned PyJWT: with the pin deleted (``algorithms=["RS256",
    "HS256"]``), `jwt.decode()` still raises ``InvalidKeyError`` before
    ever reaching this library's code. That protection lives one layer
    down, in the dependency this project already requires; a test for it
    here would prove PyJWT works, not that this library does.

    This test isolates the boundary that actually belongs to
    ``django_signet``: the SAME real secret key, re-signed HS384 instead
    of the configured HS256.

    ``jti`` is included in the forged claims deliberately - its absence
    was a real bug in an earlier version of this test. ``Token.verify()``
    independently rejects any token missing ``jti`` (see
    ``tokens/base.py``), so without it here, widening the pin in
    ``HMACBackend._decode`` to ``algorithms=["HS256", "HS384", "HS512"]``
    left this test green anyway - it was failing on the missing-``jti``
    check, never reaching the algorithm-pinning boundary it claims to
    isolate. Confirmed by mutation: with the pin widened as above AND
    ``jti`` present, this forgery decodes successfully and authenticates
    (200) - so *this* version is the one that actually goes red if
    `HMACBackend._decode` stops pinning to a single algorithm. With the
    pin restored, it correctly returns 401.
    """
    forged = jwt.encode(
        {
            "sub": str(account.pk),
            "typ": "access",
            "jti": str(uuid.uuid4()),
            "exp": _future_exp(),
        },
        key=django_settings.SECRET_KEY,
        algorithm="HS384",
    )
    assert _attack(client, forged).status_code == 401


def test_a_flipped_payload_byte_is_rejected(client):
    original = client.cookies[POLICY.access_name].value
    head, payload, sig = original.split(".")
    assert _attack(client, f"{head}.{payload[:-1]}X.{sig}").status_code == 401


def test_a_truncated_token_is_rejected(client):
    original = client.cookies[POLICY.access_name].value
    assert _attack(client, original.rsplit(".", 1)[0]).status_code == 401


def test_garbage_is_rejected(client):
    for junk in ["", "....", "not-a-jwt", "a.b.c", "Bearer x"]:
        assert _attack(client, junk).status_code == 401


def test_an_expired_token_is_rejected(account):
    with override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(seconds=-1)}):
        c = APIClient()
        c.post(
            reverse("django_signet:login"),
            {"username": "bob", "password": PASSWORD},
            format="json",
        )
        assert c.get(reverse("django_signet:verify")).status_code == 401


def test_extra_claims_cannot_overwrite_the_subject(account):
    """A custom get_claims() hook must not be able to forge identity.

    There is no HTTP-reachable way to attack this directly - ``extra`` is
    never sourced from request data anywhere in this library, only from a
    server-side hook - so this exercises ``RotationPolicy`` directly,
    the same way the brief specifies it. The property under test is
    structural (``build_claims``'s reserved-last merge), not something a
    black-box HTTP request could probe on its own.
    """
    from django_signet.sessions.rotation import RotationPolicy
    from django_signet.tokens.access import AccessToken

    pair = RotationPolicy().open_session(account, extra={"sub": "999", "exp": 1})
    claims = AccessToken().verify(pair.access.value)
    assert claims["sub"] == str(account.pk)
    assert claims["exp"] > int(timezone.now().timestamp())


def test_login_sets_every_required_cookie_flag(account):
    """Browser-enforced contract. A wrong flag fails silently in production,
    so assert it explicitly.

    Round-1 review fix: the original version of this test asserted
    ``httponly``/``secure``/``path`` on the access and refresh cookies but
    never touched ``refresh["samesite"]``, or any flag on the CSRF cookie
    at all (``secure``, ``samesite``, ``path``) - despite the docstring
    claiming "every required" flag and despite ``CookiePolicy``'s own
    class docstring naming the CSRF cookie's ``__Host-``/``__Secure-``
    prefixing and its flags as the cookie-tossing defence. Deleting
    ``samesite=p.samesite`` from the refresh ``set_cookie`` in
    ``transport/cookie.py``, or ``secure=policy.secure`` /
    ``samesite=policy.samesite`` from ``issue_csrf`` in ``csrf.py``, left
    this test fully green. Now covered.
    """
    c = APIClient()
    response = c.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    access = response.cookies[POLICY.access_name]
    refresh = response.cookies[POLICY.refresh_name]
    csrf = response.cookies[POLICY.csrf_name]

    assert access["httponly"] is True
    assert access["secure"] is True
    assert refresh["httponly"] is True
    assert refresh["secure"] is True
    assert access["samesite"] == "Lax"
    assert refresh["samesite"] == "Lax"
    assert access["path"] == "/"
    assert refresh["path"] == POLICY.refresh_path
    assert csrf["httponly"] == ""  # must stay readable for double-submit
    assert csrf["secure"] is True
    assert csrf["samesite"] == "Lax"
    assert csrf["path"] == "/"
    assert POLICY.access_name.startswith("__Host-")
    assert POLICY.refresh_name.startswith("__Secure-")
    assert POLICY.csrf_name.startswith("__Host-")


def test_error_bodies_never_disclose_the_reason(account):
    """No response body may reveal *why* a credential failed.

    The brief's original version of this test checked the body against a
    word list including "expired" - but ``GENERIC_FAILURE`` itself is the
    literal string "Invalid or expired credentials.", so that check would
    fail against a perfectly correct implementation; it was never
    exercisable as written. The actual anti-disclosure guarantee (already
    proven at the authenticator level by
    ``test_every_failure_cause_produces_the_identical_message`` in
    ``tests/test_authentication.py``) is that the WIRE-LEVEL response is
    byte-for-byte identical across every distinct failure cause - not
    that it avoids a hand-picked set of words. This proves it through the
    real endpoint for several genuinely different causes: garbage,
    expiry, and a deactivated account.
    """
    c = APIClient()
    c.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )

    garbage_body = json.dumps(_attack(c, "a.b.c").json())

    with override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(seconds=-1)}):
        expired_client = APIClient()
        expired_client.post(
            reverse("django_signet:login"),
            {"username": "bob", "password": PASSWORD},
            format="json",
        )
        expired_body = json.dumps(
            expired_client.get(reverse("django_signet:verify")).json()
        )

    inactive_client = APIClient()
    inactive_client.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    account.is_active = False
    account.save(update_fields=["is_active"])
    inactive_body = json.dumps(
        inactive_client.get(reverse("django_signet:verify")).json()
    )

    assert {garbage_body, expired_body, inactive_body} == {garbage_body}


# ---------------------------------------------------------- beyond the brief


@override_settings(SIGNET={"COOKIE_REFRESH_NAME": "__Host-signet-refresh"})
def test_a_host_prefixed_refresh_cookie_name_is_only_caught_at_check_time(account):
    """Cookie prefixes are browser-enforced, and this library derives cookie
    names from settings - so what stops an operator from setting
    ``COOKIE_REFRESH_NAME`` to something ``__Host-``-prefixed while the
    refresh cookie stays path-scoped (``COOKIE_REFRESH_PATH`` defaults to
    ``/api/auth/refresh``, never ``/``)? Nothing, at request time:
    ``CookieTransport.attach`` writes whatever name and path the policy
    hands it, with no validation of its own. This confirms both halves of
    that story - the runtime path ships the browser-illegal cookie
    without complaint, and ``checks.check_cookie_prefix`` (signet.E002) is
    the only thing that catches it, at ``manage.py check`` time, not
    request time. A deployment that never runs Django's system checks in
    CI has no defence against this at all.

    The first assertion has no single deletable line - there is no
    request-time guard to remove, which is exactly the gap this test
    documents. The second does: delete the path/domain check inside
    ``check_cookie_prefix`` and this half goes green against a genuinely
    dangerous configuration.
    """
    c = APIClient()
    response = c.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    assert POLICY.refresh_name == "__Host-signet-refresh"
    refresh_cookie = response.cookies[POLICY.refresh_name]
    assert refresh_cookie["path"] == POLICY.refresh_path
    assert refresh_cookie["path"] != "/"

    errors = check_cookie_prefix(None)
    assert any(error.id == "signet.E002" for error in errors)


# ---------------------------------------------------------- CSRF forgery


class _CookieAuthenticatedWrite(APIView):
    """A project endpoint protected by the stock cookie authenticator.

    These two tests used ``LogoutView`` as their example of a
    cookie-authenticated write (and lived in ``test_session_attacks.py``
    until moving here kept that file under 500 lines). Since the
    final-review fix for C1, logout authenticates through the *refresh*
    credential instead (its CSRF handling is pinned in ``test_seams.py``),
    so it no longer exercises the authenticator's CSRF check at all. This
    stand-in keeps the original assertion - 401 through
    ``CookieJWTAuthentication`` - on an endpoint that still takes that
    path.
    """

    authentication_classes = (CookieJWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        return Response({"ok": True})


def _cookie_write(client, **headers):
    request = APIRequestFactory().post("/", **headers)
    request.COOKIES.update({k: m.value for k, m in client.cookies.items()})
    return _CookieAuthenticatedWrite.as_view()(request)


def test_csrf_is_required_for_cookie_authenticated_writes(client):
    assert _cookie_write(client).status_code == 401
    # ...and the same request with the double-submit pair succeeds, so the
    # 401 above is the CSRF check, not a broken credential.
    csrf_value = client.cookies[POLICY.csrf_name].value
    assert _cookie_write(client, **{CSRF_HEADER: csrf_value}).status_code == 200


def test_a_forged_csrf_header_is_rejected(client):
    response = _cookie_write(client, **{CSRF_HEADER: "attacker-chosen"})
    assert response.status_code == 401
