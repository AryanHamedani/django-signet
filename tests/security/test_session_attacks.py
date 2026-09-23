"""Adversarial suite, part 2: session and refresh-rotation attacks.

Same rule as ``test_forgery.py``: every assertion here should name a real
line in the library that, deleted, turns it red. Where a brief-suggested
test could not clear that bar (see
``test_one_users_token_cannot_reach_another_users_session``) that is said
plainly rather than shipped as padding.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory

from django_signet.authentication import StrictCookieJWTAuthentication
from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason, TokenFamily
from django_signet.tokens.access import AccessToken
from django_signet.transport.cookie import CookiePolicy
from django_signet.views import TokenVerifyView

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


def _login(username="bob", password=PASSWORD):
    c = APIClient()
    c.post(
        reverse("django_signet:login"),
        {"username": username, "password": password},
        format="json",
    )
    return c


# -------------------------------------------------------------- brief attacks


def test_stolen_refresh_token_replayed_later_burns_the_family(account, settings):
    """The RFC 9700 scenario. The attacker captures a refresh token; the
    legitimate client rotates first; the attacker replays after the grace
    window and the whole lineage dies."""
    settings.SIGNET = {"GRACE_CACHE": None}  # strict mode
    victim = _login()
    stolen = victim.cookies[POLICY.refresh_name].value

    assert victim.post(reverse("django_signet:refresh")).status_code == 200

    attacker = APIClient()
    attacker.cookies[POLICY.refresh_name] = stolen
    assert attacker.post(reverse("django_signet:refresh")).status_code == 401

    family = TokenFamily.objects.get()
    assert family.is_live is False
    assert family.revoked_reason == RevocationReason.REUSE_DETECTED

    # and the victim is now locked out too - that is the intended blast radius
    assert victim.post(reverse("django_signet:refresh")).status_code == 401


def test_two_tabs_refreshing_together_do_not_burn_the_family(account):
    """The false-positive that most implementations ship. Both callers must
    succeed and the session must survive."""
    tab_a = _login()
    shared = tab_a.cookies[POLICY.refresh_name].value

    tab_b = APIClient()
    tab_b.cookies[POLICY.refresh_name] = shared

    first = tab_a.post(reverse("django_signet:refresh"))
    second = tab_b.post(reverse("django_signet:refresh"))

    assert first.status_code == 200
    assert second.status_code == 200
    assert (
        first.cookies[POLICY.refresh_name].value
        == second.cookies[POLICY.refresh_name].value
    )
    assert TokenFamily.objects.get().is_live is True


def test_csrf_is_required_for_cookie_authenticated_writes(account):
    client = _login()
    assert client.post(reverse("django_signet:logout")).status_code == 401


def test_a_forged_csrf_header_is_rejected(account):
    client = _login()
    response = client.post(
        reverse("django_signet:logout"), **{CSRF_HEADER: "attacker-chosen"}
    )
    assert response.status_code == 401


def test_a_revoked_session_cannot_be_refreshed(account):
    client = _login()
    TokenFamily.objects.get().revoke(RevocationReason.ADMIN)
    assert client.post(reverse("django_signet:refresh")).status_code == 401


def test_disabling_an_account_revokes_access_immediately(account):
    """CVE-2024-22513 regression: this is the bug that made Simple JWT
    vulnerable. Disabling must not wait for token expiry."""
    client = _login()
    assert client.get(reverse("django_signet:verify")).status_code == 200
    account.is_active = False
    account.save(update_fields=["is_active"])
    assert client.get(reverse("django_signet:verify")).status_code == 401


def test_changing_the_password_kills_refresh(account):
    client = _login()
    account.set_password("a-completely-different-password")
    account.save()
    assert client.post(reverse("django_signet:refresh")).status_code == 401


def test_one_users_token_cannot_reach_another_users_session(account, django_user_model):
    """Two live, interleaved sessions must never cross.

    Honesty check on this one, per the brief's own instructions: the
    original brief version only ever logged in as bob and never gave
    mallory a session at all, so there was nothing in it that could
    actually cross - any implementation, broken or not, passes it. This
    version at least gives both users a real, concurrent session and
    checks both identities independently. But there still is no single
    deletable production-code line that would turn it red: JWTs are
    signed per-subject, DRF builds a fresh view and authenticator per
    request, and nothing in this codebase caches identity anywhere
    shared (no class- or module-level attribute holding "the current
    user"). This is a regression guard against a *class* of bug - a
    future change that started caching request.user somewhere shared -
    rather than proof that a specific present-day defence exists. Kept
    because the brief asks for it explicitly and it is cheap and not
    actively misleading, but it is the one test in this suite closest to
    padding; flagged as such in the report rather than left silent.
    """
    mallory = django_user_model.objects.create_user(
        username="mallory", password=PASSWORD
    )
    bob_client = _login()
    mallory_client = _login(username="mallory")

    bob_response = bob_client.get(reverse("django_signet:verify"))
    mallory_response = mallory_client.get(reverse("django_signet:verify"))

    assert bob_response.data["user_id"] == account.pk
    assert mallory_response.data["user_id"] == mallory.pk
    assert bob_response.data["user_id"] != mallory_response.data["user_id"]


# ---------------------------------------------------------- beyond the brief


def test_a_session_past_its_absolute_lifetime_cannot_be_refreshed(account):
    """Rotation refreshes an individual token's own expiry (a fresh
    ``REFRESH_TOKEN_LIFETIME`` window each time, via ``RefreshToken().mint()``
    in ``_mint_into``) but never touches ``TokenFamily.expires_at``, which
    ``RotationPolicy.open_session`` sets once, at login, and never again.
    That is an absolute session-lifetime cap, independent of activity - and
    it has to be enforced by the store (``family.expires_at <= now`` in
    ``ORMTokenStore.consume``), not by the JWT's own ``exp`` claim, because
    the two genuinely diverge here: a token minted well after login still
    carries a comfortably future ``exp``, while the family's fixed cap can
    already be behind it. Without that store-side check, a session could be
    kept alive forever by refreshing often enough, defeating the point of
    an absolute cap entirely. Backdating the family directly - rather than
    waiting out a real ``REFRESH_TOKEN_LIFETIME`` or performing enough
    rotations to reproduce the divergence for real - keeps this
    deterministic, matching how ``test_an_expired_token_is_rejected`` in
    ``test_forgery.py`` already simulates elapsed time for the access
    token via ``override_settings`` rather than a real sleep.
    """
    client = _login()
    TokenFamily.objects.filter(user=account).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert client.post(reverse("django_signet:refresh")).status_code == 401


def test_an_access_token_presented_as_a_refresh_token_is_rejected(account):
    """Token-type confusion, the direction the existing suite does not
    cover. ``tests/tokens/test_tokens.py`` already proves a refresh token
    is rejected by the access verifier; nothing exercises the reverse
    through the real endpoint. An attacker who gets hold of a short-lived
    access token (e.g. read from a log, or a leaked ``Authorization``
    header on a hybrid deployment) must not be able to present it as a
    refresh cookie and mint themselves a fresh, long-lived session.

    Honesty note, found by mutation: deleting the ``typ`` check in
    ``Token.verify()`` (``tokens/base.py``) alone does NOT turn this test
    red. ``RotationPolicy.rotate()`` looks the presented token up by the
    *digest of its raw bytes* in the ``IssuedToken`` table, and an access
    token's bytes were never stored there in the first place - only a
    minted refresh token's digest is (see ``_mint_into``). So this attack
    is independently blocked by the store returning ``NOT_FOUND``, before
    the ``typ`` claim is ever consulted; the two checks are genuine
    defence in depth. For the ``typ`` check itself, see
    ``tests/tokens/test_tokens.py``. Kept anyway because it proves the
    property an attacker actually cares about - this specific redemption
    attempt fails end to end - even though it does not isolate the `typ`
    check as its single cause.
    """
    client = _login()
    access_value = client.cookies[POLICY.access_name].value
    client.cookies[POLICY.refresh_name] = access_value
    assert client.post(reverse("django_signet:refresh")).status_code == 401


def test_grace_cache_pointed_at_dummycache_treats_a_benign_replay_as_theft(account):
    """The grace cache is the only place a raw token exists outside the
    client, and ``RotationPolicy``'s module docstring documents a specific
    footgun for it: ``DummyCache`` accepts writes and silently discards
    them, so pointing ``GRACE_CACHE`` at it turns the grace window into a
    permanent no-op - a genuinely benign double-tab replay is treated
    exactly like theft and burns the family.
    ``tests/sessions/test_rotation.py::test_a_dummy_cache_alias_makes_every_replay_look_like_reuse``
    already proves this at the ``RotationPolicy`` level; this proves the
    same degrade survives the full view/serializer/cookie stack, not just
    direct policy calls - the "wiring mistakes unit tests pass over" this
    suite exists for.

    Honesty correction: an earlier version of this docstring claimed this
    test "would fail... if the except-and-degrade logic in ``_grace_put``/
    ``_grace_get`` were changed to treat a write failure as 'grace window
    satisfied'". That is false, and mutation testing disproves it -
    ``DummyCache.set()`` never raises, it just discards silently, so the
    ``except Exception`` branches in ``_grace_put``/``_grace_get`` are never
    even reached on this path. Confirmed directly: deleting the entire body
    of ``_grace_put`` (no grace-window write at all, for *any* cache) still
    leaves this specific test green, because an unconditionally-empty grace
    cache and a ``DummyCache``-backed one are indistinguishable from
    ``_grace_get``'s point of view - both return ``None``. That mutation
    does turn ``test_two_tabs_refreshing_together_do_not_burn_the_family``
    red, which is the test that actually exercises the grace-window write
    path; this one does not, and is kept only as regression documentation
    for the specific ``DummyCache`` footgun the module docstring warns
    about, not as a discriminating test of the except-and-degrade logic.
    """
    with override_settings(SIGNET={"GRACE_CACHE": "dummy"}):
        tab_a = _login()
        shared = tab_a.cookies[POLICY.refresh_name].value
        tab_b = APIClient()
        tab_b.cookies[POLICY.refresh_name] = shared

        assert tab_a.post(reverse("django_signet:refresh")).status_code == 200
        assert tab_b.post(reverse("django_signet:refresh")).status_code == 401
        assert TokenFamily.objects.get().is_live is False


class _StrictVerifyView(TokenVerifyView):
    """Test-only wiring: the shipped ``TokenVerifyView`` uses non-strict
    ``CookieJWTAuthentication`` (see ``urls.py``), so exercising the
    ``Strict*`` family-liveness check through an actual view dispatch
    (not a bare ``authenticate()`` call) needs a subclass. Same pattern
    ``tests/test_views.py`` already uses for ``_CacheBackedLogoutAllView``.
    No production code is touched - this class lives only in the test
    module and is never registered on a URL.
    """

    authentication_classes = (StrictCookieJWTAuthentication,)


def _strict_request(access_token):
    request = APIRequestFactory().get("/")
    request.COOKIES[POLICY.access_name] = access_token
    return _StrictVerifyView.as_view()(request)


def test_strict_view_rejects_a_token_with_no_sid_claim(account):
    """The seam the brief calls out by name: 'Strict* authentication
    classes read sid from the access token. What if it is absent...?'
    ``test_authentication.py`` already proves ``check_family()`` raises
    for this at the authenticator level; this proves the same failure
    survives an actual view dispatch (permission_classes, response
    construction) rather than a bare ``authenticate()`` call.
    """
    raw = AccessToken().mint(str(account.pk)).value
    assert _strict_request(raw).status_code == 401


def test_strict_view_rejects_a_token_naming_a_malformed_sid(account):
    """Companion to the missing-sid case above: '...or malformed?'"""
    raw = AccessToken().mint(str(account.pk), extra={"sid": "not-a-uuid"}).value
    assert _strict_request(raw).status_code == 401


def test_revoking_a_family_does_not_invalidate_an_already_issued_access_token(account):
    """The question an attacker (or an incident responder) actually asks
    after a session is revoked: 'does my stolen access token die right
    now, or does it keep working until it expires on its own?' For every
    concrete view this library ships - including ``TokenVerifyView`` - the
    answer is the latter: they all use non-strict ``CookieJWTAuthentication``
    (see ``urls.py``), which never calls ``check_family()``, so an
    already-issued access token keeps authenticating for the rest of its
    own (short) lifetime regardless of why the family was revoked - an
    admin action, logout-everywhere, or reuse detection burning it. This
    is the same stateless-access-token trade-off
    ``revocation.py``'s module docstring names for password changes
    ("access tokens already issued remain valid until they expire"); this
    proves it for family revocation in general, through a live request,
    rather than only asserting it in a docstring - and proves in the same
    test that swapping in a ``Strict*`` authentication class (as
    ``test_strict_view_rejects_a_token_with_no_sid_claim`` above already
    does) closes the gap, so a deployment that needs revoke-now semantics
    on a given endpoint has a verified way to get it. This is documented,
    intentional behaviour, not a defect - kept as a regression test
    against someone "fixing" it into a silent 500 or, worse, a silent
    always-strict check that would break the stateless-access-token
    design entirely.
    """
    client = _login()
    access_token = client.cookies[POLICY.access_name].value
    TokenFamily.objects.get().revoke(RevocationReason.ADMIN)

    # Non-strict verify: the already-issued access token still works.
    assert client.get(reverse("django_signet:verify")).status_code == 200

    # Strict verify, same token, same revoked family: rejected.
    assert _strict_request(access_token).status_code == 401
