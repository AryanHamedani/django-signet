"""Adversarial suite, part 3: the seams between correct components.

Every module this library ships passed its own review in isolation. The
defects pinned here lived *between* them - the refresh path that never
asked the authentication layer's question ("is this user still active?"),
the store chosen three different ways in three different modules, the
logout endpoint that could not see the credential it needed to revoke.

Same rule as parts 1 and 2: each test names the production line that,
reverted, turns it red - and each was confirmed red by actually reverting
that line, not by reasoning about it.
"""

from __future__ import annotations

import pytest
from django.core.cache import cache
from django.urls import reverse
from django.utils.http import parse_http_date
from rest_framework.test import APIClient, APIRequestFactory

from django_signet.authentication import StrictCookieJWTAuthentication
from django_signet.csrf import CSRF_HEADER
from django_signet.models import RevocationReason, TokenFamily
from django_signet.signals import token_reuse_detected
from django_signet.tokens.refresh import RefreshToken
from django_signet.transport.cookie import CookiePolicy
from django_signet.views import TokenVerifyView

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"
_CACHE_STORE = "django_signet.sessions.stores.cache.CacheTokenStore"


@pytest.fixture(autouse=True)
def _clean_cache():
    """Several tests here run under a cache-backed store."""
    cache.clear()
    yield
    cache.clear()


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


class _StrictVerifyView(TokenVerifyView):
    authentication_classes = (StrictCookieJWTAuthentication,)


def _strict_verify(access_value):
    request = APIRequestFactory().get("/")
    request.COOKIES[POLICY.access_name] = access_value
    return _StrictVerifyView.as_view()(request)


def _present(client, endpoint, refresh_value, csrf_value):
    """Present an explicit refresh/CSRF pair to ``endpoint``, independent of
    whatever the client's cookie jar was left holding by an earlier
    response."""
    client.cookies[POLICY.refresh_name] = refresh_value
    client.cookies[POLICY.csrf_name] = csrf_value
    return client.post(
        reverse(f"django_signet:{endpoint}"), **{CSRF_HEADER: csrf_value}
    )


def _refresh(client, refresh_value, csrf_value):
    return _present(client, "refresh", refresh_value, csrf_value)


# ------------------------------------------------ Group A: C3 (Critical)


def test_refresh_for_a_disabled_account_is_rejected_and_burns_the_family(account):
    """CVE-2024-22513 at the *issuance* layer. The access-token half of
    this bug is pinned by ``test_disabling_an_account_revokes_access_
    immediately``; this is the half nobody was checking. Before the fix,
    ``RotationPolicy.rotate()`` never loaded the user at all, so a
    disabled account's refresh returned 200 with a freshly signed access
    token - which any verifier outside this library's authentication
    classes (an RS256 consumer in another service) would accept.

    The second half pins the ruling that the family is burned, not merely
    refused: reactivating the account must not revive the old session.
    The original refresh value is re-presented explicitly, because the
    401 above cleared the client's cookie jar and a cleared cookie would
    fail for the wrong reason.

    Red on revert of: the ``self._active_user(claims)`` call in
    ``RotationPolicy.rotate`` (first assertion flips to 200), and of the
    ``_revoke_named_family`` call inside ``_active_user`` (the family
    stays live and the post-reactivation refresh succeeds).
    """
    client = _login()
    refresh_value = client.cookies[POLICY.refresh_name].value
    csrf_value = client.cookies[POLICY.csrf_name].value

    account.is_active = False
    account.save(update_fields=["is_active"])
    assert _refresh(client, refresh_value, csrf_value).status_code == 401
    assert TokenFamily.objects.get().is_live is False

    account.is_active = True
    account.save(update_fields=["is_active"])
    assert _refresh(client, refresh_value, csrf_value).status_code == 401


# ------------------------------------------------ Group B: C2 (Critical)


def test_logout_under_a_denylist_store_is_seen_by_strict_auth(account, settings):
    """C2's fail-open: login, refresh and logout used one store, the
    ``Strict*`` classes constructed another, and nothing made them agree.
    With a denylist store on one side and the ORM on the other, a logout
    recorded in one was invisible to the liveness check reading the
    other - the family looked live, forever, to exactly the endpoints that
    had opted into instant revocation.

    One ``STORE`` setting now feeds every component through
    ``get_store()``. The ``TokenFamily`` assertion is what proves the
    configured store is the one actually used: under the old wiring the
    setting was ignored and every session went to the ORM regardless.
    Red on revert of ``store = ConfiguredStore()`` on ``RotationPolicy``
    (back to ``ORMTokenStore()``).
    """
    settings.SIGNET = {
        "STORE": _CACHE_STORE,
        "STORE_OPTIONS": {"deny_by_default": True},
    }
    client = _login()
    access_value = client.cookies[POLICY.access_name].value
    assert not TokenFamily.objects.exists()
    assert _strict_verify(access_value).status_code == 200

    client.post(
        reverse("django_signet:logout"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert _strict_verify(access_value).status_code == 401


def test_changing_the_password_under_a_cache_store_warns_rather_than_blocks(
    account, settings, caplog
):
    """The cache-store variant of ``test_changing_the_password_kills_
    refresh``, asserting the documented behaviour rather than the ORM one.

    ``revocation.py`` used to hardcode ``ORMTokenStore()``, so under a
    cache store a password change revoked nothing *and said nothing*: the
    receiver queried an empty table and returned. ``CacheTokenStore``
    cannot enumerate a user's families, so it cannot do the revocation -
    but the ruling is that it must neither block the password save (that
    would break every password change on a documented configuration) nor
    fail silently. So: the save goes through, a warning names the gap,
    and the session the password change could not reach is still live
    (signet.W007 says so at startup, too). Red on revert of
    ``get_store()`` in ``revoke_on_password_change``: no warning is
    logged.
    """
    settings.SIGNET = {"STORE": _CACHE_STORE}
    client = _login()
    refresh_value = client.cookies[POLICY.refresh_name].value
    csrf_value = client.cookies[POLICY.csrf_name].value

    with caplog.at_level("WARNING", logger="django_signet.revocation"):
        account.set_password("a-completely-different-password")
        account.save()

    account.refresh_from_db()
    assert account.check_password("a-completely-different-password")
    assert any("cannot revoke" in record.getMessage() for record in caplog.records), (
        caplog.text
    )
    assert _refresh(client, refresh_value, csrf_value).status_code == 200


# ------------------------------------------------ Group C: C1 (Critical)


def _assert_every_cookie_cleared(response):
    for name, path in (
        (POLICY.access_name, "/"),
        (POLICY.refresh_name, POLICY.refresh_path),
        (POLICY.csrf_name, "/"),
    ):
        assert response.cookies[name]["max-age"] == 0, name
        assert response.cookies[name]["path"] == path, name


def test_logout_without_an_access_cookie_revokes_the_family_and_clears_cookies(
    account,
):
    """C1: the access cookie's ``Expires`` is the access token's, so a
    browser deletes it after five minutes. ``LogoutView`` used to require
    ``IsAuthenticated`` through that cookie - so after any idle period it
    answered 401 and cleared nothing, and the refresh cookie was
    path-scoped to ``/api/auth/refresh``, where logout could never see it.
    The cookies are httpOnly, so the client could not clear them either:
    "log out" left a live 14-day session.

    Logout now revokes via the refresh credential, whose default path is
    widened to the auth mount prefix. The first assertion is the one a
    real browser enforces and Django's test client does not (it sends
    every cookie regardless of path): the refresh cookie's ``Path`` must
    actually cover the logout URLs. Red on revert of either half - the
    path default in ``DEFAULTS["COOKIE_REFRESH_PATH"]`` (first assertion)
    or ``LogoutView``'s refresh-credential revocation (401, family live).
    """
    client = _login()
    refresh_path = client.cookies[POLICY.refresh_name]["path"]
    assert reverse("django_signet:logout").startswith(refresh_path)
    assert reverse("django_signet:logout-all").startswith(refresh_path)

    del client.cookies[POLICY.access_name]  # expired, as a browser would
    response = client.post(
        reverse("django_signet:logout"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )

    assert response.status_code == 200
    assert TokenFamily.objects.get().is_live is False
    _assert_every_cookie_cleared(response)


@pytest.mark.parametrize(
    ("endpoint", "status"), [("refresh", 401), ("logout", 200), ("logout-all", 401)]
)
def test_a_cookieless_cross_site_post_deletes_no_cookies(account, endpoint, status):
    """R4: a response deletes cookies only when the request proved it came
    from our own origin. Under ``SameSite=Lax`` a cross-site top-level
    form POST carries none of the victim's cookies - but the browser still
    honours the ``Set-Cookie`` deletions in the response, so answering it
    with clearing cookies logged anyone out with one forged request: the
    very oracle ``csrf_failure`` refuses to be. Nothing reached us, so
    there is nothing to clear on the victim's behalf.

    Logout stays idempotent - no credential is still a 200, so a second
    click on "log out" needs no special case - and refresh and logout-all
    still answer 401, the status that means "go to login".

    Replaces ``test_logout_with_nothing_to_revoke_still_clears_cookies``,
    which pinned exactly the clearing this ruling removes. Red on revert
    of the ``origin_proven`` guard in ``SignetViewMixin.clear_cookies``.
    """
    forged = APIClient().post(
        reverse(f"django_signet:{endpoint}"), {"next": "/"}, format="multipart"
    )
    assert forged.status_code == status
    assert not forged.cookies


def test_logout_with_an_ambient_refresh_cookie_requires_csrf(account):
    """The refresh cookie is ambient, so logout via it is exactly as
    forgeable as refresh via it: a cross-site page could otherwise log a
    victim out with one POST. Enforced by the same code refresh uses
    (``read_refresh_credential``), with the same 403-and-keep-cookies
    response - a failed CSRF check must not double as a logout oracle."""
    client = _login()
    for header in ({}, {CSRF_HEADER: "attacker-chosen"}):
        response = client.post(reverse("django_signet:logout"), **header)
        assert response.status_code == 403
        assert POLICY.refresh_name not in response.cookies
    assert TokenFamily.objects.get().is_live is True


# ------------------------------------------------- Group E: I5, login CSRF


def _expire_together(response):
    """Within a second: the two cookies are set microseconds apart and
    ``Expires`` is rounded to whole seconds, so exact string equality
    would fail whenever a second boundary fell between them."""
    csrf = parse_http_date(response.cookies[POLICY.csrf_name]["expires"])
    refresh = parse_http_date(response.cookies[POLICY.refresh_name]["expires"])
    return abs(csrf - refresh) <= 1


def test_the_csrf_cookie_lives_as_long_as_the_refresh_cookie(account):
    """I5: the CSRF cookie had no ``Expires`` - a session cookie - while
    the refresh cookie lasts 14 days. After a browser restart every refresh
    returned 403 (and cookies are deliberately left in place on a CSRF
    failure), so a 14-day session silently lasted one browser session.
    Both cookies now expire together, on login and on every rotation.
    Red on revert of ``expires=`` in ``SignetViewMixin.set_cookies``."""
    client = APIClient()
    login = client.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    assert login.cookies[POLICY.csrf_name]["expires"]
    assert _expire_together(login)

    rotated = client.post(
        reverse("django_signet:refresh"),
        **{CSRF_HEADER: login.cookies[POLICY.csrf_name].value},
    )
    assert rotated.status_code == 200
    assert _expire_together(rotated)


def test_a_form_encoded_login_is_rejected(account):
    """Login CSRF: a cross-site page can submit an HTML form - form-encoded,
    no preflight - but cannot send ``application/json`` without CORS
    permission. Accepting form posts let an attacker log a victim's
    browser into the *attacker's* account. JSON only, so it is 415 and no
    session is opened. Red on revert of ``parser_classes`` on
    ``TokenObtainView``."""
    response = APIClient().post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
    )
    assert response.status_code == 415
    assert not TokenFamily.objects.exists()
    assert POLICY.access_name not in response.cookies


# ------------------------------------------------- second pass: R1 (Critical)


def test_logout_all_refuses_a_refresh_token_that_was_already_rotated(account):
    """R1: logout-all checked only that the token's *family* was live, so
    a refresh token already consumed by a rotation - lifted from a log or
    a proxy - still signed its user out on every device for the rest of
    its 14-day lifetime. It must now redeem the token.

    Outside the grace window the replay is reuse exactly as at refresh:
    its own family is burned, and the user's other session does not die.
    (Inside the window it is a redemption - see
    ``test_logout_inside_the_grace_window_revokes_the_session``.) Red on
    revert of the ``_redeem`` call in ``RotationPolicy.revoke_all`` (200,
    and every session revoked).
    """
    victim = _login()
    other_sid = RefreshToken().verify(_login().cookies[POLICY.refresh_name].value)[
        "sid"
    ]
    old = victim.cookies[POLICY.refresh_name].value
    csrf_value = victim.cookies[POLICY.csrf_name].value
    assert _refresh(victim, old, csrf_value).status_code == 200

    cache.clear()  # the grace window has passed
    assert _present(APIClient(), "logout-all", old, csrf_value).status_code == 401
    mine = TokenFamily.objects.get(pk=RefreshToken().verify(old)["sid"])
    assert mine.revoked_reason == RevocationReason.REUSE_DETECTED
    assert TokenFamily.objects.get(pk=other_sid).is_live is True


def test_logout_inside_the_grace_window_revokes_the_session(account):
    """R1 grace-window correction: a tab's refresh consumes T1 and issues
    T2, then a logout still carrying T1 arrives inside the grace window.
    Treating that replay as "not LIVE" revoked nothing yet answered 200
    "Signed out." - and T2 kept refreshing, so a browser whose refresh
    ``Set-Cookie`` landed last stayed fully signed in behind a UI that said
    otherwise. Refresh already honours a grace replay (it hands over T2),
    so holding T1 inside the window already grants everything T2 does:
    logout must win. Red on revert of the grace branch in
    ``RotationPolicy._redeem`` (family live, T2 refresh 200).
    """
    tab = _login()
    t1 = tab.cookies[POLICY.refresh_name].value
    csrf_value = tab.cookies[POLICY.csrf_name].value
    assert _refresh(tab, t1, csrf_value).status_code == 200
    t2 = tab.cookies[POLICY.refresh_name].value
    assert t2 != t1

    assert _present(APIClient(), "logout", t1, csrf_value).status_code == 200
    assert TokenFamily.objects.get().is_live is False
    assert _refresh(APIClient(), t2, csrf_value).status_code == 401


def test_logout_all_inside_the_grace_window_revokes_every_session(account):
    """The logout-all half of the correction above: a grace-window replay
    of T1 is a redemption, so it revokes every session of the user."""
    victim = _login()
    _login()
    old = victim.cookies[POLICY.refresh_name].value
    csrf_value = victim.cookies[POLICY.csrf_name].value
    assert _refresh(victim, old, csrf_value).status_code == 200

    assert _present(APIClient(), "logout-all", old, csrf_value).status_code == 200
    assert TokenFamily.objects.filter(revoked_at__isnull=True).count() == 0


def test_logout_with_a_rotated_refresh_token_is_detected_as_reuse(account):
    """R1's plain-logout half: logout only verified the signature, so an
    old refresh token replayed there revoked its family as an ordinary
    ``LOGOUT`` - a stolen credential used, and no one told. It must go
    through the same replay handling as refresh: burned as
    ``REUSE_DETECTED``, and ``token_reuse_detected`` sent. Red on revert of
    the ``_redeem`` call in ``RotationPolicy.revoke`` (reason is
    ``LOGOUT``, no signal).
    """
    victim = _login()
    old = victim.cookies[POLICY.refresh_name].value
    csrf_value = victim.cookies[POLICY.csrf_name].value
    assert _refresh(victim, old, csrf_value).status_code == 200
    cache.clear()  # the grace window has passed

    detected = []

    def _receiver(sender, family, **kwargs):
        detected.append(family.pk)

    token_reuse_detected.connect(_receiver)
    try:
        response = _present(APIClient(), "logout", old, csrf_value)
    finally:
        token_reuse_detected.disconnect(_receiver)

    assert response.status_code == 200
    family = TokenFamily.objects.get()
    assert family.revoked_reason == RevocationReason.REUSE_DETECTED
    assert detected == [family.pk]
