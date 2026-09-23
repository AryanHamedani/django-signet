from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from django_signet.authentication import (
    GENERIC_FAILURE,
    CookieJWTAuthentication,
    HeaderJWTAuthentication,
    HybridJWTAuthentication,
    StrictCookieJWTAuthentication,
    StrictHeaderJWTAuthentication,
    StrictHybridJWTAuthentication,
)
from django_signet.csrf import CSRF_HEADER
from django_signet.exceptions import TransportError
from django_signet.models import RevocationReason
from django_signet.sessions.rotation import RotationPolicy
from django_signet.tokens.access import AccessToken
from django_signet.transport.base import Transport

pytestmark = pytest.mark.django_db


@pytest.fixture
def pair(user):
    return RotationPolicy().open_session(user)


def _cookie_request(auth, pair, method="get", **extra):
    factory = getattr(APIRequestFactory(), method)
    request = factory("/", **extra)
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    return request


def _header_request(pair, method="get", **extra):
    factory = getattr(APIRequestFactory(), method)
    return factory("/", HTTP_AUTHORIZATION=f"Bearer {pair.access.value}", **extra)


# --------------------------------------------------------------- absence


def test_returns_none_when_no_cookie_is_present():
    """DRF contract: absence means 'not my scheme', not failure."""
    assert CookieJWTAuthentication().authenticate(APIRequestFactory().get("/")) is None


def test_returns_none_when_no_header_is_present():
    assert HeaderJWTAuthentication().authenticate(APIRequestFactory().get("/")) is None


def test_hybrid_returns_none_when_neither_credential_is_present():
    """A hybrid class must still say 'not mine' to a request carrying no
    credential at all - not raise, and not ask for CSRF (there is nothing
    to validate the CSRF pair against)."""
    assert HybridJWTAuthentication().authenticate(APIRequestFactory().get("/")) is None


def test_returns_none_does_not_mean_a_present_bad_token_is_ignored():
    """Guards the other half of the absence/failure split: a token that IS
    present but garbage must raise, not silently return None like the
    absence case above would. A broken implementation that swallowed every
    SignetError into None (instead of only TransportError) would pass the
    absence tests above but wrongly pass this one too - unless it asserts
    the raise, which is what this test does."""
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = "not-a-jwt-at-all"
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


# ------------------------------------------------------------- happy path


def test_authenticates_a_valid_cookie(pair, user):
    auth = CookieJWTAuthentication()
    authed, claims = auth.authenticate(_cookie_request(auth, pair))
    assert authed == user
    assert claims["typ"] == "access"


def test_authenticates_a_valid_bearer_header(pair, user):
    authed, _ = HeaderJWTAuthentication().authenticate(_header_request(pair))
    assert authed == user


def test_hybrid_authenticates_via_cookie(pair, user):
    auth = HybridJWTAuthentication()
    authed, _ = auth.authenticate(_cookie_request(auth, pair))
    assert authed == user


def test_hybrid_authenticates_via_header(pair, user):
    authed, _ = HybridJWTAuthentication().authenticate(_header_request(pair))
    assert authed == user


# --------------------------------------------------------- generic failure


def test_a_tampered_token_fails_generically(pair):
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value[:-2] + "xx"
    with pytest.raises(AuthenticationFailed) as exc:
        auth.authenticate(request)
    assert str(exc.value) == GENERIC_FAILURE


def test_every_failure_cause_produces_the_identical_message(pair, user):
    """A test that only checks the message excludes a couple of forbidden
    words (e.g. not "signature", not "expired") would still pass an
    implementation that leaked a *different* internal detail - "no such
    user", "csrf", "revoked", "inactive" are all still information
    disclosures. Pinning every distinct failure cause to the exact same
    string closes that whole class of leak at once, not just the two
    words a narrower test happened to think of."""
    auth = CookieJWTAuthentication()
    strict_auth = StrictCookieJWTAuthentication()

    tampered = APIRequestFactory().get("/")
    tampered.COOKIES[auth.transport.policy.access_name] = pair.access.value[:-2] + "xx"

    refresh_as_access = APIRequestFactory().get("/")
    refresh_as_access.COOKIES[auth.transport.policy.access_name] = pair.refresh.value

    csrf_missing = APIRequestFactory().post("/")
    csrf_missing.COOKIES[auth.transport.policy.access_name] = pair.access.value

    user.is_active = False
    user.save(update_fields=["is_active"])
    inactive = APIRequestFactory().get("/")
    inactive.COOKIES[auth.transport.policy.access_name] = pair.access.value

    pair.family.revoke(RevocationReason.LOGOUT)
    revoked = APIRequestFactory().get("/")
    revoked.COOKIES[strict_auth.transport.policy.access_name] = pair.access.value

    messages = set()
    for authenticator, request in (
        (auth, tampered),
        (auth, refresh_as_access),
        (auth, csrf_missing),
        (auth, inactive),
        (strict_auth, revoked),
    ):
        with pytest.raises(AuthenticationFailed) as exc:
            authenticator.authenticate(request)
        messages.add(str(exc.value))

    assert messages == {GENERIC_FAILURE}


def test_an_inactive_user_is_rejected(pair, user):
    """Regression guard for CVE-2024-22513: disabling an account must take
    effect immediately, not at token expiry. Would NOT fail against an
    implementation that skipped the is_active check entirely - that is
    the entire point of running it, so the failure mode is deliberate."""
    user.is_active = False
    user.save(update_fields=["is_active"])
    auth = CookieJWTAuthentication()
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(_cookie_request(auth, pair))


def test_an_active_user_with_explicit_true_still_authenticates(pair, user):
    """Companion to the inactive-user test: proves the check discriminates
    on the value, not merely on the attribute's presence."""
    user.is_active = True
    user.save(update_fields=["is_active"])
    auth = CookieJWTAuthentication()
    authed, _ = auth.authenticate(_cookie_request(auth, pair))
    assert authed == user


def test_a_refresh_token_cannot_authenticate(pair):
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = pair.refresh.value
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_unknown_subject_fails_generically(pair, user):
    """A well-signed token for a user who no longer exists must fail the
    same generic way as every other cause - not a 500 from a raw
    DoesNotExist escaping unhandled."""
    user_pk = user.pk
    auth = CookieJWTAuthentication()
    request = _cookie_request(auth, pair)
    user.delete()
    with pytest.raises(AuthenticationFailed) as exc:
        auth.authenticate(request)
    assert str(exc.value) == GENERIC_FAILURE
    assert str(user_pk) not in str(exc.value)


# ------------------------------------------------------------------- csrf


def test_unsafe_cookie_request_requires_the_csrf_header(pair):
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().post("/")
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_unsafe_cookie_request_passes_with_a_matching_csrf_pair(pair, user):
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().post("/", **{CSRF_HEADER: "tok"})
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    request.COOKIES[auth.transport.policy.csrf_name] = "tok"
    authed, _ = auth.authenticate(request)
    assert authed == user


def test_unsafe_cookie_request_with_mismatched_csrf_pair_fails(pair):
    """Would pass a broken implementation that only checked *presence* of
    both cookie and header (e.g. `if cookie and header`) rather than that
    they match."""
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().post("/", **{CSRF_HEADER: "wrong-token"})
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    request.COOKIES[auth.transport.policy.csrf_name] = "right-token"
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_safe_cookie_method_skips_csrf_even_with_no_pair(pair, user):
    """GET must not require a CSRF pair at all - the CSRF check must be
    gated on unsafe methods, not just "cookie transport was used"."""
    auth = CookieJWTAuthentication()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    authed, _ = auth.authenticate(request)
    assert authed == user


def test_header_auth_skips_csrf_because_it_is_not_ambient(pair, user):
    authed, _ = HeaderJWTAuthentication().authenticate(
        _header_request(pair, method="post", **{CSRF_HEADER: "irrelevant"})
    )
    assert authed == user


def test_hybrid_cookie_path_requires_csrf_on_unsafe_method(pair):
    """The half of the hybrid CSRF story that a class-name-only check
    (`isinstance(transport, CookieTransport)`) would get right by
    accident, but a naive "hybrid is never ambient" shortcut would get
    wrong."""
    auth = HybridJWTAuthentication()
    request = APIRequestFactory().post("/")
    request.COOKIES[auth.transport.policy.access_name] = pair.access.value
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_hybrid_header_path_skips_csrf_on_unsafe_method(pair, user):
    """The other half: a hybrid request authenticated via the header must
    NOT be asked for CSRF, even on POST, even though HybridTransport as a
    whole reports is_ambient=True. This is what used_cookie() exists to
    distinguish - a check that only consulted is_ambient would wrongly
    demand CSRF here and this test would catch that."""
    authed, _ = HybridJWTAuthentication().authenticate(
        _header_request(pair, method="post")
    )
    assert authed == user


# ------------------------------------------------------------ strict/non-strict


def test_non_strict_auth_still_works_after_revocation(pair, user):
    """Documented trade-off: the stateless fast path tolerates revocation
    up to the access token's lifetime. A 'fix' that made non-strict auth
    also check family liveness would break this test - that is the point
    of pinning it, not just the strict-rejects test below."""
    pair.family.revoke(RevocationReason.LOGOUT)
    auth = CookieJWTAuthentication()
    authed, _ = auth.authenticate(_cookie_request(auth, pair))
    assert authed == user


def test_strict_auth_rejects_immediately_after_revocation(pair):
    pair.family.revoke(RevocationReason.LOGOUT)
    auth = StrictCookieJWTAuthentication()
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(_cookie_request(auth, pair))


def test_strict_header_auth_rejects_immediately_after_revocation(pair):
    pair.family.revoke(RevocationReason.LOGOUT)
    with pytest.raises(AuthenticationFailed):
        StrictHeaderJWTAuthentication().authenticate(_header_request(pair))


def test_strict_hybrid_auth_rejects_immediately_after_revocation(pair):
    pair.family.revoke(RevocationReason.LOGOUT)
    with pytest.raises(AuthenticationFailed):
        StrictHybridJWTAuthentication().authenticate(_header_request(pair))


def test_strict_auth_still_authenticates_a_live_session(pair, user):
    """Companion to the rejection tests: proves strict mode isn't simply
    broken/always-failing - it must still accept a session that genuinely
    is live."""
    auth = StrictCookieJWTAuthentication()
    authed, _ = auth.authenticate(_cookie_request(auth, pair))
    assert authed == user


# --------------------------------------------------------------------- hooks


def test_on_authentication_failed_hook_receives_the_real_exception(pair):
    """Distinct internal exception types exist for hooks/logging, not the
    client. This proves the hook actually receives the specific
    SignetError subtype - if it only ever saw a generic wrapper, that
    contract would be broken even though the client-facing message is
    unaffected."""
    from django_signet.exceptions import TokenInvalid

    seen = []

    class LoggingAuth(CookieJWTAuthentication):
        def on_authentication_failed(self, exc):
            seen.append(exc)

    auth = LoggingAuth()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = "garbage"
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)

    assert len(seen) == 1
    assert isinstance(seen[0], TokenInvalid)


def test_validate_claims_hook_can_reject(pair):
    from django_signet.exceptions import TokenInvalid

    class TenantAuth(CookieJWTAuthentication):
        def validate_claims(self, claims):
            raise TokenInvalid("wrong tenant")

    auth = TenantAuth()
    with pytest.raises(AuthenticationFailed) as exc:
        auth.authenticate(_cookie_request(auth, pair))
    assert str(exc.value) == GENERIC_FAILURE


# ---------------------------------------------------- fix round 1: finding 1


def test_a_validation_error_from_a_malformed_subject_fails_generically(
    pair, monkeypatch
):
    """ValidationError is what a UUID-keyed custom user model's
    UUIDField.get_prep_value() raises for a `sub` that isn't a valid UUID
    (this project's own TokenFamily.id is one such field, so it's not
    exotic). This project's own User model has an integer pk and can't
    trigger it via a real lookup, and Django doesn't support swapping
    AUTH_USER_MODEL per-test once the app registry is loaded, so the
    manager is monkeypatched to reproduce the exact exception instead.
    Would fail against the pre-fix except clause - it doesn't list
    ValidationError, so it propagates unhandled as a 500 rather than the
    generic 401 every other bad-credential cause here produces."""
    user_model = get_user_model()

    def _raise_validation_error(*args, **kwargs):
        raise ValidationError("“not-a-uuid” is not a valid UUID.")

    monkeypatch.setattr(user_model.objects, "get", _raise_validation_error)

    auth = CookieJWTAuthentication()
    with pytest.raises(AuthenticationFailed) as exc:
        auth.authenticate(_cookie_request(auth, pair))
    assert str(exc.value) == GENERIC_FAILURE


# ---------------------------------------------------- fix round 1: finding 2


class _StubAmbientTransport(Transport):
    """Stands in for a hypothetical future ambient transport that carries
    no CookiePolicy, to prove a live CSRF decision can never be silently
    dropped just because ``_enforce_csrf_if_needed`` doesn't know how to
    enforce it for this transport."""

    def __init__(self, raw_token):
        self._raw_token = raw_token

    @property
    def is_ambient(self):
        return True

    def extract_access(self, request):
        return self._raw_token

    def extract_refresh(self, request):
        raise TransportError("not used by this test")

    def attach(self, response, pair):
        pass

    def clear(self, response):
        pass


def test_an_ambient_transport_with_no_csrf_policy_fails_loudly(pair):
    """A transport that is ambient but not Cookie/Hybrid used to sail
    through CSRF entirely unchecked - no exception, no log line. This
    proves the request now fails loudly (NotImplementedError) instead.
    Would fail against the pre-fix code, which returned a successful
    (user, claims) pair here with no exception raised at all."""

    class StubAuth(CookieJWTAuthentication):
        transport = _StubAmbientTransport(pair.access.value)

    auth = StubAuth()
    request = APIRequestFactory().post("/")
    with pytest.raises(NotImplementedError):
        auth.authenticate(request)


# ---------------------------------------------------- fix round 1: finding 3


def test_missing_is_active_attribute_fails_closed(pair, monkeypatch):
    """Fails closed, unlike Django's own ModelBackend: a user model with
    no is_active attribute at all must be rejected, not trusted - the
    entire point of hardening against CVE-2024-22513. SimpleNamespace has
    no is_active attribute at all (not even None), which a plain
    getattr(..., default) can't tell apart from "absent". Would fail
    against the original getattr(user, "is_active", None) with "None
    passes" logic, which would authenticate this stand-in successfully."""
    user_model = get_user_model()
    stand_in = SimpleNamespace(pk=1)  # deliberately no is_active attribute

    def _return_stand_in(*args, **kwargs):
        return stand_in

    monkeypatch.setattr(user_model.objects, "get", _return_stand_in)

    auth = CookieJWTAuthentication()
    with pytest.raises(AuthenticationFailed) as exc:
        auth.authenticate(_cookie_request(auth, pair))
    assert str(exc.value) == GENERIC_FAILURE


def test_is_active_true_still_authenticates(pair, user):
    """The other two branches of the three-way split, alongside the
    missing-attribute test above and the existing
    test_an_inactive_user_is_rejected (is_active=False)."""
    user.is_active = True
    user.save(update_fields=["is_active"])
    auth = CookieJWTAuthentication()
    authed, _ = auth.authenticate(_cookie_request(auth, pair))
    assert authed == user


# ---------------------------------------------------- fix round 1: finding 4


def test_strict_auth_rejects_a_token_with_no_sid_claim(user):
    """Every existing revocation test uses a real family id minted via
    open_session(), so a check_family() that treated a missing sid as
    "nothing to check" would pass them all while defeating the Strict*
    promise. Minting directly, not via open_session(), is what lets this
    test omit the claim. Would fail against a check_family() that
    returned early instead of raising when `sid` is absent."""
    raw = AccessToken().mint(str(user.pk)).value
    auth = StrictCookieJWTAuthentication()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = raw
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_strict_auth_rejects_a_token_with_a_malformed_sid_claim(user):
    """Companion to the missing-sid test: a `sid` present but not a valid
    UUID must also reject, not be silently ignored or crash as an
    unhandled 500."""
    raw = AccessToken().mint(str(user.pk), extra={"sid": "not-a-uuid"}).value
    auth = StrictCookieJWTAuthentication()
    request = APIRequestFactory().get("/")
    request.COOKIES[auth.transport.policy.access_name] = raw
    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)
