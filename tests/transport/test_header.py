import pytest
from django.test import RequestFactory

from django_signet.exceptions import TransportError
from django_signet.transport.header import HeaderTransport, HybridTransport


def test_reads_a_bearer_token():
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer a.b.c")
    assert HeaderTransport().extract_access(request) == "a.b.c"


def test_rejects_the_wrong_keyword():
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Basic a.b.c")
    with pytest.raises(TransportError):
        HeaderTransport().extract_access(request)


def test_rejects_a_malformed_header():
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer")
    with pytest.raises(TransportError):
        HeaderTransport().extract_access(request)


def test_rejects_a_missing_header():
    """No Authorization header at all is a different broken path than a
    malformed one; a `.split()`-only implementation could conflate them."""
    request = RequestFactory().get("/")
    with pytest.raises(TransportError):
        HeaderTransport().extract_access(request)


def test_header_transport_is_not_ambient():
    """The CSRF check in a later task keys off is_ambient, not class name -
    a header-only client isn't subject to ambient credential attachment."""
    assert HeaderTransport().is_ambient is False


def test_hybrid_prefers_the_cookie_then_falls_back_to_the_header():
    hybrid = HybridTransport()
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer from-header")
    assert hybrid.extract_access(request) == "from-header"

    request.COOKIES[hybrid.cookie.policy.access_name] = "from-cookie"
    assert hybrid.extract_access(request) == "from-cookie"


def test_hybrid_is_ambient():
    """Hybrid can be authenticated ambiently (via the cookie), so it must
    report True even though it can also serve header-only clients."""
    assert HybridTransport().is_ambient is True


def test_hybrid_raises_when_neither_transport_has_a_token():
    hybrid = HybridTransport()
    request = RequestFactory().get("/")
    with pytest.raises(TransportError):
        hybrid.extract_access(request)


def test_hybrid_used_cookie_true_when_the_cookie_authenticated():
    hybrid = HybridTransport()
    request = RequestFactory().get("/")
    request.COOKIES[hybrid.cookie.policy.access_name] = "from-cookie"
    assert hybrid.used_cookie(request) is True


def test_hybrid_used_cookie_false_when_only_the_header_authenticated():
    hybrid = HybridTransport()
    request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer from-header")
    assert hybrid.used_cookie(request) is False


def test_hybrid_policy_delegates_to_the_cookie_transports_policy():
    """Task 10's validate_csrf(request, self.transport.policy) needs this to
    be the cookie policy specifically - a hybrid has no policy of its own."""
    hybrid = HybridTransport()
    assert hybrid.policy is hybrid.cookie.policy
