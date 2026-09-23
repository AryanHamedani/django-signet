import time
from datetime import timedelta

import jwt
import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from django_signet.exceptions import TokenExpired, TokenInvalid
from django_signet.tokens.backends import HMACBackend, get_backend


@pytest.fixture
def backend():
    return HMACBackend(key="k" * 64)


def test_round_trip(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) + 60})
    assert backend.verify(token)["sub"] == "1"


def test_rejects_tampered_signature(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) + 60})
    head, payload, _ = token.split(".")
    with pytest.raises(TokenInvalid):
        backend.verify(f"{head}.{payload}.deadbeef")


def test_rejects_alg_none(backend):
    """An attacker strips the signature and claims alg=none.

    This only demonstrates that an unsigned token is rejected — it does not
    isolate algorithm pinning as the cause. PyJWT independently refuses
    ``alg=none`` unless ``key=None`` is passed to ``decode()`` (never done
    here), and it independently rejects a payload with no ``exp`` claim via
    ``options={"require": ["exp"]}``. Give the forged token a valid ``exp``
    so at least the "no exp" reason is ruled out; the algorithm-pinning
    guarantee itself is what `test_rejects_algorithm_substitution` proves.
    """
    forged = jwt.encode(
        {"sub": "999", "exp": int(time.time()) + 60}, key="", algorithm="none"
    )
    with pytest.raises(TokenInvalid):
        backend.verify(forged)


def test_rejects_algorithm_substitution(backend):
    """A token signed HS512 must not verify on an HS256 backend.

    This is the test that specifically proves algorithm pinning is
    load-bearing: the forged token is correctly signed, has a valid ``exp``,
    and would decode successfully if `_decode()` derived ``algorithms`` from
    the token's own ``alg`` header instead of pinning to `self.algorithm`.
    """
    forged = jwt.encode(
        {"sub": "999", "exp": int(time.time()) + 60}, key="k" * 64, algorithm="HS512"
    )
    with pytest.raises(TokenInvalid):
        backend.verify(forged)


def test_rejects_malformed_unicode_input(backend):
    """A lone UTF-16 surrogate crashes PyJWT's internal `.encode("utf-8")`
    with a raw UnicodeEncodeError rather than a PyJWTError. `verify()` must
    still translate it to TokenInvalid rather than letting it escape as a
    500.
    """
    with pytest.raises(TokenInvalid):
        backend.verify("\ud800.\ud800.\ud800")


def test_raises_expired_distinctly(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) - 1})
    with pytest.raises(TokenExpired):
        backend.verify(token)


def test_leeway_tolerates_small_clock_skew(backend):
    token = backend.sign({"sub": "1", "exp": int(time.time()) - 2})
    assert backend.verify(token, leeway=timedelta(seconds=10))["sub"] == "1"


def test_audience_and_issuer_are_enforced(backend):
    token = backend.sign(
        {"sub": "1", "exp": int(time.time()) + 60, "aud": "api", "iss": "signet"}
    )
    assert backend.verify(token, audience="api", issuer="signet")["sub"] == "1"
    with pytest.raises(TokenInvalid):
        backend.verify(token, audience="other", issuer="signet")
    with pytest.raises(TokenInvalid):
        backend.verify(token, audience="api", issuer="elsewhere")


@override_settings(SIGNET={"ALGORITHM": "RS256"})
def test_get_backend_requires_verifying_key_for_rs_algorithms():
    """RS256 with no VERIFYING_KEY must fail fast at construction time, not
    500 on every subsequent authentication attempt."""
    with pytest.raises(ImproperlyConfigured):
        get_backend()
