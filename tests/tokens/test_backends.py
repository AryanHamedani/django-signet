import time
from datetime import timedelta

import jwt
import pytest

from django_signet.exceptions import TokenExpired, TokenInvalid
from django_signet.tokens.backends import HMACBackend


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
    """An attacker strips the signature and claims alg=none."""
    forged = jwt.encode({"sub": "999"}, key="", algorithm="none")
    with pytest.raises(TokenInvalid):
        backend.verify(forged)


def test_rejects_algorithm_substitution(backend):
    """A token signed HS512 must not verify on an HS256 backend."""
    forged = jwt.encode(
        {"sub": "999", "exp": int(time.time()) + 60}, key="k" * 64, algorithm="HS512"
    )
    with pytest.raises(TokenInvalid):
        backend.verify(forged)


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
