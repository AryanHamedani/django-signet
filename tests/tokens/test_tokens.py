import time
import uuid

import pytest

from django_signet.exceptions import TokenInvalid
from django_signet.hashing import token_digest
from django_signet.tokens.access import AccessToken
from django_signet.tokens.backends import get_backend
from django_signet.tokens.refresh import RefreshToken


def test_digest_is_sha256_hex():
    d = token_digest("abc")
    assert len(d) == 64
    assert d == token_digest("abc")
    assert d != token_digest("abd")


def test_access_token_round_trip():
    minted = AccessToken().mint(subject="42")
    claims = AccessToken().verify(minted.value)
    assert claims["sub"] == "42"
    assert claims["typ"] == "access"
    assert claims["jti"] == minted.jti


def test_each_mint_has_a_unique_jti():
    a, b = AccessToken().mint(subject="42"), AccessToken().mint(subject="42")
    assert a.jti != b.jti


def test_refresh_token_carries_the_family_id():
    fam = str(uuid.uuid4())
    minted = RefreshToken().mint(subject="42", family_id=fam)
    assert RefreshToken().verify(minted.value)["sid"] == fam


def test_refresh_token_requires_a_family_id():
    with pytest.raises(ValueError, match="requires a family_id"):
        RefreshToken().mint(subject="42")


def test_a_refresh_token_is_rejected_by_the_access_verifier():
    """Token-type confusion: a long-lived refresh token must never be
    accepted where a short-lived access token is expected."""
    minted = RefreshToken().mint(subject="42", family_id=str(uuid.uuid4()))
    with pytest.raises(TokenInvalid):
        AccessToken().verify(minted.value)


def test_an_access_token_is_rejected_by_the_refresh_verifier():
    minted = AccessToken().mint(subject="42")
    with pytest.raises(TokenInvalid):
        RefreshToken().verify(minted.value)


def test_extra_claims_are_merged_but_cannot_overwrite_reserved_ones():
    minted = AccessToken().mint(subject="42", extra={"org": 7, "sub": "hacked"})
    claims = AccessToken().verify(minted.value)
    assert claims["org"] == 7
    assert claims["sub"] == "42"


def test_a_correctly_signed_token_missing_sub_is_rejected():
    """The signing backend only requires ``exp``, so a correctly-signed
    token missing ``sub`` (or ``jti``) passes the crypto layer intact. It
    must still be rejected here, at ``verify()``, rather than reaching a
    caller and blowing up as a ``KeyError`` - a 500 where a 401 belongs.

    Built by signing a claim dict directly through the backend, bypassing
    ``mint()`` entirely, since ``mint()`` always sets ``sub``.
    """
    raw = get_backend().sign({"typ": "access", "exp": int(time.time()) + 60})
    with pytest.raises(TokenInvalid):
        AccessToken().verify(raw)
