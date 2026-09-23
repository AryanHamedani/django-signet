"""Adversarial suite, part 4: RS256 end to end, and ``aud``/``iss``.

``RSABackend`` and the RS branch of ``get_backend()`` had no end-to-end
test, and ``aud``/``iss`` minting was never exercised - so a regression
widening the RS algorithm pin, or dropping the audience from minted
tokens, would have passed the whole suite. The key pair is generated here,
per test session; no key material is committed.

These are coverage tests for code that already worked, so there was no
failing "before" to show. Each was instead confirmed to go red under the
mutation named in its docstring.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from django_signet.csrf import CSRF_HEADER
from django_signet.transport.cookie import CookiePolicy

pytestmark = pytest.mark.django_db
POLICY = CookiePolicy()
PASSWORD = "correct-horse-battery-staple"


def _key_pair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private, public


@pytest.fixture(scope="module")
def keys():
    return _key_pair()


@pytest.fixture
def rs256(settings, keys):
    private, public = keys
    settings.SIGNET = {
        "ALGORITHM": "RS256",
        "SIGNING_KEY": private,
        "VERIFYING_KEY": public,
    }
    return private, public


@pytest.fixture
def account(db):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(username="bob", password=PASSWORD)


def _login():
    client = APIClient()
    client.post(
        reverse("django_signet:login"),
        {"username": "bob", "password": PASSWORD},
        format="json",
    )
    return client


def _claims(account, **extra):
    return {
        "sub": str(account.pk),
        "typ": "access",
        "jti": str(uuid.uuid4()),
        "exp": int((timezone.now() + timedelta(hours=1)).timestamp()),
        **extra,
    }


def _verify_with(client, token):
    client.cookies[POLICY.access_name] = token
    return client.get(reverse("django_signet:verify"))


# ------------------------------------------------------------ RS256


def test_rs256_round_trip_through_login_refresh_and_verify(account, rs256):
    """The whole cycle under RS256 - and the minted token verifies with
    nothing but the public key, which is the advertised reason to choose
    RS256 (another service verifying without the signing secret). Red
    under mutation: swapping ``private_key``/``public_key`` in the RS
    branch of ``get_backend()``."""
    _, public = rs256
    client = _login()
    access = client.cookies[POLICY.access_name].value
    assert jwt.get_unverified_header(access)["alg"] == "RS256"
    assert jwt.decode(access, public, algorithms=["RS256"])["typ"] == "access"
    assert client.get(reverse("django_signet:verify")).status_code == 200

    refreshed = client.post(
        reverse("django_signet:refresh"),
        **{CSRF_HEADER: client.cookies[POLICY.csrf_name].value},
    )
    assert refreshed.status_code == 200
    assert client.get(reverse("django_signet:verify")).status_code == 200


def test_rs256_rejects_a_sibling_rs_algorithm_with_the_real_key(account, rs256):
    """Algorithm pinning, RS edition - the counterpart of
    ``test_an_algorithm_substitution_with_the_real_secret_is_rejected``.
    Same private key, re-signed RS512 instead of the configured RS256,
    with every required claim present so nothing else can reject it
    first. Red under mutation: widening ``algorithms=[self.algorithm]`` in
    ``RSABackend._decode`` to all three RS algorithms."""
    private, _ = rs256
    client = _login()
    forged = jwt.encode(_claims(account), private, algorithm="RS512")
    assert _verify_with(client, forged).status_code == 401


def test_rs256_rejects_a_token_signed_by_another_key(account, rs256):
    other_private, _ = _key_pair()
    client = _login()
    forged = jwt.encode(_claims(account), other_private, algorithm="RS256")
    assert _verify_with(client, forged).status_code == 401


# ------------------------------------------------------------ aud / iss


@pytest.fixture
def audience(settings):
    settings.SIGNET = {"AUDIENCE": "api.example.com", "ISSUER": "auth.example.com"}


def test_configured_audience_and_issuer_are_minted_and_enforced(account, audience):
    """Red under mutation: dropping ``audience=self.audience`` from
    ``Token.mint`` (the token then carries no ``aud`` and fails its own
    verification) or from ``Token.verify`` (PyJWT then rejects the token
    that *does* carry one)."""
    client = _login()
    access = client.cookies[POLICY.access_name].value
    claims = jwt.decode(access, options={"verify_signature": False})
    assert claims["aud"] == "api.example.com"
    assert claims["iss"] == "auth.example.com"
    assert client.get(reverse("django_signet:verify")).status_code == 200


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "attacker.example.com"},
        {"iss": "attacker.example.com"},
        {"aud": None},  # no audience at all
        {"iss": None},
    ],
    ids=["wrong-aud", "wrong-iss", "missing-aud", "missing-iss"],
)
def test_a_token_for_another_audience_or_issuer_is_rejected(
    account, audience, overrides
):
    """Correctly signed with the real secret, so only the ``aud``/``iss``
    checks can reject it."""
    from django.conf import settings as django_settings

    claims = _claims(account, aud="api.example.com", iss="auth.example.com")
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    forged = jwt.encode(claims, django_settings.SECRET_KEY, algorithm="HS256")
    assert _verify_with(_login(), forged).status_code == 401
