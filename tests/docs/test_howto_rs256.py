"""``docs/howto/rs256.md``: RS256 signing, and a verify-only resource server.

The key pair is generated here, once per module, and handed to the
examples through the environment, as the page tells the reader to. No key
material is committed.
"""

import importlib
from io import StringIO

import jwt
import pytest
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from tests.docs.helpers import settings_of

# The rsa extra, django-signet[rsa]. CI installs it; skip where it is absent.
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

CREDENTIALS = {"username": "alice", "password": "pw-not-used-in-assertions"}


@pytest.fixture(scope="module")
def key_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def keys_in_env(monkeypatch, key_pair):
    private_pem, public_pem = key_pair
    monkeypatch.setenv("SIGNET_SIGNING_KEY", private_pem)
    monkeypatch.setenv("SIGNET_VERIFYING_KEY", public_pem)
    return key_pair


def _load(name):
    """Import a settings example afresh, so it reads the current environment."""
    return importlib.reload(importlib.import_module(f"examples.{name}"))


@pytest.fixture
def auth_server(keys_in_env):
    return settings_of(_load("rs256_settings"))


@pytest.fixture
def resource_server(keys_in_env):
    return settings_of(_load("rs256_resource_settings"))


def _mobile_login():
    response = APIClient().post(reverse("mobile:login"), CREDENTIALS, format="json")
    assert response.status_code == 200
    return response.json()


def _me(access):
    return APIClient().get(reverse("me"), headers={"Authorization": f"Bearer {access}"})


def test_the_settings_read_both_keys_from_the_environment(auth_server, key_pair):
    assert auth_server["SIGNET"] == {
        "ALGORITHM": "RS256",
        "SIGNING_KEY": key_pair[0],
        "VERIFYING_KEY": key_pair[1],
    }


def test_the_settings_fail_at_import_without_the_keys(monkeypatch):
    monkeypatch.delenv("SIGNET_SIGNING_KEY", raising=False)
    with pytest.raises(KeyError):
        _load("rs256_settings")


@pytest.mark.django_db
def test_the_auth_server_signs_rs256(auth_server, user):
    with override_settings(ROOT_URLCONF="examples.header_urls", **auth_server):
        pair = _mobile_login()
        assert jwt.get_unverified_header(pair["access"])["alg"] == "RS256"
        assert _me(pair["access"]).json() == {"user": "alice"}
        with StringIO() as out, StringIO() as err:
            call_command("check", stdout=out, stderr=err)
            assert "signet." not in out.getvalue() + err.getvalue()


@pytest.mark.django_db
def test_a_resource_server_verifies_with_the_public_key_only(
    auth_server, resource_server, user
):
    assert "SIGNING_KEY" not in resource_server["SIGNET"]
    with override_settings(ROOT_URLCONF="examples.header_urls", **auth_server):
        pair = _mobile_login()
    with override_settings(ROOT_URLCONF="examples.header_urls", **resource_server):
        assert _me(pair["access"]).json() == {"user": "alice"}
        # It cannot mint: login fails with the server error the page names.
        with pytest.raises(ImproperlyConfigured):
            APIClient().post(reverse("mobile:login"), CREDENTIALS, format="json")


def test_a_resource_server_is_warned_w011_unless_it_silences_it(resource_server):
    unsilenced = {
        k: v for k, v in resource_server.items() if k != "SILENCED_SYSTEM_CHECKS"
    }
    with override_settings(**unsilenced), StringIO() as out, StringIO() as err:
        call_command("check", stdout=out, stderr=err)  # a warning does not fail
        assert "(signet.W011)" in err.getvalue()
    assert resource_server["SILENCED_SYSTEM_CHECKS"] == ["signet.W011"]
    with override_settings(**resource_server), StringIO() as out, StringIO() as err:
        call_command("check", stdout=out, stderr=err)
        assert "signet.W011" not in err.getvalue()
        assert "1 silenced" in out.getvalue()


def test_a_missing_verifying_key_is_error_e004(auth_server):
    signet = {k: v for k, v in auth_server["SIGNET"].items() if k != "VERIFYING_KEY"}
    with override_settings(SIGNET=signet), pytest.raises(SystemCheckError) as raised:
        call_command("check", stdout=StringIO(), stderr=StringIO())
    assert "(signet.E004)" in str(raised.value)


@pytest.mark.django_db
def test_a_refresh_sent_to_a_resource_server_spends_the_token(
    auth_server, resource_server, user
):
    """Pins why the page says not to mount the auth endpoints on a resource
    server: refresh consumes the token before signing its successor fails,
    so the client's retry at the issuing server is taken for reuse."""
    from django_signet.models import RevocationReason, TokenFamily

    with override_settings(ROOT_URLCONF="examples.header_urls", **auth_server):
        pair = _mobile_login()
    bearer = {"Authorization": f"Bearer {pair['refresh']}"}
    with override_settings(ROOT_URLCONF="examples.header_urls", **resource_server):
        client = APIClient(raise_request_exception=False)
        assert client.post(reverse("mobile:refresh"), headers=bearer).status_code == 500
    with override_settings(ROOT_URLCONF="examples.header_urls", **auth_server):
        # Within the grace window, too: the failed refresh cached no pair.
        retry = APIClient().post(reverse("mobile:refresh"), headers=bearer)
    assert retry.status_code == 401
    assert TokenFamily.objects.get().revoked_reason == RevocationReason.REUSE_DETECTED
