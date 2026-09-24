"""``docs/explanation/architecture.md``: polymorphism by subclassing, and the
import-linter contracts the page quotes.
"""

import tomllib
from pathlib import Path

import pytest
from django.test import override_settings
from django.urls import reverse
from examples.short_access_urls import ShortLivedAccessToken, ShortLivedRealm
from rest_framework.test import APIClient, APIRequestFactory

from django_signet.sessions.rotation import RotationPolicy
from django_signet.tokens.access import AccessToken
from django_signet.transport.cookie import CookiePolicy
from django_signet.views import SignetViewMixin, TokenObtainView

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "docs" / "explanation" / "architecture.md"
CREDENTIALS = {"username": "alice", "password": "pw-not-used-in-assertions"}


@pytest.mark.django_db
def test_the_realm_mints_two_minute_access_tokens(user):
    with override_settings(ROOT_URLCONF="examples.short_access_urls"):
        client = APIClient()
        response = client.post(
            reverse("django_signet:login"), CREDENTIALS, format="json"
        )
    assert response.status_code == 200
    claims = AccessToken().verify(client.cookies[CookiePolicy().access_name].value)
    # Minted by the subclass, verified by the stock class: the lifetime is a
    # property of the token that was minted, not of the verifier.
    assert claims["exp"] - claims["iat"] == 120


def test_the_realm_holds_a_policy_instance_like_the_mixin():
    assert isinstance(SignetViewMixin.rotation, RotationPolicy)
    assert isinstance(ShortLivedRealm.rotation, RotationPolicy)
    assert ShortLivedRealm.rotation.access_token_class is ShortLivedAccessToken


@pytest.mark.django_db
def test_a_rotation_class_instead_of_an_instance_raises_type_error(user):
    class Broken(SignetViewMixin):
        rotation = RotationPolicy  # the class, not an instance

    view = type("BrokenLogin", (Broken, TokenObtainView), {}).as_view()
    request = APIRequestFactory().post("/login", CREDENTIALS, format="json")
    with pytest.raises(TypeError):
        view(request)


def test_every_import_linter_contract_is_quoted_on_the_page():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    contracts = config["tool"]["importlinter"]["contracts"]
    text = PAGE.read_text()
    assert len(contracts) == 5
    for contract in contracts:
        assert contract["name"] in text, contract["name"]
        for module in contract.get("source_modules", []) + contract.get(
            "protected_modules", []
        ):
            assert f"`{module.removeprefix('django_signet.')}`" in text, module
