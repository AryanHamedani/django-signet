"""A realm whose access tokens live two minutes instead of five."""

from datetime import timedelta

from django.urls import include, path

from django_signet.sessions.rotation import RotationPolicy
from django_signet.tokens.access import AccessToken
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin


class ShortLivedAccessToken(AccessToken):
    lifetime = timedelta(minutes=2)


class ShortLivedRotation(RotationPolicy):
    # The policy mints the tokens, so it chooses their class.
    access_token_class = ShortLivedAccessToken


class ShortLivedRealm(SignetViewMixin):
    rotation = ShortLivedRotation()  # an instance, as on SignetViewMixin


urlpatterns = [
    path("api/auth/", include(signet_urls(ShortLivedRealm))),
]
