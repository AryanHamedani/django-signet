"""During the move from Simple JWT: header clients get a keyword of their own."""

from django.urls import include, path

from django_signet.authentication import HeaderJWTAuthentication
from django_signet.transport.header import HeaderTransport
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin

# "Authorization: Signet <token>". Each class answers "not mine" to the
# other's keyword, so DRF moves on instead of refusing the request.
SIGNET_HEADER = HeaderTransport(keyword="Signet")


class MobileRealm(SignetViewMixin):
    transport = SIGNET_HEADER


class SignetHeaderAuthentication(HeaderJWTAuthentication):
    transport = SIGNET_HEADER


urlpatterns = [
    path("api/mobile/auth/", include(signet_urls(MobileRealm, namespace="mobile"))),
]
