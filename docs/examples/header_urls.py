"""A header realm for mobile and service clients, beside the browser one."""

from django.urls import include, path
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django_signet.authentication import HeaderJWTAuthentication
from django_signet.transport.header import HeaderTransport
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin


class MobileRealm(SignetViewMixin):
    """Tokens travel in the response body and in ``Authorization: Bearer``."""

    transport = HeaderTransport()


class MeView(APIView):
    """One of your own views, authenticated by a bearer access token."""

    authentication_classes = (HeaderJWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({"user": request.user.get_username()})


urlpatterns = [
    path("api/auth/", include("django_signet.urls")),  # the browser realm
    path("api/mobile/auth/", include(signet_urls(MobileRealm, namespace="mobile"))),
    path("api/me", MeView.as_view(), name="me"),
]
