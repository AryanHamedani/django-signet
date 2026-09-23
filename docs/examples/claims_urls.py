"""Custom claims: derived from the user at login and at every refresh."""

from django.urls import include, path
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django_signet.authentication import CookieJWTAuthentication
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin


class AppRealm(SignetViewMixin):
    def get_claims(self, user):
        # From the database, never from the request.
        return {"groups": sorted(user.groups.values_list("name", flat=True))}


class GroupsView(APIView):
    authentication_classes = (CookieJWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        # request.auth holds the access token's verified claims. A token
        # minted before AppRealm was deployed has no "groups" claim.
        return Response({"groups": request.auth.get("groups", [])})


urlpatterns = [
    # In place of include("django_signet.urls"): the same five endpoints,
    # the same URL names, with AppRealm's get_claims.
    path("api/auth/", include(signet_urls(AppRealm))),
    path("api/groups", GroupsView.as_view()),
]
