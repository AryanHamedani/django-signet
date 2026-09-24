"""A staff realm whose sessions cannot be opened, or carried in, elsewhere."""

from django.urls import include, path
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from django_signet.authentication import CookieJWTAuthentication
from django_signet.exceptions import TokenInvalid
from django_signet.sessions.rotation import RotationPolicy
from django_signet.transport.cookie import CookiePolicy, CookieTransport
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin

STAFF_COOKIES = CookieTransport(
    CookiePolicy(prefix="staff", refresh_path="/staff/auth/"),
)
REALM_CLAIM = {"realm": "staff"}


def require_staff_realm(claims):
    if claims.get("realm") != REALM_CLAIM["realm"]:
        raise TokenInvalid("the session was not opened at the staff realm")


class StaffRotationPolicy(RotationPolicy):
    def get_user(self, claims):
        # Refresh: refuse a refresh token minted by another realm.
        require_staff_realm(claims)
        return super().get_user(claims)


class StaffRealm(SignetViewMixin):
    transport = STAFF_COOKIES
    rotation = StaffRotationPolicy()
    # serializer_class = YourSecondFactorSerializer  # the stricter login
    # this binding protects; without one, any user who logs in here is
    # stamped as staff, so pair it with a permission class too.

    def get_claims(self, user):
        # Login and every refresh at this realm stamp its tokens, for
        # every user alike.
        _ = user
        return dict(REALM_CLAIM)


class StaffCookieAuthentication(CookieJWTAuthentication):
    transport = STAFF_COOKIES

    def validate_claims(self, claims):
        # Your views: refuse an access token minted by another realm.
        require_staff_realm(claims)


class StaffReportView(APIView):
    authentication_classes = (StaffCookieAuthentication,)
    permission_classes = (IsAdminUser,)  # still decides who the user is

    def get(self, request):
        return Response({"reports": [], "for": request.user.get_username()})


urlpatterns = [
    path("api/auth/", include("django_signet.urls")),
    path("staff/auth/", include(signet_urls(StaffRealm, namespace="staff"))),
    path("staff/api/reports", StaffReportView.as_view()),
]
