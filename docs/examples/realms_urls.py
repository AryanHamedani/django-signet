"""A staff realm beside the default one, and a staff-only view."""

from django.urls import include, path
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from django_signet.authentication import CookieJWTAuthentication
from django_signet.transport.cookie import CookiePolicy, CookieTransport
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin

# One transport for the realm and for its views: the cookies the staff
# endpoints set are then the cookies the staff views read.
STAFF_COOKIES = CookieTransport(
    CookiePolicy(prefix="staff", refresh_path="/staff/auth/"),
)


class StaffRealm(SignetViewMixin):
    """The five endpoints, setting __Host-staff-access and its siblings."""

    transport = STAFF_COOKIES


class StaffCookieAuthentication(CookieJWTAuthentication):
    transport = STAFF_COOKIES


class StaffReportView(APIView):
    authentication_classes = (StaffCookieAuthentication,)
    # The realm decides which cookie is read. This decides who gets in.
    permission_classes = (IsAdminUser,)

    def get(self, request):
        return Response({"reports": [], "for": request.user.get_username()})


urlpatterns = [
    path("api/auth/", include("django_signet.urls")),  # the default realm
    path("staff/auth/", include(signet_urls(StaffRealm, namespace="staff"))),
    # Outside /staff/auth/, so the refresh cookie is not sent here.
    path("staff/api/reports", StaffReportView.as_view()),
]
