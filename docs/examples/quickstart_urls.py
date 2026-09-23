"""The quickstart's root URLconf."""

from django.urls import include, path

urlpatterns = [
    # /api/auth/ is the refresh cookie's default path, COOKIE_REFRESH_PATH.
    path("api/auth/", include("django_signet.urls")),
]
