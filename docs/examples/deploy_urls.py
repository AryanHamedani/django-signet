"""The auth views mounted at /auth/ rather than the default /api/auth/."""

from django.urls import include, path

urlpatterns = [
    # Nothing else under /auth/: the refresh cookie is sent to every URL
    # below its path, not only to refresh, logout and logout-all.
    path("auth/", include("django_signet.urls")),
]
