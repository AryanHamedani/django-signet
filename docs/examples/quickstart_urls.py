"""The quickstart's root URLconf."""

from django.urls import include, path
from notes.views import NotesView

urlpatterns = [
    # ...your existing URLs, such as the admin...
    # /api/auth/ is the refresh cookie's default path, COOKIE_REFRESH_PATH.
    path("api/auth/", include("django_signet.urls")),
    path("api/notes", NotesView.as_view()),
]
