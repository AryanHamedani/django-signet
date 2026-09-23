from django.urls import path

from django_signet.views import (
    LogoutAllView,
    LogoutView,
    TokenObtainView,
    TokenRefreshView,
    TokenVerifyView,
)

app_name = "django_signet"

urlpatterns = [
    path("login", TokenObtainView.as_view(), name="login"),
    path("refresh", TokenRefreshView.as_view(), name="refresh"),
    path("verify", TokenVerifyView.as_view(), name="verify"),
    path("logout", LogoutView.as_view(), name="logout"),
    path("logout-all", LogoutAllView.as_view(), name="logout-all"),
]
