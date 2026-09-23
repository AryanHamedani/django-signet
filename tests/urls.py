from django.urls import include, path

urlpatterns = [path("api/auth/", include("django_signet.urls"))]
