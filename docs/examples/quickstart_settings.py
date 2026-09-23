"""What the quickstart adds to a project's settings."""

INSTALLED_APPS = [
    # ...the other apps startproject created, including these three:
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.staticfiles",
    # Added by this tutorial:
    "rest_framework",
    "django_signet",
    "notes",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_signet.authentication.CookieJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}
