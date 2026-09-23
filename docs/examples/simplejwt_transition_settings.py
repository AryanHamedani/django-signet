"""During the move from Simple JWT: accept both kinds of token."""

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_signet.authentication.CookieJWTAuthentication",
        # Remove once the last Simple JWT access token has expired.
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
}
