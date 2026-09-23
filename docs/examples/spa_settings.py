"""An SPA at https://app.example.com calling an API at https://api.example.com.

The CORS_* names are django-cors-headers settings, not django-signet ones.
"""

SIGNET = {
    # Set every cookie for the whole site, so the frontend's JavaScript can
    # read the CSRF cookie the API sets.
    "COOKIE_DOMAIN": "example.com",
}

# Name the frontend's origin. Never allow every origin.
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
# fetch() with credentials: "include" fails its CORS check without this.
CORS_ALLOW_CREDENTIALS = True
# Login sends JSON; refresh, logout and unsafe API calls send X-CSRF-Token.
CORS_ALLOW_HEADERS = ["content-type", "x-csrf-token"]
