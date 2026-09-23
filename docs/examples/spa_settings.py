"""An SPA at https://app.example.com calling an API at https://api.example.com.

The CORS_* names are django-cors-headers settings, not django-signet ones.
"""

from corsheaders.defaults import default_headers

SIGNET = {
    # Set every cookie for the whole site, so the frontend's JavaScript can
    # read the CSRF cookie the API sets.
    "COOKIE_DOMAIN": "example.com",
}

# Name the frontend's origin. Never allow every origin.
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
# fetch() with credentials: "include" fails its CORS check without this.
CORS_ALLOW_CREDENTIALS = True
# The package's defaults, plus the header refresh, logout and every unsafe
# request send. The defaults include content-type, for the JSON login, and
# authorization, for a header realm.
CORS_ALLOW_HEADERS = (*default_headers, "x-csrf-token")
