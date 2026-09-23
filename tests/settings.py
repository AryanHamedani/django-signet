SECRET_KEY = "test-secret-key-not-for-production-use-0123456789abcdef"
DEBUG = False
USE_TZ = True
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django_signet",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
    # Used by tests/sessions/test_rotation.py to pin the documented
    # DummyCache footgun: it accepts writes and silently discards them.
    "dummy": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"},
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
ROOT_URLCONF = "tests.urls"
# The live server (tests/docs/test_client_node.py) builds its static-files
# handler from STATIC_URL when it starts, and fails every request without one.
STATIC_URL = "static/"
