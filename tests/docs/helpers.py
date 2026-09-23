"""Helpers shared by the documentation tests."""

from rest_framework.settings import api_settings


def settings_of(module):
    """The settings a settings example defines: its upper-case names."""
    return {k: v for k, v in vars(module).items() if k.isupper()}


def wire_header(meta_key):
    """A WSGI ``META`` key as the header name a client sends.

    ``HTTP_X_CSRF_TOKEN`` -> ``X-CSRF-TOKEN``. Header names are
    case-insensitive on the wire, so callers compare them lower-cased.
    """
    assert meta_key.startswith("HTTP_")
    return meta_key.removeprefix("HTTP_").replace("_", "-")


def use_rest_framework_defaults(monkeypatch, *views):
    """Give example views the ``REST_FRAMEWORK`` defaults now in effect.

    ``APIView`` copies ``DEFAULT_AUTHENTICATION_CLASSES`` and
    ``DEFAULT_PERMISSION_CLASSES`` into class attributes when DRF is first
    imported. In the reader's project the settings exist by then. Here DRF
    was imported under ``tests.settings``, so an ``override_settings`` alone
    would leave the example views with DRF's stock defaults (``AllowAny``).
    Call this inside the override. It refuses a view that sets either
    attribute itself, because then the defaults are not what it uses.
    """
    for view in views:
        for name, value in (
            ("authentication_classes", api_settings.DEFAULT_AUTHENTICATION_CLASSES),
            ("permission_classes", api_settings.DEFAULT_PERMISSION_CLASSES),
        ):
            assert name not in vars(view), f"{view.__name__} sets {name} itself"
            monkeypatch.setattr(view, name, value)
