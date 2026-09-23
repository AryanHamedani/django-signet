"""The five endpoints, for the default configuration or for a realm.

``include("django_signet.urls")`` mounts the stock views, unchanged - the
zero-config setup. ``include(signet_urls(StaffRealm, namespace="staff"))``
mounts the same five endpoints configured by one ``SignetViewMixin``
subclass, so a custom transport, rotation policy or ``get_claims`` is
declared once and every endpoint of the realm uses it.
"""

from __future__ import annotations

from django.urls import URLPattern, path
from rest_framework.views import APIView

from django_signet.views import (
    LogoutAllView,
    LogoutView,
    SignetViewMixin,
    TokenObtainView,
    TokenRefreshView,
    TokenVerifyView,
)

# (route, view). Each route doubles as its URL name.
_ENDPOINTS: tuple[tuple[str, type[APIView]], ...] = (
    ("login", TokenObtainView),
    ("refresh", TokenRefreshView),
    ("verify", TokenVerifyView),
    ("logout", LogoutView),
    ("logout-all", LogoutAllView),
)


def _bind[V: APIView](view: type[V], realm: type[SignetViewMixin]) -> type[V]:
    """``view`` with ``realm`` mixed in ahead of it, so everything the realm
    declares overrides the stock view's defaults."""
    name = f"{realm.__name__}{view.__name__}"
    bound = type(name, (realm, view), {"__module__": realm.__module__})
    # type() is typed as returning a bare `type`; issubclass narrows it to
    # what it demonstrably is - a subclass of `view` - without a cast.
    if not issubclass(bound, view):
        raise TypeError(f"{name} is not a subclass of {view.__name__}")
    return bound


def signet_urls(
    realm: type[SignetViewMixin] | None = None, namespace: str = "django_signet"
) -> tuple[list[URLPattern], str]:
    """Build the five endpoints, as a ``(patterns, namespace)`` pair for
    ``include()``.

    ``realm`` is a ``SignetViewMixin`` subclass - not the mixin itself -
    whose attributes and hooks every endpoint inherits. ``None`` (the
    default) means the stock views, unchanged.

    Mount the result where the realm's refresh cookie path points: the
    refresh cookie has to reach refresh, logout and logout-all, and system
    check ``signet.E008`` fails startup when it cannot.
    """
    patterns = [
        path(route, (_bind(view, realm) if realm else view).as_view(), name=route)
        for route, view in _ENDPOINTS
    ]
    return patterns, namespace


urlpatterns, app_name = signet_urls()
