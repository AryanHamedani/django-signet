"""``signet.E008``: every mounted endpoint that reads the refresh cookie
sits under that cookie's ``Path``."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from django.conf import settings
from django.core.checks import CheckMessage, Error
from django.urls import NoReverseMatch, URLResolver, get_resolver, reverse

from django_signet.checks._common import _raw_signet
from django_signet.views import RefreshCredentialView


def _named_views(
    resolver: URLResolver, namespaces: tuple[str, ...] = ()
) -> Iterator[tuple[str, Any]]:
    """Every named, class-based route in the URLconf, as
    ``(qualified_name, view_class)``."""
    for entry in resolver.url_patterns:
        if isinstance(entry, URLResolver):
            nested = (*namespaces, entry.namespace) if entry.namespace else namespaces
            yield from _named_views(entry, nested)
        elif entry.name and hasattr(entry.callback, "view_class"):
            yield ":".join((*namespaces, entry.name)), entry.callback.view_class


def _cookie_path_covers(cookie_path: str, url: str) -> bool:
    """Whether a browser sends a cookie scoped to ``cookie_path`` to
    ``url``. Paths match at ``/`` boundaries (RFC 6265 section 5.1.4), not
    as string prefixes: ``/api/auth`` covers ``/api/auth/refresh`` but not
    ``/api/authn/refresh``."""
    if not url.startswith(cookie_path):
        return False
    return (
        len(url) == len(cookie_path)
        or cookie_path.endswith("/")
        or url[len(cookie_path)] == "/"
    )


def _refresh_path_error(name: str, view_class: Any) -> CheckMessage | None:
    if not (
        isinstance(view_class, type) and issubclass(view_class, RefreshCredentialView)
    ):
        return None
    policy = view_class.transport.cookie_policy
    if policy is None:
        return None  # a header transport sets no cookie to scope
    if not isinstance(policy.refresh_path, str):
        return None  # signet.E006 reports the real problem
    try:
        url = reverse(name)
    except NoReverseMatch:
        return None  # a route that needs arguments has no single URL
    if _cookie_path_covers(policy.refresh_path, url):
        return None
    return Error(
        f"{view_class.__name__} is mounted at {url!r}, outside its refresh "
        f"cookie's path {policy.refresh_path!r}.",
        hint="A browser only sends a cookie to URLs under its Path, so "
        "refresh, logout and logout-all would never receive the refresh "
        "cookie - refresh fails and logout cannot revoke, with no error. "
        "Set COOKIE_REFRESH_PATH (or the realm's CookiePolicy refresh_path) "
        "to the prefix the auth URLs are mounted at.",
        id="signet.E008",
    )


def check_refresh_cookie_path(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Every mounted endpoint that reads the refresh cookie must sit under
    that cookie's ``Path``.

    Walks the real URLconf rather than trusting the default mount point,
    so it covers ``django_signet.urls`` mounted anywhere and every realm
    built with ``signet_urls()``. Mounting at ``/auth/`` with the default
    ``/api/auth/`` path is caught here, at startup, instead of surfacing as
    silent refresh failures in production.
    """
    if not getattr(settings, "ROOT_URLCONF", None):
        return []
    if not isinstance(_raw_signet(), dict | None):
        return []  # signet.E005 reports the real problem
    found = (
        _refresh_path_error(name, view_class)
        for name, view_class in _named_views(get_resolver())
    )
    return [error for error in found if error is not None]
