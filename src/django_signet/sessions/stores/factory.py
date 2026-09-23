"""The one place a concrete :class:`TokenStore` is chosen.

Login, refresh and logout (``RotationPolicy``), the ``Strict*`` liveness
check (``BaseJWTAuthentication``) and password-change revocation all have
to agree on where sessions live. They once each constructed their own
store - one of them hardcoding ``ORMTokenStore()`` - so under a cache store
a password change revoked nothing, and a mismatched ``Strict*`` store
either rejected every request or failed open after logout.

Everything now resolves through :func:`get_store`, and an ``import-linter``
contract in ``pyproject.toml`` makes this module the only one allowed to
import a concrete adapter - so a fourth construction site is a CI failure,
not a review finding.
"""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from django_signet.conf import setting
from django_signet.sessions.stores.base import TokenStore


class _StoreSettings:
    store = setting("STORE")
    options = setting("STORE_OPTIONS")


def get_store() -> TokenStore:
    """Build the store named by ``SIGNET["STORE"]``.

    ``STORE`` is a dotted path (the default,
    ``"django_signet.sessions.stores.orm.ORMTokenStore"``, is one: a path
    rather than a class because ``settings.py`` cannot import a module that
    imports models) or a ``TokenStore`` subclass; ``STORE_OPTIONS`` is
    passed to its constructor as keyword arguments, in the same shape as
    Django's own ``CACHES[...]["OPTIONS"]``.

    Nothing is cached, matching every other ``setting()``: stores hold no
    per-request state and are cheap to build, and resolving afresh is what
    lets ``override_settings`` work.
    """
    cfg = _StoreSettings()
    try:
        factory = import_string(cfg.store) if isinstance(cfg.store, str) else cfg.store
        store: Any = factory(**(cfg.options or {}))
    except (ImportError, TypeError) as exc:
        raise ImproperlyConfigured(
            f"SIGNET['STORE'] = {cfg.store!r} with STORE_OPTIONS = "
            f"{cfg.options!r} could not be constructed: {exc}"
        ) from exc
    if not isinstance(store, TokenStore):
        raise ImproperlyConfigured(
            f"SIGNET['STORE'] = {cfg.store!r} built a {type(store).__name__}, "
            "which is not a django_signet TokenStore."
        )
    return store


class ConfiguredStore:
    """Descriptor: ``store = ConfiguredStore()`` resolves to
    :func:`get_store` on every access.

    The same resolution order as :class:`django_signet.conf.setting`: a
    literal assigned on a subclass (``store = CacheTokenStore()``) shadows
    this descriptor through normal attribute lookup and wins outright;
    otherwise the ``SIGNET`` setting decides.
    """

    def __get__(self, obj: object, owner: type | None = None) -> TokenStore:
        return get_store()
