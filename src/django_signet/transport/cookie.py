from __future__ import annotations

from typing import Any

from django_signet.conf import setting
from django_signet.exceptions import TransportError
from django_signet.transport.base import Transport


class CookiePolicy:
    """Cookie naming and flags.

    Every field uses the same ``setting()`` descriptor as the rest of the
    library, so resolution is uniform: a keyword passed to ``__init__``
    becomes an instance attribute and wins; otherwise the project's
    ``SIGNET`` dict is consulted; otherwise the library default applies.
    ``setting`` is a non-data descriptor, so the instance ``__dict__``
    shadows it naturally - that's the whole mechanism, nothing is
    reimplemented here.

    Prefix rules are browser-enforced, not stylistic:

    - ``__Host-`` requires Secure, Path=/, and no Domain.
    - ``__Secure-`` requires Secure only.

    A ``__Host-`` cookie with a non-root path is silently dropped by the
    browser - no error, the request just arrives unauthenticated - so the
    path-scoped refresh cookie must use ``__Secure-`` instead. It is
    confined to the auth endpoints (``/api/auth/`` by default: refresh,
    logout and logout-all all act on it), so it isn't sent on ordinary API
    calls - which is also why it can't be ``__Host-``: that would need
    ``Path=/``. The CSRF cookie is root-scoped like the access
    cookie: it has to reach every state-changing endpoint, and the same
    ``__Host-``/``__Secure-`` protection matters for it too, since an
    unprefixed double-submit cookie can be overwritten by a sibling
    subdomain (RFC 6265bis "cookie tossing"), which would defeat the CSRF
    check entirely.
    """

    prefix = setting("COOKIE_PREFIX")
    samesite = setting("COOKIE_SAMESITE")
    secure = setting("COOKIE_SECURE")
    httponly = setting("COOKIE_HTTPONLY")
    refresh_path = setting("COOKIE_REFRESH_PATH")
    domain = setting("COOKIE_DOMAIN")
    explicit_access_name = setting("COOKIE_ACCESS_NAME")
    explicit_refresh_name = setting("COOKIE_REFRESH_NAME")
    explicit_csrf_name = setting("COOKIE_CSRF_NAME")

    @classmethod
    def _overridable(cls) -> frozenset[str]:
        """The actual set of ``__init__``-overridable fields: the
        ``setting()``-backed descriptors, and nothing else.

        Deliberately narrower than ``hasattr(type(self), key)``, which is
        true for *any* class attribute - a method like ``resolved_name`` or
        a read-only ``@property`` like ``access_name`` would pass that
        check and then either silently corrupt the instance (for a method)
        or raise the wrong exception, an ``AttributeError`` from the
        property setter rather than the ``TypeError`` this constructor
        promises (for a property). Walking ``__mro__`` rather than just
        ``vars(cls)`` keeps this correct for a subclass of ``CookiePolicy``
        too.
        """
        return frozenset(
            name
            for klass in cls.__mro__
            for name, value in vars(klass).items()
            if isinstance(value, setting)
        )

    def __init__(self, **overrides: Any) -> None:
        overridable = self._overridable()
        for key, value in overrides.items():
            if key not in overridable:
                raise TypeError(f"CookiePolicy got an unexpected field {key!r}")
            setattr(self, key, value)

    def resolved_name(self, base: str, *, root_path: bool) -> str:
        """Apply the ``__Host-``/``__Secure-`` prefix rules to ``base``.

        ``root_path`` says whether the cookie this name is for is scoped to
        ``Path=/`` (true for access and CSRF) or to a narrower path (the
        refresh cookie), because ``__Host-`` is only valid on the former.
        """
        if not self.secure:
            return base
        if root_path and self.domain is None:
            return f"__Host-{base}"
        return f"__Secure-{base}"

    @property
    def access_name(self) -> str:
        """The access cookie's name: ``COOKIE_ACCESS_NAME`` verbatim if
        set, else ``prefix-access`` with the ``__Host-``/``__Secure-``
        prefix applied. Root-scoped, so ``__Host-`` is available to it."""
        return self.explicit_access_name or self.resolved_name(
            f"{self.prefix}-access", root_path=True
        )

    @property
    def refresh_name(self) -> str:
        """The refresh cookie's name, resolved the same way as
        :attr:`access_name`. Path-scoped, so ``__Host-`` is invalid here
        by definition - only ``__Secure-`` applies."""
        # Path-scoped, so __Host- is invalid here by definition.
        return self.explicit_refresh_name or self.resolved_name(
            f"{self.prefix}-refresh", root_path=False
        )

    @property
    def csrf_name(self) -> str:
        """The CSRF cookie's name, resolved the same way as
        :attr:`access_name`. Readable by JavaScript (never ``httponly``),
        but not exempt from the ``__Host-``/``__Secure-`` prefix rules -
        see the class docstring on cookie tossing."""
        # Deliberately readable by JavaScript (not httponly): the client
        # must echo it back. That doesn't exempt it from prefixing - see
        # the class docstring on cookie tossing.
        #
        # root_path=True assumes the CSRF cookie is always set at Path=/.
        # That assumption lives here, not just in whoever calls
        # set_cookie(): if a later task ever scopes the CSRF cookie more
        # narrowly than root, __Host- becomes invalid for it in exactly the
        # same silent-drop way described on resolved_name(), and this
        # property must change to root_path=False (matching refresh_name)
        # at the same time the path narrows. Do not scope the CSRF cookie
        # without revisiting this line.
        return self.explicit_csrf_name or self.resolved_name(
            f"{self.prefix}-csrf", root_path=True
        )


class CookieTransport(Transport):
    """Reads and writes tokens as `Secure`/`HttpOnly` cookies.

    Ambient by nature - the browser attaches cookies to every matching
    request on its own, which is exactly what makes this transport subject
    to CSRF (see ``is_ambient``) and exactly why the CSRF cookie exists.
    """

    policy: CookiePolicy = CookiePolicy()

    def __init__(self, policy: CookiePolicy | None = None) -> None:
        if policy is not None:
            self.policy = policy

    @property
    def is_ambient(self) -> bool:
        return True

    @property
    def cookie_policy(self) -> CookiePolicy:
        return self.policy

    def _read(self, request: Any, name: str) -> str:
        token = request.COOKIES.get(name)
        if not token:
            raise TransportError(f"no {name} cookie on the request")
        return str(token)

    def extract_access(self, request: Any) -> str:
        return self._read(request, self.policy.access_name)

    def extract_refresh(self, request: Any) -> str:
        return self._read(request, self.policy.refresh_name)

    def attach(self, response: Any, pair: Any) -> None:
        p = self.policy
        response.set_cookie(
            p.access_name,
            pair.access.value,
            expires=pair.access.expires_at,
            path="/",
            domain=p.domain,
            secure=p.secure,
            httponly=p.httponly,
            samesite=p.samesite,
        )
        response.set_cookie(
            p.refresh_name,
            pair.refresh.value,
            expires=pair.refresh.expires_at,
            path=p.refresh_path,
            domain=p.domain,
            secure=p.secure,
            httponly=p.httponly,
            samesite=p.samesite,
        )

    def clear(self, response: Any) -> None:
        p = self.policy
        for name, path in (
            (p.access_name, "/"),
            (p.refresh_name, p.refresh_path),
            (p.csrf_name, "/"),
        ):
            response.set_cookie(
                name,
                "",
                max_age=0,
                path=path,
                domain=p.domain,
                secure=p.secure,
                samesite=p.samesite,
            )
