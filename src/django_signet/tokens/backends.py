from __future__ import annotations

import abc
from datetime import timedelta
from typing import Any

import jwt
from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured

from django_signet.conf import setting
from django_signet.exceptions import TokenExpired, TokenInvalid

_ZERO = timedelta(0)


class SigningBackend(abc.ABC):
    """Port for signing and verifying a JWT.

    Isolating this makes a future native backend a purely additive change: a
    new subclass, no edits to callers.
    """

    algorithm: str

    @abc.abstractmethod
    def sign(self, payload: dict[str, Any]) -> str:
        """Return ``payload`` encoded and signed as a compact JWS string."""

    @abc.abstractmethod
    def _decode(
        self,
        token: str,
        *,
        audience: str | None,
        issuer: str | None,
        leeway: timedelta,
    ) -> dict[str, Any]: ...

    def verify(
        self,
        token: str,
        *,
        audience: str | None = None,
        issuer: str | None = None,
        leeway: timedelta = _ZERO,
    ) -> dict[str, Any]:
        """Decode and verify ``token``, translating every failure into a
        ``SignetError`` subclass - never a raw ``PyJWTError`` or another
        crypto-library exception - so callers only ever handle this
        library's own exception taxonomy.
        """
        try:
            return self._decode(token, audience=audience, issuer=issuer, leeway=leeway)
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpired(str(exc)) from exc
        except (jwt.PyJWTError, UnicodeError, TypeError, ValueError) as exc:
            # Covers bad signature, alg=none, algorithm substitution, wrong
            # audience, wrong issuer, and malformed input alike. The non-
            # PyJWTError types are here because PyJWT's own internals are not
            # exhaustively guarded: e.g. a lone UTF-16 surrogate in the token
            # reaches an unguarded `.encode("utf-8")` in PyJWS._load and
            # raises UnicodeEncodeError (a ValueError) rather than a
            # PyJWTError. ImproperlyConfigured is deliberately not caught
            # here - a misconfigured server is a 500, not a failed token.
            raise TokenInvalid(str(exc)) from exc


class HMACBackend(SigningBackend):
    """Symmetric HS256 / HS384 / HS512."""

    def __init__(self, algorithm: str = "HS256", key: str | None = None) -> None:
        if algorithm not in {"HS256", "HS384", "HS512"}:
            raise ValueError(f"{algorithm} is not an HMAC algorithm")
        self.algorithm = algorithm
        self._key = key

    @property
    def key(self) -> str:
        """The HMAC key: the one passed to ``__init__``, or
        ``settings.SECRET_KEY`` when none was given."""
        return self._key or django_settings.SECRET_KEY

    def sign(self, payload: dict[str, Any]) -> str:
        return jwt.encode(payload, self.key, algorithm=self.algorithm)

    def _decode(
        self,
        token: str,
        *,
        audience: str | None,
        issuer: str | None,
        leeway: timedelta,
    ) -> dict[str, Any]:
        # algorithms is pinned to exactly one value. Never trust the token's
        # own alg header - that is the algorithm-confusion attack.
        return jwt.decode(
            token,
            self.key,
            algorithms=[self.algorithm],
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            options={"require": ["exp"]},
        )


class RSABackend(SigningBackend):
    """Asymmetric RS256 / RS384 / RS512. Requires the ``rsa`` extra."""

    def __init__(
        self,
        algorithm: str = "RS256",
        private_key: str | None = None,
        public_key: str | None = None,
    ) -> None:
        if algorithm not in {"RS256", "RS384", "RS512"}:
            raise ValueError(f"{algorithm} is not an RSA algorithm")
        self.algorithm = algorithm
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, payload: dict[str, Any]) -> str:
        if self.private_key is None:
            raise ImproperlyConfigured("RSABackend requires a private_key to sign")
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def _decode(
        self,
        token: str,
        *,
        audience: str | None,
        issuer: str | None,
        leeway: timedelta,
    ) -> dict[str, Any]:
        if self.public_key is None:
            raise ImproperlyConfigured("RSABackend requires a public_key to verify")
        return jwt.decode(
            token,
            self.public_key,
            algorithms=[self.algorithm],
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            options={"require": ["exp"]},
        )


class _BackendFactory:
    algorithm = setting("ALGORITHM")
    signing_key = setting("SIGNING_KEY")
    verifying_key = setting("VERIFYING_KEY")


def get_backend() -> SigningBackend:
    """Build the backend named by the project's ``SIGNET`` settings."""
    cfg = _BackendFactory()
    if cfg.algorithm.startswith("HS"):
        return HMACBackend(algorithm=cfg.algorithm, key=cfg.signing_key)
    if cfg.algorithm.startswith("RS"):
        if cfg.verifying_key is None:
            raise ImproperlyConfigured(
                "SIGNET['VERIFYING_KEY'] must be set to use an RS algorithm"
            )
        return RSABackend(
            algorithm=cfg.algorithm,
            private_key=cfg.signing_key,
            public_key=cfg.verifying_key,
        )
    raise ValueError(f"Unsupported ALGORITHM: {cfg.algorithm!r}")
