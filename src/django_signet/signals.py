"""The library's signals, and the one function that sends them.

Signals exist for observability - logging, metrics, alerting. They must
never change an authentication outcome, so every one of them is sent
through :func:`send`, never ``Signal.send()``: a receiver that raises is
logged and skipped, and the login, refresh, logout or revocation that sent
it completes exactly as it would have with no receiver connected.

That matters most for ``family_revoked``, which fires inside the
transaction that consumes a refresh token and revokes its family at
logout: a receiver exception propagating out of it would roll the
revocation back and leave the session live. Swallowing the exception is
not enough on its own - a receiver whose database write fails has already
marked the enclosing transaction for rollback - so inside a transaction
the receivers run under a savepoint of their own.

A decision that *should* be able to affect the outcome belongs in a hook
such as ``BaseJWTAuthentication.on_authentication_failed``, not a
receiver. ``RotationPolicy.on_reuse_detected`` is contained like a
receiver, for the same reason: it runs after a burn that must not be
rolled back.
"""

from __future__ import annotations

import logging
from typing import Any

import django.dispatch

from django_signet.isolation import savepoint_if_in_transaction

logger = logging.getLogger(__name__)

#: Sent after a successful login, with keyword arguments ``user``,
#: ``family`` and ``request``. ``family`` is whatever the configured store
#: returns - a :class:`TokenFamily <django_signet.sessions.models.TokenFamily>`
#: under the ORM store, the cache store's own record under the cache store.
token_issued = django.dispatch.Signal()

#: Sent after a successful refresh, with the same ``user``, ``family`` and
#: ``request`` arguments as :data:`token_issued`.
token_refreshed = django.dispatch.Signal()

#: Sent when a consumed refresh token is presented again - to refresh,
#: logout or logout-all - and the grace window holds no pair for it, with
#: ``user``, ``family`` and ``request``. Sent whether or not
#: ``RotationPolicy.burn_family_on_reuse`` burns the family. When it does,
#: the store has already revoked the family, but the ``family`` object
#: passed is the one read before the burn, so its ``revoked_at`` is still
#: ``None``: ask the store (``is_live()``).
#: ``request`` is always ``None``: reuse is detected inside
#: :class:`RotationPolicy <django_signet.sessions.rotation.RotationPolicy>`,
#: which never sees the HTTP request that triggered it.
token_reuse_detected = django.dispatch.Signal()

#: Sent the first time a family is revoked - logout, logout-all, reuse
#: detection, a password change, a refresh by an inactive account
#: (recorded as ``ADMIN``), or code calling ``revoke_family()`` -
#: with ``user``, ``family`` and ``reason`` (a :class:`RevocationReason
#: <django_signet.sessions.models.RevocationReason>` value), and **no**
#: ``request``: it is sent by the store layer (``TokenFamily.revoke()``,
#: ``CacheTokenStore.revoke_family()``), not a view, so a receiver with a
#: required ``request`` parameter raises ``TypeError`` here. ``family`` is a
#: ``TokenFamily`` under the ORM store and the cache store's own record
#: under the cache store. Never sent a second time for the same family:
#: revocation is first-reason-wins. The cache store sends nothing when the
#: family's cache entry has already expired or been evicted: it records the
#: revocation, but has no user or family to report.
family_revoked = django.dispatch.Signal()

_NAMES: dict[django.dispatch.Signal, str] = {
    token_issued: "token_issued",
    token_refreshed: "token_refreshed",
    token_reuse_detected: "token_reuse_detected",
    family_revoked: "family_revoked",
}


def _describe(receiver: Any) -> str:
    module = getattr(receiver, "__module__", None)
    qualname = getattr(receiver, "__qualname__", None)
    if module and qualname:
        return f"{module}.{qualname}"
    return repr(receiver)


def send(signal: django.dispatch.Signal, sender: Any, **named: Any) -> None:
    """Send ``signal`` to every receiver, isolating each one's failure.

    Uses ``Signal.send_robust()``: every receiver is called even if an
    earlier one raised - unless that receiver has no ``__qualname__`` (a
    callable instance, a ``functools.partial``), when Django's own failure
    logging raises and the rest of the dispatch is abandoned and logged as
    a dispatch failure naming only the signal; connect plain functions or
    methods. No ``Exception`` a receiver raises reaches the
    caller (a ``BaseException`` such as ``SystemExit`` still propagates, as
    it does through any ``except Exception``). Each
    one is logged at ``error`` on the ``django_signet.signals`` logger,
    naming the signal and the receiver, with the receiver's traceback
    attached. (Django also logs it, without the signal's name, on
    ``django.dispatch``.)

    Inside a transaction the receivers run under a savepoint, so a
    receiver whose database write fails rolls back only the receivers'
    writes, never the sender's. A failure of the dispatch itself is logged
    and ignored too: Django's own failure logging raises for a receiver
    with no ``__qualname__``, such as a callable instance.

    Receivers' return values are discarded: nothing a receiver returns,
    and no ``Exception`` it raises, can change what the sender does next.
    """
    name = _NAMES.get(signal, repr(signal))
    try:
        with savepoint_if_in_transaction():
            responses = signal.send_robust(sender=sender, **named)
    except Exception:
        logger.exception(
            "signet: dispatching signal %s failed; the exception was logged "
            "and ignored, and the operation that sent the signal was not "
            "affected",
            name,
        )
        return
    for receiver, result in responses:
        if isinstance(result, Exception):
            logger.error(
                "signet: receiver %s of signal %s raised; the exception was "
                "logged and ignored, and the operation that sent the signal "
                "was not affected",
                _describe(receiver),
                name,
                exc_info=result,
            )
