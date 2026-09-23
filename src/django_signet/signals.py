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

import contextlib
import logging
from typing import Any

import django.dispatch
from django.db import transaction

logger = logging.getLogger(__name__)

token_issued = django.dispatch.Signal()  # user, family, request
token_refreshed = django.dispatch.Signal()  # user, family, request
# user, family, request - and request is always None: reuse is detected
# inside RotationPolicy, which never sees the HTTP request.
token_reuse_detected = django.dispatch.Signal()
family_revoked = django.dispatch.Signal()  # user, family, reason

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
    earlier one raised, and no receiver exception reaches the caller. Each
    one is logged at ``error`` on the ``django_signet.signals`` logger,
    naming the signal and the receiver, with the receiver's traceback
    attached. (Django also logs it, without the signal's name, on
    ``django.dispatch``.)

    Inside a transaction the receivers run under a savepoint, so a
    receiver whose database write fails rolls back only the receivers'
    writes, never the sender's. A failure of the dispatch itself is logged
    and ignored too: Django's own failure logging raises for a receiver
    with no ``__qualname__``, such as a callable instance.

    Receivers' return values are discarded: nothing a receiver returns or
    raises can change what the sender does next.
    """
    name = _NAMES.get(signal, repr(signal))
    isolation = (
        transaction.atomic()
        if transaction.get_connection().in_atomic_block
        else contextlib.nullcontext()
    )
    try:
        with isolation:
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
