"""The library's signals, and the one function that sends them.

Signals exist for observability - logging, metrics, alerting. They must
never change an authentication outcome, so every one of them is sent
through :func:`send`, never ``Signal.send()``: a receiver that raises is
logged and skipped, and the login, refresh, logout or revocation that sent
it completes exactly as it would have with no receiver connected.

That matters most for ``family_revoked``, which fires inside the
transaction that consumes a refresh token and revokes its family at
logout: a receiver exception propagating out of it would roll the
revocation back and leave the session live.

A decision that *should* be able to affect the outcome belongs in a hook
(``RotationPolicy.on_reuse_detected``,
``BaseJWTAuthentication.on_authentication_failed``), not a receiver.
"""

from __future__ import annotations

import logging
from typing import Any

import django.dispatch

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

    Receivers' return values are discarded: nothing a receiver returns or
    raises can change what the sender does next.
    """
    name = _NAMES.get(signal, repr(signal))
    for receiver, result in signal.send_robust(sender=sender, **named):
        if isinstance(result, Exception):
            logger.error(
                "signet: receiver %s of signal %s raised; the exception was "
                "logged and ignored, and the operation that sent the signal "
                "was not affected",
                _describe(receiver),
                name,
                exc_info=result,
            )
