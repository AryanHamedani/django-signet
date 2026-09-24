"""Run a callback so that its database failure cannot roll back ours.

A signal receiver or an event hook runs inside whatever transaction the
library, or the project (``ATOMIC_REQUESTS``), has open. Catching the
exception it raises is not enough on its own: a database write that fails
inside a transaction has already marked that transaction for rollback, so
the revocation or burn written just before it would be silently undone
when the transaction ends. Under a savepoint only the callback's own
writes are rolled back.
"""

from __future__ import annotations

import contextlib
from contextlib import AbstractContextManager
from typing import Any

from django.db import transaction


def savepoint_if_in_transaction() -> AbstractContextManager[Any]:
    """A savepoint when a transaction is open, otherwise nothing: in
    autocommit a failed statement affects only itself, and opening a
    transaction just for the callback would change when its writes
    commit."""
    if transaction.get_connection().in_atomic_block:
        return transaction.atomic()
    return contextlib.nullcontext()
