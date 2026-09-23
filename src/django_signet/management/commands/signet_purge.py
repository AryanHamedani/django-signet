"""``manage.py signet_purge`` - delete expired sessions.

Run it on a schedule (cron, a Celery beat task, a platform scheduler).
Nothing else ever calls ``TokenStore.purge_expired()``, so without it the
ORM store keeps every expired family and its tokens forever.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from django_signet.sessions.stores.factory import get_store


class Command(BaseCommand):
    help = (
        "Delete expired session families, and their refresh-token digests, "
        "from the configured token store."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        _ = args, options  # BaseCommand's signature; this command takes none
        purged = get_store().purge_expired()
        noun = "family" if purged == 1 else "families"
        self.stdout.write(f"Purged {purged} expired session {noun}.")
