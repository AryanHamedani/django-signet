"""A job for your scheduler: delete expired sessions, and log how many."""

import logging
from io import StringIO

from django.core.management import call_command

logger = logging.getLogger(__name__)


def purge_expired_sessions():
    output = StringIO()
    call_command("signet_purge", stdout=output)
    logger.info(output.getvalue().strip())
