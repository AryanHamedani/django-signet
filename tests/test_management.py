"""Final review, Group G: I7 - ``signet_purge``."""

from __future__ import annotations

from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.utils import timezone

from django_signet.models import IssuedToken, TokenFamily
from django_signet.sessions.rotation import RotationPolicy

pytestmark = pytest.mark.django_db


def test_signet_purge_deletes_expired_families_and_keeps_live_ones(user):
    """I7: ``purge_expired()`` existed but nothing ever called it, so
    expired families (and their tokens) accumulated forever."""
    expired = RotationPolicy().open_session(user).family
    live = RotationPolicy().open_session(user).family
    TokenFamily.objects.filter(pk=expired.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )

    out = StringIO()
    call_command("signet_purge", stdout=out)

    assert list(TokenFamily.objects.values_list("pk", flat=True)) == [live.pk]
    assert not IssuedToken.objects.filter(family_id=expired.pk).exists()
    assert "Purged 1 expired session family." in out.getvalue()


def test_signet_purge_uses_the_configured_store(user, settings):
    """Through ``get_store()``, like everything else: a cache store's
    entries expire on their own, so it reports nothing to purge."""
    settings.SIGNET = {"STORE": "django_signet.sessions.stores.cache.CacheTokenStore"}
    out = StringIO()
    call_command("signet_purge", stdout=out)
    assert "Purged 0 expired session families." in out.getvalue()
