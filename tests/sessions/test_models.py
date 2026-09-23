from datetime import timedelta

import pytest
from django.db.utils import IntegrityError
from django.utils import timezone

from django_signet.models import IssuedToken, RevocationReason, TokenFamily
from django_signet.signals import family_revoked

pytestmark = pytest.mark.django_db


def _family(user, **kw):
    return TokenFamily.objects.create(
        user=user, expires_at=timezone.now() + timedelta(days=14), **kw
    )


def test_a_fresh_family_is_live(user):
    assert _family(user).is_live is True


def test_revoking_records_the_reason_and_ends_liveness(user):
    fam = _family(user)
    fam.revoke(RevocationReason.REUSE_DETECTED)
    fam.refresh_from_db()
    assert fam.is_live is False
    assert fam.revoked_reason == RevocationReason.REUSE_DETECTED
    assert fam.revoked_at is not None


def test_revoking_twice_keeps_the_first_reason(user):
    fam = _family(user)
    fam.revoke(RevocationReason.LOGOUT)
    first = fam.revoked_at
    fam.revoke(RevocationReason.ADMIN)
    fam.refresh_from_db()
    assert fam.revoked_reason == RevocationReason.LOGOUT
    assert fam.revoked_at == first


def test_a_security_revocation_cannot_be_overridden_by_a_routine_one(user):
    """The brief's own scenario: reuse detection fires first, a routine
    logout follows. A guard keyed on the *incoming* reason (e.g. "don't
    overwrite when the new reason is reuse_detected") would pass the
    LOGOUT-then-ADMIN test above but still let this ordering through -
    only a guard keyed on "already revoked" catches it.
    """
    fam = _family(user)
    fam.revoke(RevocationReason.REUSE_DETECTED)
    fam.revoke(RevocationReason.LOGOUT)
    fam.refresh_from_db()
    assert fam.revoked_reason == RevocationReason.REUSE_DETECTED


def test_a_security_revocation_survives_a_racing_instance(user):
    """The persistence-level counterpart of the test above.

    Both prior idempotency tests call ``revoke()`` twice on the *same*
    Python instance, so an in-memory-only guard (``if self.revoked_at is
    not None: return``) short-circuits the second call and both tests pass
    even though nothing stops two independently-loaded instances of the
    same row from both seeing ``revoked_at is None`` and both writing. That
    is exactly the reuse-detected-during-a-race-with-a-logout-request
    scenario the security guarantee exists for, so it has to be exercised
    with two separate instances fetched before either is revoked.
    """
    fam = _family(user)
    fam1 = TokenFamily.objects.get(pk=fam.pk)
    fam2 = TokenFamily.objects.get(pk=fam.pk)

    received: list[dict[str, object]] = []

    def handler(**kwargs: object) -> None:
        received.append(kwargs)

    family_revoked.connect(handler, dispatch_uid="test-race-signal")
    try:
        fam1.revoke(RevocationReason.REUSE_DETECTED)
        fam2.revoke(RevocationReason.LOGOUT)
    finally:
        family_revoked.disconnect(dispatch_uid="test-race-signal")

    stored = TokenFamily.objects.get(pk=fam.pk)
    assert stored.revoked_reason == RevocationReason.REUSE_DETECTED
    assert len(received) == 1
    assert received[0]["reason"] == RevocationReason.REUSE_DETECTED


def test_revoke_fires_the_signal_only_on_the_first_call(user):
    """A revoke() that forgets the early return would still make the other
    idempotency tests fail on the *reason*, but a version that resets the
    reason correctly (via save() with the old value) while still sending
    the signal unconditionally would slip through unless the signal count
    itself is asserted.
    """
    received: list[dict[str, object]] = []

    def handler(**kwargs: object) -> None:
        received.append(kwargs)

    family_revoked.connect(handler, dispatch_uid="test-revoke-signal")
    try:
        fam = _family(user)
        fam.revoke(RevocationReason.LOGOUT)
        fam.revoke(RevocationReason.ADMIN)
    finally:
        family_revoked.disconnect(dispatch_uid="test-revoke-signal")
    assert len(received) == 1


def test_an_expired_family_is_not_live(user):
    fam = TokenFamily.objects.create(
        user=user, expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert fam.is_live is False


def test_a_family_expiring_at_this_exact_instant_is_not_live(user, monkeypatch):
    """``is_live`` uses ``expires_at > now()`` (strictly greater), so the
    instant a family's expiry equals "now" it is already not live. Real
    clock reads always advance between the two calls, so comparing against
    an ordinary "one second past expiry" case (see above) can't tell ``>``
    apart from ``>=``. Freezing ``timezone.now()`` to the exact value used
    as ``expires_at`` pins that boundary: under ``>=`` this would flip to
    live and the test would fail.
    """
    frozen = timezone.now()
    fam = TokenFamily.objects.create(user=user, expires_at=frozen)
    monkeypatch.setattr("django_signet.sessions.models.timezone.now", lambda: frozen)
    assert fam.is_live is False


def test_digests_are_unique(user):
    fam = _family(user)
    exp = timezone.now() + timedelta(days=1)
    IssuedToken.objects.create(family=fam, digest="a" * 64, expires_at=exp)
    with pytest.raises(IntegrityError):
        IssuedToken.objects.create(family=fam, digest="a" * 64, expires_at=exp)


def test_deleting_a_family_deletes_its_tokens(user):
    fam = _family(user)
    IssuedToken.objects.create(
        family=fam, digest="b" * 64, expires_at=timezone.now() + timedelta(days=1)
    )
    fam.delete()
    assert IssuedToken.objects.count() == 0
