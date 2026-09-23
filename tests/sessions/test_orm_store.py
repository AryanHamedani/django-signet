from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

import pytest
from django.utils import timezone

from django_signet.models import IssuedToken, RevocationReason, TokenFamily
from django_signet.sessions.stores.base import ConsumeResult, Outcome
from django_signet.sessions.stores.orm import ORMTokenStore
from django_signet.signals import family_revoked

pytestmark = pytest.mark.django_db

FUTURE = timedelta(days=14)


@pytest.fixture
def store() -> ORMTokenStore:
    return ORMTokenStore()


def _open(store: ORMTokenStore, user: Any, digest: str = "a" * 64) -> TokenFamily:
    """Open a family and issue its first token - the two-step sequence the
    rotation layer uses, because the token's ``sid`` claim needs the family
    id to exist first."""
    fam = store.open_family(user, timezone.now() + FUTURE)
    store.issue(fam, digest, timezone.now() + FUTURE)
    return fam


def test_open_family_creates_an_empty_family(store, user):
    fam = store.open_family(user, timezone.now() + FUTURE)
    assert TokenFamily.objects.count() == 1
    assert IssuedToken.objects.filter(family=fam).count() == 0


def test_issue_adds_the_first_token(store, user):
    fam = _open(store, user)
    assert IssuedToken.objects.filter(family=fam, digest="a" * 64).exists()


def test_consuming_a_live_token_marks_it_consumed(store, user):
    _open(store, user)
    result = store.consume("a" * 64)
    assert result.outcome is Outcome.LIVE
    assert IssuedToken.objects.get(digest="a" * 64).consumed_at is not None


def test_consuming_twice_reports_already_consumed(store, user):
    _open(store, user)
    store.consume("a" * 64)
    assert store.consume("a" * 64).outcome is Outcome.ALREADY_CONSUMED


def test_unknown_digest_reports_not_found(store, user):
    assert store.consume("f" * 64).outcome is Outcome.NOT_FOUND


def test_expired_token_reports_expired(store, user):
    fam = _open(store, user)
    IssuedToken.objects.filter(family=fam).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert store.consume("a" * 64).outcome is Outcome.EXPIRED


def test_revoked_family_reports_family_revoked(store, user):
    fam = _open(store, user)
    store.revoke_family(fam.id, RevocationReason.LOGOUT)
    assert store.consume("a" * 64).outcome is Outcome.FAMILY_REVOKED


def test_is_live_tracks_revocation(store, user):
    fam = _open(store, user)
    assert store.is_live(fam.id) is True
    store.revoke_family(fam.id, RevocationReason.LOGOUT)
    assert store.is_live(fam.id) is False


def test_is_live_is_false_for_an_unknown_family(store, user):
    """Allowlist semantics: absence means not live. A denylist-shaped
    implementation (``True`` unless explicitly revoked) or one that lets
    ``TokenFamily.DoesNotExist`` propagate instead of returning ``False``
    would both fail this."""
    assert store.is_live(uuid.uuid4()) is False


def test_is_live_is_false_for_an_expired_family(store, user):
    """The store's ``is_live`` is a separate query from the model's
    ``is_live`` property (tested in test_models.py) - this pins the same
    expiry rule at the store layer, since an implementation that only
    checked ``revoked_at__isnull=True`` and forgot ``expires_at`` would
    pass every other test in this file but let an expired, never-revoked
    family report itself live forever."""
    fam = _open(store, user)
    TokenFamily.objects.filter(pk=fam.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert store.is_live(fam.id) is False


def test_issue_adds_a_successor_to_the_same_family(store, user):
    fam = _open(store, user)
    store.issue(fam, "b" * 64, timezone.now() + FUTURE)
    assert IssuedToken.objects.filter(family=fam).count() == 2


def test_revoke_all_for_user_revokes_every_live_family(store, user):
    f1 = _open(store, user, "a" * 64)
    f2 = _open(store, user, "b" * 64)
    store.revoke_all_for_user(user, RevocationReason.LOGOUT_ALL)
    assert store.is_live(f1.id) is False
    assert store.is_live(f2.id) is False


def test_revoke_all_for_user_sends_the_signal_for_every_family(store, user):
    """A bulk ``TokenFamily.objects.filter(...).update(revoked_at=...,
    revoked_reason=...)`` - the exact bypass the brief warns against -
    would set the same field state as calling the model's ``revoke()``,
    so asserting only ``revoked_reason`` afterwards (as an earlier version
    of this test did) cannot tell the two apart: both leave every family
    with the right reason recorded. What a bulk update cannot fake is the
    ``family_revoked`` signal, which only ``TokenFamily.revoke()`` sends -
    and only once per family, honouring the first-reason-wins guard.
    """
    f1 = _open(store, user, "a" * 64)
    f2 = _open(store, user, "b" * 64)

    received: list[dict[str, Any]] = []

    def handler(**kwargs: Any) -> None:
        received.append(kwargs)

    family_revoked.connect(handler, dispatch_uid="test-revoke-all-signal")
    try:
        store.revoke_all_for_user(user, RevocationReason.LOGOUT_ALL)
    finally:
        family_revoked.disconnect(dispatch_uid="test-revoke-all-signal")

    assert len(received) == 2
    assert {r["family"].pk for r in received} == {f1.pk, f2.pk}
    assert all(r["reason"] == RevocationReason.LOGOUT_ALL for r in received)


def test_purge_expired_removes_only_expired_families(store, user):
    live = _open(store, user, "a" * 64)
    dead = _open(store, user, "b" * 64)
    TokenFamily.objects.filter(pk=dead.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert store.purge_expired() == 1
    assert list(TokenFamily.objects.values_list("pk", flat=True)) == [live.pk]


def test_consume_claim_is_exclusive_under_a_race(store, user, monkeypatch):
    """Proves the claim step is an atomic conditional UPDATE, not a
    read-check-write.

    Calling ``consume()`` twice back to back would NOT prove this: the
    second call's read always happens *after* the first call's write has
    already committed, so even a read-check-write consume() (one that
    decides ALREADY_CONSUMED from an in-memory ``consumed_at`` read
    instead of a WHERE clause enforced by the database) would report the
    right outcome - by the time it reads, the truth has already changed.
    That is exactly the shape of bug this project has shipped before (see
    test_models.py's racing-instance test for ``TokenFamily.revoke()``).

    So this test forces the interleaving that actually breaks a
    read-check-write implementation: caller A's classify (read) happens,
    then - before A's claim (write) reaches the database - caller B runs
    its *entire* consume() (its own read, then its own write) to
    completion, and only then does A's claim proceed. Both reads happen
    before either write. Under the real atomic-UPDATE implementation this
    yields exactly one LIVE and one ALREADY_CONSUMED, because A's claim
    re-checks the database, not memory. Under a read-check-write
    implementation, A would still be holding its own in-memory token
    object with ``consumed_at is None`` from its earlier read, so it would
    proceed to save and report LIVE too - both callers would report LIVE,
    and reuse would never be detected.
    """
    _open(store, user)
    digest = "a" * 64

    original_claim = ORMTokenStore._claim
    second_outcome: list[Outcome] = []

    def racing_claim(
        self: ORMTokenStore,
        token: IssuedToken,
        family: TokenFamily,
        now: datetime,
    ) -> ConsumeResult:
        # A has already classified (read) and is about to claim (write).
        # Run B's full consume() - its own read, then its own write -
        # before A's write reaches the database.
        monkeypatch.setattr(ORMTokenStore, "_claim", original_claim)
        second_outcome.append(store.consume(digest).outcome)
        monkeypatch.setattr(ORMTokenStore, "_claim", racing_claim)
        return original_claim(self, token, family, now)

    monkeypatch.setattr(ORMTokenStore, "_claim", racing_claim)
    first_outcome = store.consume(digest).outcome

    assert {first_outcome, second_outcome[0]} == {
        Outcome.LIVE,
        Outcome.ALREADY_CONSUMED,
    }
    assert IssuedToken.objects.get(digest=digest).consumed_at is not None


def test_consume_reports_family_revoked_when_revocation_races_the_claim(
    store, user, monkeypatch
):
    """The revocation TOCTOU this store must not have: classify reads
    ``family.revoked_at`` once, and the claim step used to only re-check
    ``consumed_at`` - so a sibling token's reuse burning this family
    between those two steps would still let this in-flight consume()
    report LIVE. That is precisely the scenario the whole module exists
    to prevent: reuse is detected, the family is burned, and a
    still-in-flight sibling token gets treated as live anyway.

    This forces the family to be revoked in the gap between classify
    (which observes it live) and claim (whose conditional UPDATE must now
    re-check revocation, not just consumption, to catch this).
    """
    fam = _open(store, user)
    digest = "a" * 64

    original_claim = ORMTokenStore._claim

    def revoke_then_claim(
        self: ORMTokenStore,
        token: IssuedToken,
        family: TokenFamily,
        now: datetime,
    ) -> ConsumeResult:
        monkeypatch.setattr(ORMTokenStore, "_claim", original_claim)
        store.revoke_family(fam.id, RevocationReason.REUSE_DETECTED)
        return original_claim(self, token, family, now)

    monkeypatch.setattr(ORMTokenStore, "_claim", revoke_then_claim)
    result = store.consume(digest)

    assert result.outcome is Outcome.FAMILY_REVOKED
    assert IssuedToken.objects.get(digest=digest).consumed_at is None
