from __future__ import annotations

import sys
import threading
import uuid
from datetime import timedelta

import pytest
from django.core.cache import cache
from django.utils import timezone

from django_signet.models import RevocationReason
from django_signet.sessions.stores.base import Outcome
from django_signet.sessions.stores.cache import _REVOKED, CacheTokenStore, _CachedFamily

pytestmark = pytest.mark.django_db
FUTURE = timedelta(days=14)


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def store() -> CacheTokenStore:
    return CacheTokenStore()


def _open(store, user, digest="a" * 64):
    fam = store.open_family(user, timezone.now() + FUTURE)
    store.issue(fam, digest, timezone.now() + FUTURE)
    return fam


def test_open_family_creates_a_family_for_the_user(store, user):
    fam = store.open_family(user, timezone.now() + FUTURE)
    assert fam.user == user
    assert store.is_live(fam.id) is True


def test_issue_returns_a_token_carrying_the_digest(store, user):
    fam = store.open_family(user, timezone.now() + FUTURE)
    token = store.issue(fam, "a" * 64, timezone.now() + FUTURE)
    assert token.digest == "a" * 64
    assert token.family_id == fam.id


def test_consume_live_then_already_consumed(store, user):
    _open(store, user)
    assert store.consume("a" * 64).outcome is Outcome.LIVE
    assert store.consume("a" * 64).outcome is Outcome.ALREADY_CONSUMED


def test_unknown_digest_is_not_found(store, user):
    assert store.consume("f" * 64).outcome is Outcome.NOT_FOUND


def test_expired_token_reports_expired(store, user):
    fam = store.open_family(user, timezone.now() + FUTURE)
    store.issue(fam, "a" * 64, timezone.now() - timedelta(seconds=1))
    assert store.consume("a" * 64).outcome is Outcome.EXPIRED


def test_revoked_family_is_reported(store, user):
    fam = _open(store, user)
    store.revoke_family(fam.id, RevocationReason.LOGOUT)
    assert store.consume("a" * 64).outcome is Outcome.FAMILY_REVOKED


def test_revoke_family_keeps_the_first_reason(store, user):
    """TokenFamily.revoke() is first-reason-wins: a later routine LOGOUT
    must not mask an earlier REUSE_DETECTED security event. Same port,
    same guarantee - a set()-based revoke_family() (the second call
    silently overwriting the first) would pass every other test in this
    file but fail this one specifically."""
    fam = _open(store, user)
    store.revoke_family(fam.id, RevocationReason.REUSE_DETECTED)
    store.revoke_family(fam.id, RevocationReason.LOGOUT)
    assert cache.get(_REVOKED.format(fam.id)) == RevocationReason.REUSE_DETECTED


def test_allowlist_mode_treats_absence_as_dead(store):
    assert store.is_live(uuid.uuid4()) is False


def test_denylist_mode_treats_absence_as_live(user):
    store = CacheTokenStore(deny_by_default=True)
    unknown = uuid.uuid4()
    assert store.is_live(unknown) is True
    store.revoke_family(unknown, RevocationReason.ADMIN)
    assert store.is_live(unknown) is False


def test_revoke_all_for_user_is_honestly_unsupported(store, user):
    """The cache cannot enumerate a user's families - no scan, no key
    pattern, no secondary index. The documented failure is the
    deliverable; silently doing nothing or inventing a scan would both
    be worse than raising."""
    with pytest.raises(NotImplementedError):
        store.revoke_all_for_user(user, RevocationReason.LOGOUT_ALL)


def test_cached_family_is_live_matches_the_model_boundary_exactly():
    """Pins ``_CachedFamily.is_live`` against ``TokenFamily.is_live``'s
    exact boundary direction: ``expires_at > now``, not ``>=``. A ``>=``
    implementation would still pass every other test in this file (they
    never construct a family expiring at exactly ``now()``) but would
    wrongly report a family live for one extra instant at its boundary."""
    now = timezone.now()
    still_live = _CachedFamily(
        id=uuid.uuid4(), user=None, expires_at=now + timedelta(seconds=1)
    )
    assert still_live.is_live is True

    exactly_now = _CachedFamily(id=uuid.uuid4(), user=None, expires_at=now)
    assert exactly_now.is_live is False

    already_past = _CachedFamily(
        id=uuid.uuid4(), user=None, expires_at=now - timedelta(seconds=1)
    )
    assert already_past.is_live is False

    revoked = _CachedFamily(
        id=uuid.uuid4(),
        user=None,
        expires_at=now + timedelta(seconds=1),
        revoked_at=now,
    )
    assert revoked.is_live is False


def test_only_one_of_n_racing_consumes_wins(store, user):
    """``cache.add()`` is the only compare-and-set primitive every Django
    cache backend implements - there is no cache-level transaction and no
    conditional update. A ``get(); <decide>; set()`` implementation has a
    real gap between its read and its write; a concurrent caller landing
    inside that gap also reads "not yet consumed" and also decides LIVE.

    Calling ``consume()`` twice back to back would prove nothing: the
    second call's read always happens strictly after the first call's
    write has already committed (see ORMTokenStore's equivalent test and
    its docstring), so even a broken read-then-write implementation
    reports the right outcome by then - there is no gap left to fall
    into.

    So this drives many real threads through ``consume()`` at once,
    released together by a ``Barrier`` so every caller's read genuinely
    happens concurrently with every other caller's read and write - the
    exact interleaving a get-then-set implementation cannot survive,
    because some pair of callers will both observe "not consumed" before
    either of them writes. ``sys.setswitchinterval`` is lowered for the
    duration of the race: back-to-back pure-memory ``get()``/``set()``
    calls are fast enough that CPython rarely preempts a thread between
    them at the default interval, which would let a broken
    implementation pass this test by accident, not by being correct.

    A single 64-thread round only lands inside a broken implementation's
    read/write gap on most runs, not literally every run (this was
    measured directly, see the task report), so one round alone would
    occasionally let a broken implementation slip through by luck. This
    runs 5 independent rounds - fresh digest, fresh family, fresh
    threads each time - and requires every single one to show exactly
    one winner. Measured failure rate of the broken get-then-set
    implementation on a single round was ~25% (repeated trials came back
    around 15/20 rounds *catching* it, i.e. reporting more than one
    LIVE), so the chance of a broken implementation passing all 5 rounds
    by chance is roughly 0.25**5 - under 0.1% - while the real
    ``cache.add()``-based implementation is not probabilistic at all: it
    always yields exactly one winner, every round, because the cache
    backend's own lock makes each individual ``add()`` call atomic
    regardless of thread scheduling.
    """
    racer_count = 64
    rounds = 5
    original_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-7)
    try:
        for round_number in range(rounds):
            digest = f"{round_number:064x}"
            _open(store, user, digest)
            outcomes = _race_consume(store, digest, racer_count)

            assert outcomes.count(Outcome.LIVE) == 1, (
                f"round {round_number}: {outcomes.count(Outcome.LIVE)} callers "
                "reported LIVE for the same token"
            )
            assert outcomes.count(Outcome.ALREADY_CONSUMED) == racer_count - 1
    finally:
        sys.setswitchinterval(original_interval)


def _race_consume(
    store: CacheTokenStore, digest: str, racer_count: int
) -> list[Outcome]:
    """Runs ``racer_count`` threads through ``store.consume(digest)`` at
    once, released together by a ``Barrier``. A plain module-level helper
    rather than a closure defined inside the round loop above, so each
    round's ``barrier``/``outcomes``/``outcomes_lock`` are fresh locals
    with no risk of a thread from one round reaching into the next."""
    barrier = threading.Barrier(racer_count)
    outcomes: list[Outcome] = []
    outcomes_lock = threading.Lock()

    def race() -> None:
        barrier.wait()
        outcome = store.consume(digest).outcome
        with outcomes_lock:
            outcomes.append(outcome)

    racers = [threading.Thread(target=race) for _ in range(racer_count)]
    for racer in racers:
        racer.start()
    for racer in racers:
        racer.join()
    return outcomes


def test_consume_reports_family_revoked_when_revocation_wins_the_add_race(
    store, user, monkeypatch
):
    """The narrowed-but-not-closed window this store documents: a
    revocation landing between the pre-check and this caller winning the
    ``add()`` must still be caught by the post-add re-check, rather than
    silently reporting LIVE for a family that is, by the time the caller
    can act on the result, already revoked."""
    fam = _open(store, user)
    digest = "a" * 64
    consumed_key = f"signet:used:{digest}"

    original_add = store.cache.add

    def add_then_revoke(key, value, timeout=None, version=None):
        # Only the claim's own add() should trigger the side effect below.
        # revoke_family() also calls cache.add() (for its own
        # first-reason-wins guarantee), and this wrapper patches the same
        # cache's add() globally, so triggering the side effect for every
        # key would have revoke_family() call itself forever.
        if key != consumed_key:
            return original_add(key, value, timeout, version)
        won = original_add(key, value, timeout, version)
        store.revoke_family(fam.id, RevocationReason.REUSE_DETECTED)
        return won

    monkeypatch.setattr(store.cache, "add", add_then_revoke)

    result = store.consume(digest)
    assert result.outcome is Outcome.FAMILY_REVOKED


# ---------------------------------------------- final review, Group B: I8


def test_revoke_family_fires_family_revoked_once_with_the_first_reason(store, user):
    """I8: ``family_revoked`` used to fire only from the ORM model, so a
    receiver wired to it saw nothing under this store. Both adapters now
    honour one event contract: it fires on the first-reason-wins success
    path, with the same ``user``/``family``/``reason`` arguments, and not
    again for a later revocation that loses."""
    from django_signet.signals import family_revoked

    fam = _open(store, user)
    received = []

    def receiver(sender, **kwargs):
        received.append(kwargs)

    family_revoked.connect(receiver)
    try:
        store.revoke_family(fam.id, RevocationReason.REUSE_DETECTED)
        store.revoke_family(fam.id, RevocationReason.LOGOUT)
    finally:
        family_revoked.disconnect(receiver)

    assert len(received) == 1
    assert received[0]["reason"] == RevocationReason.REUSE_DETECTED
    assert received[0]["user"] == user
    assert received[0]["family"].id == fam.id


def test_revoking_an_unknown_family_fires_nothing(store):
    from django_signet.signals import family_revoked

    received = []

    def receiver(sender, **kwargs):
        received.append(kwargs)

    family_revoked.connect(receiver)
    try:
        store.revoke_family(uuid.uuid4(), RevocationReason.LOGOUT)
    finally:
        family_revoked.disconnect(receiver)
    assert received == []


def test_the_store_declares_that_it_cannot_revoke_all_for_a_user(store):
    """What signet.W007 reads: a capability, not an isinstance check."""
    assert CacheTokenStore.supports_revoke_all_for_user is False


def _recorded_add_timeouts(store, monkeypatch):
    timeouts = {}
    real_add = store.cache.add

    def add(key, value, timeout=None, version=None):
        timeouts[key] = timeout
        return real_add(key, value, timeout, version)

    monkeypatch.setattr(store.cache, "add", add)
    return timeouts


def test_a_revocation_marker_expires_once_nothing_it_guards_can_verify(
    store, user, monkeypatch
):
    """Markers used to be written with no timeout, so under a noeviction
    policy every logout added a key that was never removed, until the
    cache refused writes. The bound: the family's remaining lifetime, plus
    the refresh and access lifetimes and LEEWAY - after that no token of
    the family can verify, so the denylist cannot revive it."""
    fam = _open(store, user)
    timeouts = _recorded_add_timeouts(store, monkeypatch)

    store.revoke_family(fam.id, RevocationReason.LOGOUT)

    expected = FUTURE + timedelta(days=14) + timedelta(minutes=5)
    timeout = timeouts[_REVOKED.format(fam.id)]
    assert timeout is not None
    assert abs(timeout - expected.total_seconds()) <= 2


def test_a_marker_for_a_family_the_cache_no_longer_holds_is_bounded_too(
    store, monkeypatch
):
    """No token of an unheld family can be minted from now on, so the
    bound starts from now."""
    timeouts = _recorded_add_timeouts(store, monkeypatch)
    family_id = uuid.uuid4()

    store.revoke_family(family_id, RevocationReason.ADMIN)

    expected = timedelta(days=14) + timedelta(minutes=5)
    assert abs(timeouts[_REVOKED.format(family_id)] - expected.total_seconds()) <= 2
