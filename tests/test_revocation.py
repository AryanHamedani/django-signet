import pytest

from django_signet.models import RevocationReason, TokenFamily
from django_signet.sessions.rotation import RotationPolicy

pytestmark = pytest.mark.django_db


def test_changing_a_password_revokes_every_session(user):
    RotationPolicy().open_session(user)
    RotationPolicy().open_session(user)
    user.set_password("a-brand-new-password")
    user.save()

    families = TokenFamily.objects.filter(user=user)
    assert families.count() == 2
    assert all(f.is_live is False for f in families)
    assert all(f.revoked_reason == RevocationReason.PASSWORD_CHANGE for f in families)


def test_saving_without_changing_the_password_leaves_sessions_alone(user):
    pair = RotationPolicy().open_session(user)
    user.first_name = "Alice"
    user.save()
    pair.family.refresh_from_db()
    assert pair.family.is_live is True


def test_creating_a_brand_new_user_does_not_crash_the_receiver():
    """``instance.pk is None`` on the very first save: there is no previous
    row to compare against and nothing to revoke. Guards against the
    receiver naively querying ``sender.objects.get(pk=instance.pk)`` before
    checking ``pk is None``, which would raise on every user creation."""
    from django.contrib.auth import get_user_model

    new_user = get_user_model()(username="brand-new")
    new_user.set_password("initial-password")
    new_user.save()
    assert new_user.pk is not None
    assert TokenFamily.objects.filter(user=new_user).count() == 0
