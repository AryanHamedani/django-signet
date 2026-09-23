from datetime import timedelta

from django.test import override_settings

from django_signet.conf import setting


class Base:
    lifetime = setting("ACCESS_TOKEN_LIFETIME", default=timedelta(minutes=5))


class Override(Base):
    lifetime = timedelta(minutes=30)


def test_falls_back_to_library_default():
    assert Base().lifetime == timedelta(minutes=5)


@override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(minutes=9)})
def test_project_settings_beat_library_default():
    assert Base().lifetime == timedelta(minutes=9)


@override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(minutes=9)})
def test_class_attribute_beats_project_settings():
    assert Override().lifetime == timedelta(minutes=30)


def test_readable_on_the_class_not_only_the_instance():
    assert Base.lifetime == timedelta(minutes=5)
