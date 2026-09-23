from datetime import timedelta

from django.test import override_settings

from django_signet.conf import setting


class Base:
    lifetime = setting("ACCESS_TOKEN_LIFETIME", default=timedelta(minutes=5))


class Override(Base):
    lifetime = timedelta(minutes=30)


class NoExplicitDefault:
    lifetime = setting("REFRESH_TOKEN_LIFETIME")


class DistinctExplicitDefault:
    lifetime = setting("ACCESS_TOKEN_LIFETIME", default=timedelta(minutes=99))


def test_falls_back_to_library_default():
    assert Base().lifetime == timedelta(minutes=5)


def test_no_default_argument_falls_back_to_defaults_dict():
    assert NoExplicitDefault().lifetime == timedelta(days=14)


def test_explicit_default_wins_over_defaults_dict_when_they_differ():
    assert DistinctExplicitDefault().lifetime == timedelta(minutes=99)


@override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(minutes=9)})
def test_project_settings_beat_library_default():
    assert Base().lifetime == timedelta(minutes=9)


@override_settings(SIGNET={"ACCESS_TOKEN_LIFETIME": timedelta(minutes=9)})
def test_class_attribute_beats_project_settings():
    assert Override().lifetime == timedelta(minutes=30)


def test_readable_on_the_class_not_only_the_instance():
    assert Base.lifetime == timedelta(minutes=5)
