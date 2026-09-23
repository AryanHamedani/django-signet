from __future__ import annotations

from typing import Any

from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

from django_signet.authentication import GENERIC_FAILURE


class TokenObtainSerializer(serializers.Serializer[Any]):
    """Validates credentials. Subclass and override ``validate`` to support
    email login, one-time codes, or anything else that yields a user."""

    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields[self.username_field] = serializers.CharField()

    @property
    def username_field(self) -> str:
        return get_user_model().USERNAME_FIELD

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        user = authenticate(
            request=self.context.get("request"),
            username=attrs[self.username_field],
            password=attrs["password"],
        )
        # One message for both "no such user" and "wrong password", so the
        # endpoint cannot be used to enumerate accounts. Reuses the same
        # GENERIC_FAILURE string every other endpoint in this library
        # returns on an auth failure, rather than a second, differently
        # worded "invalid credentials" message that would otherwise exist
        # only here.
        #
        # ``not user.is_active`` is unreachable under the stock
        # ``ModelBackend``, which already excludes inactive users via
        # ``user_can_authenticate`` before ``authenticate()`` ever returns
        # them - so this branch never fires with the default backend. It
        # is kept as defence-in-depth for a custom authentication backend
        # that does not perform that check itself, not because it changes
        # behaviour under the default configuration.
        if user is None or not user.is_active:
            raise serializers.ValidationError(GENERIC_FAILURE)
        return {"user": user}
