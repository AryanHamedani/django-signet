from django.apps import AppConfig
from django.core.checks import register


class SignetConfig(AppConfig):
    """Registers Signet's system checks and its password-change revocation
    receiver when the app is ready."""

    name = "django_signet"
    label = "django_signet"
    verbose_name = "Signet JWT authentication"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        """Register ``ALL_CHECKS`` under the ``signet`` tag, and connect
        :func:`django_signet.revocation.revoke_on_password_change` to the
        configured user model's ``pre_save`` signal."""
        # Imported here, not at module scope: Django forbids importing
        # models (directly or via get_user_model()) before the app
        # registry is fully populated, and ready() is the first point at
        # which that is safe.
        from django.contrib.auth import get_user_model
        from django.db.models.signals import pre_save

        from django_signet.checks import ALL_CHECKS
        from django_signet.revocation import revoke_on_password_change

        for check in ALL_CHECKS:
            register(check, "signet")

        pre_save.connect(
            revoke_on_password_change,
            sender=get_user_model(),
            dispatch_uid="signet.revoke_on_password_change",
        )
