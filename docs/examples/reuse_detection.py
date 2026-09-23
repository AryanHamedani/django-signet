"""Alert on refresh-token reuse, from a RotationPolicy hook or a receiver."""

import logging

from django.urls import include, path

from django_signet.sessions.rotation import RotationPolicy
from django_signet.urls import signet_urls
from django_signet.views import SignetViewMixin

# Route this logger to whatever pages your on-call: Sentry, email, a chat hook.
security_log = logging.getLogger("security")


def send_reuse_alert(family):
    security_log.critical(
        "Refresh token reuse: user %s, session %s, opened from %s with %r",
        family.user.pk,
        family.id,
        family.ip_address,
        family.user_agent,
    )


class AlertingRotationPolicy(RotationPolicy):
    def on_reuse_detected(self, family):
        send_reuse_alert(family)


class AppRealm(SignetViewMixin):
    rotation = AlertingRotationPolicy()


urlpatterns = [
    # In place of include("django_signet.urls"), with the same URL names.
    path("api/auth/", include(signet_urls(AppRealm))),
]


def alert_on_reuse(**kwargs):
    """The same alert as a token_reuse_detected receiver."""
    send_reuse_alert(kwargs["family"])
