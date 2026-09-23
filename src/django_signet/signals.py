import django.dispatch

token_issued = django.dispatch.Signal()  # user, family, request
token_refreshed = django.dispatch.Signal()  # user, family, request
token_reuse_detected = django.dispatch.Signal()  # user, family, request
family_revoked = django.dispatch.Signal()  # user, family, reason
