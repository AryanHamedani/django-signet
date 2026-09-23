import django.dispatch

token_issued = django.dispatch.Signal()  # user, family, request
token_refreshed = django.dispatch.Signal()  # user, family, request
# user, family, request - and request is always None: reuse is detected
# inside RotationPolicy, which never sees the HTTP request.
token_reuse_detected = django.dispatch.Signal()
family_revoked = django.dispatch.Signal()  # user, family, reason
