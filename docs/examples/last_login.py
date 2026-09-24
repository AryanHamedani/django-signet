"""What Simple JWT's UPDATE_LAST_LOGIN did, as a token_issued receiver."""

from django.contrib.auth.models import update_last_login


def record_last_login(**kwargs):
    # Connect in your AppConfig.ready(): token_issued.connect(record_last_login)
    update_last_login(None, kwargs["user"])
