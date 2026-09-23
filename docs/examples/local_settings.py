"""Local development over plain http:// only. Never deploy this."""

DEBUG = True

SIGNET = {
    # Browsers drop Secure cookies set over http://, so turn the flag off.
    # The __Host-/__Secure- name prefixes need Secure and go with it.
    # signet.E001 rejects this whenever DEBUG is False.
    "COOKIE_SECURE": False,
}
