"""A resource server: it verifies access tokens, and never issues any."""

import os

SIGNET = {
    "ALGORITHM": "RS256",
    "VERIFYING_KEY": os.environ["SIGNET_VERIFYING_KEY"],  # the public key only
}

# signet.W011 warns that this server cannot sign. That is the point of it.
# Add it to any SILENCED_SYSTEM_CHECKS you already have; do not replace them.
SILENCED_SYSTEM_CHECKS = ["signet.W011"]
