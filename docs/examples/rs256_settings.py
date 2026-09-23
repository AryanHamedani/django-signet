"""RS256 on the server that logs users in: it holds both keys."""

import os

SIGNET = {
    "ALGORITHM": "RS256",
    # PEM text, from the environment or a secrets manager. A missing
    # variable stops the process at startup with a KeyError.
    "SIGNING_KEY": os.environ["SIGNET_SIGNING_KEY"],  # the private key
    "VERIFYING_KEY": os.environ["SIGNET_VERIFYING_KEY"],  # the public key
}
