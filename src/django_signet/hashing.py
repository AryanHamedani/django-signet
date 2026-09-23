import hashlib


def token_digest(raw: str) -> str:
    """Return the sha256 hex digest of a token.

    We only ever need to answer "is the token just presented the one I
    issued?" - a comparison, not a retrieval. A one-way digest suffices and
    leaves no key to leak or rotate.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
