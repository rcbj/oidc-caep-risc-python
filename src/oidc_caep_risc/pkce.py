# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""PKCE S256 and the random tokens used as state and nonce."""

import hashlib
import secrets

from .b64 import b64url_encode


def random_token(nbytes=32):
    """32 random bytes, base64url. A PKCE verifier (RFC 7636) and a state or nonce."""
    return b64url_encode(secrets.token_bytes(nbytes))


def code_challenge_s256(verifier):
    """RFC 7636 S256: base64url(SHA-256(verifier)), with no padding."""
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return b64url_encode(digest)
