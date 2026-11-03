# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""DPoP (RFC 9449): an ES256 key held by this relying party, and the proofs it signs."""

import hashlib
import json
import re
import threading
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .b64 import b64url_encode
from .errors import OidcError
from .keys import sign_jws

DPOP_ALG = "ES256"
DPOP_MODES = ("auto", "always", "never")

_RESOURCE_NONCE = re.compile(r'error\s*=\s*"?use_dpop_nonce"?', re.IGNORECASE)
_DPOP_SCHEME = re.compile(r"(^|,)\s*DPoP(\s|$|,)", re.IGNORECASE)


def htu_of(url):
    """The htu claim: the request URL without its query and fragment (RFC 9449 section 4.2)."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def origin_of(url):
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def access_token_hash(access_token):
    """The ath claim: base64url of the SHA-256 of the access token."""
    return b64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())


def load_dpop_key(pem):
    """A P-256 private key from PEM. Any other key is a configuration error."""
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception as err:
        raise OidcError("config", f"dpopKey could not be read: {err}", cause=err) from err
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise OidcError("config", "dpopKey must be a P-256 (ES256) private key")
    return key


def is_nonce_challenge(status, oauth_error, www_authenticate):
    """True for an authorization server's 400 use_dpop_nonce or a resource server's 401 DPoP challenge."""
    if status == 400 and oauth_error == "use_dpop_nonce":
        return True
    if status == 401 and www_authenticate:
        return bool(_DPOP_SCHEME.search(www_authenticate)) and bool(_RESOURCE_NONCE.search(www_authenticate))
    return False


class DPoPKey:
    """An ES256 key pair, in memory only unless the application supplied the PEM, and the latest nonce per origin."""

    def __init__(self, private_key=None):
        self._key = private_key or ec.generate_private_key(ec.SECP256R1())
        numbers = self._key.public_key().public_numbers()
        self.public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url_encode(numbers.x.to_bytes(32, "big")),
            "y": b64url_encode(numbers.y.to_bytes(32, "big")),
        }
        self._nonces = {}
        self._lock = threading.Lock()

    @property
    def thumbprint(self):
        """The RFC 7638 JWK SHA-256 thumbprint, the value of dpop_jkt."""
        canonical = json.dumps(
            {name: self.public_jwk[name] for name in ("crv", "kty", "x", "y")},
            separators=(",", ":"),
            sort_keys=True,
        )
        return b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())

    def nonce_for(self, url):
        with self._lock:
            return self._nonces.get(origin_of(url))

    def remember(self, url, headers):
        """Keeps the DPoP-Nonce a response from url's origin carried, if any. Returns it."""
        nonce = (headers or {}).get("dpop-nonce")
        if nonce:
            with self._lock:
                self._nonces[origin_of(url)] = nonce.strip()
        return nonce

    def proof(self, method, url, access_token=None, nonce=None):
        """A DPoP proof JWT for one request. A resource request's proof carries ath."""
        header = {"typ": "dpop+jwt", "alg": DPOP_ALG, "jwk": dict(self.public_jwk)}
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": htu_of(url),
            "iat": int(time.time()),
        }
        nonce = nonce if nonce is not None else self.nonce_for(url)
        if nonce:
            payload["nonce"] = nonce
        if access_token:
            payload["ath"] = access_token_hash(access_token)
        signing_input = (
            b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
            + "."
            + b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        )
        signature = sign_jws(self._key, DPOP_ALG, signing_input.encode("ascii"))
        return signing_input + "." + b64url_encode(signature)
