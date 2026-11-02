# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Client authentication on a token or pushed-authorization request."""

import base64
import json
import time
import uuid
from urllib.parse import quote

from .b64 import b64url_encode
from .errors import OidcError
from .keys import load_private_key, sign_jws


def form_encode(value):
    """application/x-www-form-urlencoded, the encoding of a Basic client id and secret (RFC 6749)."""
    return quote(str(value), safe="-_.!~*'()").replace("%20", "+")


def load_signing_key(pem, alg):
    return load_private_key(pem, alg)


def _compact(header, payload, key, alg):
    signing_input = (
        b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    )
    signature = sign_jws(key, alg, signing_input.encode("ascii"))
    return signing_input + "." + b64url_encode(signature)


def apply_client_auth(config, key, body, headers, audience):
    """Adds this client's authentication. A client assertion's audience is the issuer."""
    method = config["tokenEndpointAuthMethod"]
    client_id = config["clientId"]
    if method == "client_secret_basic":
        raw = f"{form_encode(client_id)}:{form_encode(config.get('clientSecret') or '')}"
        headers["authorization"] = "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")
        return
    if method == "client_secret_post":
        body["client_id"] = client_id
        body["client_secret"] = config.get("clientSecret") or ""
        return
    if key is None:
        raise OidcError("config", "private_key_jwt has no signing key")
    now = int(time.time())
    alg = config.get("privateKeyAlg") or "RS256"
    assertion = _compact(
        {"alg": alg, "typ": "JWT"},
        {"iss": client_id, "sub": client_id, "aud": audience, "jti": str(uuid.uuid4()), "iat": now, "exp": now + 60},
        key,
        alg,
    )
    body["client_id"] = client_id
    body["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    body["client_assertion"] = assertion
