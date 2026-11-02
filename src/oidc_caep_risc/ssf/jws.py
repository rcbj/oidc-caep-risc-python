# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Verify a Security Event Token. The key comes from the JWKS, never from the token."""

import json

from ..b64 import b64url_decode
from ..errors import OidcError
from ..keys import _ALG, public_key_from_jwk, verify_signature

SUPPORTED_JWS_ALGS = tuple(alg for alg, spec in _ALG.items() if spec[2] != "hmac")


def verify_compact_jws(token, keys):
    """Verifies a compact JWS against the keys of a JWKS and returns its header and payload."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
        raise OidcError("signature", "the SET is not a compact JWS")
    try:
        header = json.loads(b64url_decode(parts[0], "header").decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1], "payload").decode("utf-8"))
    except OidcError:
        raise
    except Exception as err:
        if isinstance(err, ValueError) and "base64url" in str(err):
            what = "header" if "header" in str(err) else "payload" if "payload" in str(err) else "signature"
            raise OidcError("signature", f"the SET's {what} is not base64url", cause=err) from err
        raise OidcError("signature", "the SET's header or payload is not JSON", cause=err) from err
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise OidcError("signature", "the SET's header or payload is not a JSON object")
    alg = str(header.get("alg") or "")
    spec = _ALG.get(alg)
    if spec is None or spec[2] == "hmac":
        raise OidcError(
            "signature",
            f"the SET is signed with {alg or '(no alg)'}, which this receiver does not verify ({', '.join(SUPPORTED_JWS_ALGS)})",
        )
    if "crit" in header and header["crit"] is not None:
        raise OidcError("signature", "the SET's header has a crit member this receiver does not understand")
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None
    candidates = [
        jwk for jwk in keys
        if (jwk.get("kid") == kid if kid else True)
        and jwk.get("kty") == spec[0]
        and (not jwk.get("use") or jwk.get("use") == "sig")
        and (not jwk.get("alg") or jwk.get("alg") == alg)
    ]
    if not candidates:
        suffix = f" with kid {kid}" if kid else ""
        raise OidcError("signature", f"the transmitter publishes no {spec[0]} signing key{suffix}")
    try:
        signature = b64url_decode(parts[2], "signature")
    except Exception as err:
        raise OidcError("signature", "the SET's signature is not base64url", cause=err) from err
    data = f"{parts[0]}.{parts[1]}".encode("ascii")
    for jwk in candidates:
        key = public_key_from_jwk(jwk)
        if verify_signature(key, alg, data, signature):
            return {"header": header, "payload": payload}
    raise OidcError("signature", "the SET's signature does not verify against the transmitter's keys")
