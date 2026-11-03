# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""ID token checks: signature, issuer, audience, time, nonce, and at_hash / c_hash."""

import hashlib
import hmac
import json
import time

from .b64 import b64url_decode, b64url_encode
from .backchannel import send
from .discovery import ASYMMETRIC_JWS_ALGS
from .errors import OidcError
from .keys import alg_spec, public_key_from_jwk, verify_signature

# typ values that are some other token. An ID token must not carry one (RFC 8725).
_NOT_ID_TOKEN = {
    "at+jwt", "application/at+jwt", "logout+jwt", "secevent+jwt", "dpop+jwt",
    "token-introspection+jwt", "software-statement+jwt", "jwt-bearer",
}


def _same(left, right):
    a = left.encode("utf-8")
    b = right.encode("utf-8")
    return len(a) == len(b) and hmac.compare_digest(a, b)


def hash_claim(value, alg):
    """The hash half an at_hash or c_hash is: base64url of the left half of the digest the alg names."""
    if alg in ("EdDSA", "Ed25519"):
        name = "sha512"
    elif "384" in alg:
        name = "sha384"
    elif "512" in alg:
        name = "sha512"
    else:
        name = "sha256"
    digest = hashlib.new(name, value.encode("utf-8")).digest()
    return b64url_encode(digest[: len(digest) // 2])


def _check_hash(claim, value, alg, name):
    if claim is None:
        return
    if not isinstance(claim, str) or not _same(claim, hash_claim(value, alg)):
        raise OidcError("validation", f"the ID token's {name} does not match")


def _decode_part(token, index, what):
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise OidcError("signature", "the ID token is not a compact JWS: not a compact JWS")
    try:
        raw = b64url_decode(parts[index], what)
        parsed = json.loads(raw.decode("utf-8"))
    except OidcError:
        raise
    except Exception as err:
        raise OidcError("signature", f"the ID token is not a compact JWS: {err}", cause=err) from err
    if not isinstance(parsed, dict):
        raise OidcError("signature", "the ID token is not a compact JWS: not a JSON object")
    return parsed


def _candidates(jwks, alg, kid):
    spec = alg_spec(alg)
    if spec is None:
        return []
    found = []
    for jwk in jwks or []:
        if kid and jwk.get("kid") != kid:
            continue
        if jwk.get("kty") != spec[0]:
            continue
        if jwk.get("use") and jwk.get("use") != "sig":
            continue
        if jwk.get("alg") and jwk.get("alg") != alg:
            continue
        found.append(jwk)
    return found


def _signature_ok(token, alg, jwks, secret):
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        signature = b64url_decode(parts[2], "signature")
    except Exception as err:
        raise OidcError("signature", f"the ID token is not a compact JWS: {err}", cause=err) from err
    if alg.startswith("HS"):
        return verify_signature(secret.encode("utf-8"), alg, signing_input, signature)
    header = _decode_part(token, 0, "header")
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None
    keys = _candidates(jwks, alg, kid)
    if not keys:
        raise OidcError("signature", "signature verification failed: no applicable key")
    for jwk in keys:
        try:
            key = public_key_from_jwk(jwk)
        except OidcError:
            continue
        if verify_signature(key, alg, signing_input, signature):
            return True
    return False


def validate_id_token(token, checks):
    """Verifies an ID token and returns the payload.

    requireTyp: the header must carry typ (JWT or application/jwt). requireAtHash: with
    accessToken given, at_hash must be present. Without them each is checked when present.
    """
    try:
        header = _decode_part(token, 0, "header")
    except OidcError:
        raise
    alg = str(header.get("alg") or "")
    algorithms = checks.get("algorithms") or []
    if alg not in algorithms:
        raise OidcError("signature", f"the ID token is signed with {alg or '(no alg)'}, which this client does not accept")
    if "crit" in header and header["crit"] is not None:
        raise OidcError("validation", "the ID token has a crit header this client does not understand")
    typ = "" if header.get("typ") is None else str(header.get("typ")).lower()
    if not typ and checks.get("requireTyp"):
        raise OidcError("validation", "the ID token header has no typ (JWT or application/jwt is required)")
    if typ and ((typ != "jwt" and typ != "application/jwt") or typ in _NOT_ID_TOKEN):
        raise OidcError("validation", f"the ID token typ is {header.get('typ')}, not an ID token")
    if alg.startswith("HS") and not checks.get("clientSecret"):
        raise OidcError("config", f"{alg} ID tokens need the client secret")
    payload = _decode_part(token, 1, "payload")
    try:
        ok = _signature_ok(token, alg, checks.get("jwks"), checks.get("clientSecret") or "")
    except OidcError:
        raise
    except Exception as err:
        raise OidcError("signature", f"the ID token was refused: signature: {err}", cause=err) from err
    if not ok:
        raise OidcError("signature", "the ID token was refused: signature verification failed")
    if payload.get("iss") != checks.get("issuer"):
        raise OidcError("validation", "the ID token was refused: issuer mismatch")
    aud = payload.get("aud")
    audiences = [str(item) for item in aud] if isinstance(aud, list) else [str(aud if aud is not None else "")]
    if checks.get("clientId") not in audiences:
        raise OidcError("validation", "the ID token audience does not include this client")
    now = time.time()
    tolerance = checks.get("clockToleranceSec") or 0
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise OidcError("validation", "the ID token was refused: exp is missing")
    if float(exp) + tolerance < now:
        raise OidcError("validation", "the ID token was refused: exp expired")
    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and not isinstance(nbf, bool) and float(nbf) - tolerance > now:
        raise OidcError("validation", "the ID token was refused: nbf is in the future")
    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and not isinstance(iat, bool) and float(iat) - tolerance > now:
        raise OidcError("validation", "the ID token was refused: iat is in the future")
    max_age_sec = checks.get("maxIdTokenAgeSec")
    if max_age_sec is not None:
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            raise OidcError("validation", "the ID token was refused: iat is missing")
        if (now - float(iat)) - tolerance > float(max_age_sec):
            raise OidcError("validation", "the ID token was refused: iat is too old")
    if not isinstance(payload.get("sub"), str) or not payload.get("sub"):
        raise OidcError("validation", "the ID token has no sub")
    if len(audiences) > 1 and payload.get("azp") != checks.get("clientId"):
        raise OidcError("validation", "an ID token with several audiences must name this client as azp")
    if "azp" in payload and payload.get("azp") is not None and payload.get("azp") != checks.get("clientId"):
        raise OidcError("validation", f"the ID token azp is {payload.get('azp')}, not {checks.get('clientId')}")
    if checks.get("nonce") is not None:
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not _same(nonce, checks["nonce"]):
            raise OidcError("validation", "the ID token nonce does not match this sign-in")
    if checks.get("previousSub") is not None and payload.get("sub") != checks["previousSub"]:
        raise OidcError("validation", "the refreshed ID token is for a different subject")
    if checks.get("accessToken"):
        if payload.get("at_hash") is None and checks.get("requireAtHash"):
            raise OidcError("validation", "the token response carries an access token and the ID token has no at_hash")
        _check_hash(payload.get("at_hash"), checks["accessToken"], alg, "at_hash")
    if checks.get("code"):
        _check_hash(payload.get("c_hash"), checks["code"], alg, "c_hash")
    if checks.get("maxAge") is not None:
        auth_time = payload.get("auth_time")
        if not isinstance(auth_time, (int, float)) or isinstance(auth_time, bool):
            raise OidcError("validation", "max_age was requested and the ID token has no auth_time")
        if float(auth_time) < int(time.time()) - checks["maxAge"] - tolerance:
            raise OidcError("validation", "the ID token auth_time is older than max_age")
    return payload


def fetch_jwks(jwks_uri, tls=None):
    """Fetches a JWKS document. The caller verifies with it."""
    answer = send(jwks_uri, headers={"accept": "application/json"}, tls=tls, code="discovery")
    if answer["status"] != 200:
        raise OidcError("discovery", f"the JWKS at {jwks_uri} answered {answer['status']}")
    try:
        body = json.loads(answer["body"])
    except Exception as err:
        raise OidcError("discovery", f"the JWKS at {jwks_uri} is not JSON", cause=err) from err
    keys = body.get("keys") if isinstance(body, dict) else None
    if not isinstance(body, dict) or not isinstance(keys, list):
        raise OidcError("discovery", f"the JWKS at {jwks_uri} has no keys")
    return keys


def id_token_algorithms(advertised, pinned=None, allowed=None):
    from .discovery import id_token_algorithms as _impl
    return _impl(advertised, pinned, allowed)
