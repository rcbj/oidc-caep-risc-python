# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""JWS key import and verify/sign. HMAC is only used when an ID token names it."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .b64 import b64url_decode
from .errors import OidcError

_HASHES = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}
_EC = {
    "P-256": (ec.SECP256R1(), 32, "sha256"),
    "P-384": (ec.SECP384R1(), 48, "sha384"),
    "P-521": (ec.SECP521R1(), 66, "sha512"),
}
_ALG = {
    "RS256": ("RSA", "sha256", "pkcs1"),
    "RS384": ("RSA", "sha384", "pkcs1"),
    "RS512": ("RSA", "sha512", "pkcs1"),
    "PS256": ("RSA", "sha256", "pss"),
    "PS384": ("RSA", "sha384", "pss"),
    "PS512": ("RSA", "sha512", "pss"),
    "ES256": ("EC", "sha256", "p1363"),
    "ES384": ("EC", "sha384", "p1363"),
    "ES512": ("EC", "sha512", "p1363"),
    "EdDSA": ("OKP", None, "eddsa"),
    "Ed25519": ("OKP", None, "eddsa"),
    "HS256": ("oct", "sha256", "hmac"),
    "HS384": ("oct", "sha384", "hmac"),
    "HS512": ("oct", "sha512", "hmac"),
}


def alg_spec(alg):
    return _ALG.get(alg)


def _uint(value):
    raw = b64url_decode(value)
    return int.from_bytes(raw, "big")


def public_key_from_jwk(jwk):
    """A public key object from a JWK. The caller has already filtered kty."""
    try:
        kty = jwk.get("kty")
        if kty == "RSA":
            numbers = rsa.RSAPublicNumbers(_uint(jwk["e"]), _uint(jwk["n"]))
            return numbers.public_key()
        if kty == "EC":
            curve, size, _hash = _EC[jwk["crv"]]
            x = int.from_bytes(b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(b64url_decode(jwk["y"]), "big")
            if len(b64url_decode(jwk["x"])) != size or len(b64url_decode(jwk["y"])) != size:
                raise ValueError("EC coordinate length")
            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        if kty == "OKP":
            if jwk.get("crv") not in (None, "Ed25519"):
                raise ValueError(jwk.get("crv"))
            return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
    except OidcError:
        raise
    except Exception as err:
        raise OidcError(
            "signature",
            f"the transmitter's key {jwk.get('kid') or ''} cannot be read: {err}",
            cause=err,
        ) from err
    raise OidcError("signature", f"the key type {jwk.get('kty')} cannot be read")


def load_private_key(pem, alg):
    """Loads a PKCS#8 PEM for private_key_jwt. A key that does not match alg fails here."""
    spec = _ALG.get(alg)
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception as err:
        raise OidcError("config", f"the private key could not be read as {alg}: {err}", cause=err) from err
    if spec is None:
        raise OidcError("config", f"the private key could not be read as {alg}: unsupported algorithm")
    ok = False
    if spec[0] == "RSA" and isinstance(key, rsa.RSAPrivateKey):
        ok = True
    elif spec[0] == "EC" and isinstance(key, ec.EllipticCurvePrivateKey):
        curve = {ec.SECP256R1: "ES256", ec.SECP384R1: "ES384", ec.SECP521R1: "ES512"}.get(type(key.curve))
        ok = curve == alg
    elif spec[0] == "OKP" and isinstance(key, ed25519.Ed25519PrivateKey):
        ok = True
    if not ok:
        raise OidcError("config", f"the private key could not be read as {alg}: key type does not match {alg}")
    return key


def _rsa_pad(kind, name):
    hash_alg = _HASHES[name]
    if kind == "pkcs1":
        return padding.PKCS1v15(), hash_alg
    return padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size), hash_alg


def _ec_size(key):
    return {ec.SECP256R1: 32, ec.SECP384R1: 48, ec.SECP521R1: 66}[type(key.curve)]


def sign_jws(key, alg, signing_input):
    spec = _ALG[alg]
    try:
        if spec[2] == "hmac":
            import hmac
            import hashlib
            digestmod = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}[spec[1]]
            return hmac.new(key, signing_input, digestmod).digest()
        if spec[0] == "RSA":
            pad, hash_alg = _rsa_pad(spec[2], spec[1])
            return key.sign(signing_input, pad, hash_alg)
        if spec[0] == "EC":
            hash_alg = _HASHES[spec[1]]
            der = key.sign(signing_input, ec.ECDSA(hash_alg))
            r, s = utils.decode_dss_signature(der)
            size = _ec_size(key)
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")
        return key.sign(signing_input)
    except OidcError:
        raise
    except Exception as err:
        raise OidcError("protocol", f"the client assertion could not be signed: {err}", cause=err) from err


def verify_signature(key, alg, signing_input, signature):
    """True when signature matches. A malformed signature is a miss, not an exception."""
    spec = _ALG.get(alg)
    if spec is None or key is None:
        return False
    try:
        if spec[2] == "hmac":
            import hmac
            import hashlib
            digestmod = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}[spec[1]]
            expected = hmac.new(key, signing_input, digestmod).digest()
            return hmac.compare_digest(expected, signature)
        if spec[0] == "RSA":
            pad, hash_alg = _rsa_pad(spec[2], spec[1])
            key.verify(signature, signing_input, pad, hash_alg)
            return True
        if spec[0] == "EC":
            size = _ec_size(key)
            if len(signature) != size * 2:
                return False
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            der = encode_dss_signature(r, s)
            key.verify(der, signing_input, ec.ECDSA(_HASHES[spec[1]]))
            return True
        key.verify(signature, signing_input)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:
        return False
