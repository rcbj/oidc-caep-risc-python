# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""OpenID Provider discovery for a confidential Authorization Code client."""

from urllib.parse import urlsplit

from .backchannel import send
from .errors import OidcError

# Asymmetric JWS algorithms this client verifies. HMAC algorithms are accepted only when named explicitly.
ASYMMETRIC_JWS_ALGS = (
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519",
)

# The scopes the demo and RelyingParty ask for unless the configuration names others.
DEFAULT_SCOPES = "openid profile email offline_access ssf.read ssf.manage"

_REQUIRED = (
    "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
    "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported",
)


def issuer_from_metadata_url(metadata_url):
    """The issuer a discovery URL was built from."""
    parts = urlsplit(metadata_url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise OidcError("config", f"metadataUrl is not a URL: {metadata_url}")
    marker = "/.well-known/openid-configuration"
    path = parts.path or ""
    at = path.find(marker)
    if at < 0:
        raise OidcError("config", f"metadataUrl must be the openid-configuration URL, not {metadata_url}")
    prefix = path[:at].rstrip("/")
    return f"{parts.scheme}://{parts.netloc}{prefix}"


def _must_be_url(value, name):
    if not isinstance(value, str) or not value:
        raise OidcError("discovery", f"OpenID Provider metadata {name} is missing")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise OidcError("discovery", f"OpenID Provider metadata {name} is not a valid URL")
    if name == "issuer" and (parts.query or parts.fragment):
        raise OidcError("discovery", "issuer must not contain a query or fragment")
    return value


def validate_provider_metadata(raw, expected_issuer=None):
    """Checks metadata for a confidential Authorization Code client."""
    if not isinstance(raw, dict):
        raise OidcError("discovery", "OpenID Provider metadata must be a JSON object")
    missing = [key for key in _REQUIRED if key not in raw]
    if missing:
        raise OidcError("discovery", f"OpenID Provider metadata is missing {', '.join(missing)}")
    metadata = {
        "issuer": _must_be_url(raw.get("issuer"), "issuer"),
        "authorization_endpoint": _must_be_url(raw.get("authorization_endpoint"), "authorization_endpoint"),
        "token_endpoint": _must_be_url(raw.get("token_endpoint"), "token_endpoint"),
        "jwks_uri": _must_be_url(raw.get("jwks_uri"), "jwks_uri"),
        "response_types_supported": raw.get("response_types_supported"),
        "subject_types_supported": raw.get("subject_types_supported"),
        "id_token_signing_alg_values_supported": raw.get("id_token_signing_alg_values_supported"),
    }
    for key in ("userinfo_endpoint", "end_session_endpoint", "pushed_authorization_request_endpoint", "revocation_endpoint"):
        if key in raw and raw[key] is not None:
            metadata[key] = _must_be_url(raw[key], key)
    for key in ("token_endpoint_auth_methods_supported", "code_challenge_methods_supported", "scopes_supported", "grant_types_supported"):
        if key in raw and raw[key] is not None:
            if not isinstance(raw[key], list):
                raise OidcError("discovery", f"{key} must be an array")
            metadata[key] = [str(item) for item in raw[key]]
    if "authorization_response_iss_parameter_supported" in raw and raw["authorization_response_iss_parameter_supported"] is not None:
        metadata["authorization_response_iss_parameter_supported"] = raw["authorization_response_iss_parameter_supported"] is True
    response_types = metadata["response_types_supported"]
    if not isinstance(response_types, list) or "code" not in [str(item) for item in response_types]:
        raise OidcError("discovery", "OpenID Provider does not support response_type=code")
    metadata["response_types_supported"] = [str(item) for item in response_types]
    if not isinstance(metadata["subject_types_supported"], list):
        raise OidcError("discovery", "subject_types_supported must be an array")
    metadata["subject_types_supported"] = [str(item) for item in metadata["subject_types_supported"]]
    if not isinstance(metadata["id_token_signing_alg_values_supported"], list):
        raise OidcError("discovery", "id_token_signing_alg_values_supported must be an array")
    metadata["id_token_signing_alg_values_supported"] = [str(item) for item in metadata["id_token_signing_alg_values_supported"]]
    if expected_issuer is not None and metadata["issuer"] != expected_issuer:
        raise OidcError("discovery", f'issuer mismatch: expected "{expected_issuer}", got "{metadata["issuer"]}"')
    return metadata


def discover_provider(metadata_url, tls=None):
    """Fetches and checks metadataUrl. Its issuer must be the issuer the URL was built from."""
    expected = issuer_from_metadata_url(metadata_url)
    answer = send(metadata_url, headers={"accept": "application/json"}, tls=tls, code="discovery")
    if answer["status"] != 200:
        raise OidcError("discovery", f"{metadata_url} answered {answer['status']}")
    import json
    try:
        body = json.loads(answer["body"])
    except Exception as err:
        raise OidcError("discovery", f"{metadata_url} did not answer JSON", cause=err) from err
    return validate_provider_metadata(body, expected)


def well_known_urls(issuer, suffix):
    """RFC 8414 well-known URLs: path insertion, then the appended form."""
    parts = urlsplit(issuer)
    path = (parts.path or "").rstrip("/")
    origin = f"{parts.scheme}://{parts.netloc}"
    inserted = f"{origin}/.well-known/{suffix}{path}"
    appended = f"{origin}{path}/.well-known/{suffix}"
    if inserted == appended:
        return [inserted]
    return [inserted, appended]


def id_token_algorithms(advertised, pinned=None):
    """The algorithms an ID token from this provider may use."""
    advertised = list(advertised or [])
    if pinned:
        if pinned not in advertised:
            raise OidcError("discovery", f"the provider does not advertise id_token alg {pinned}")
        return [pinned]
    allowed = [alg for alg in advertised if alg in ASYMMETRIC_JWS_ALGS]
    if not allowed:
        raise OidcError("discovery", f"none of the provider's ID token algorithms can be verified ({', '.join(advertised)})")
    return allowed
