# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Configuration. JSON keys are the same names the Node library reads."""

import json
import os

from .discovery import DEFAULT_SCOPES, issuer_from_metadata_url, validate_provider_metadata
from .errors import OidcError

AUTH_METHODS = ("client_secret_basic", "client_secret_post", "private_key_jwt")


class ResolvedConfig(dict):
    """Resolved configuration. Attribute access uses the JSON key names.

    signals is omitted when CAEP and RISC are on, and present as false when they are off.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as err:
            raise AttributeError(name) from err


def _as_object(raw):
    if not isinstance(raw, dict):
        raise OidcError("config", "the configuration must be a JSON object")
    return raw


def _read_path(path, base_dir, what):
    full = path if os.path.isabs(path) else os.path.join(base_dir, path)
    try:
        with open(full, encoding="utf-8") as handle:
            return handle.read().strip()
    except Exception as err:
        raise OidcError("config", f"could not read {what} at {full}: {err}", cause=err) from err


def _secret_value(raw, base_dir, what):
    if raw.startswith("env:"):
        name = raw[4:]
        value = os.environ.get(name)
        if not value:
            raise OidcError("config", f"{what} reads {name}, and that variable is empty")
        return value
    if raw.startswith("file:"):
        return _read_path(raw[5:], base_dir, what)
    return raw


def _key_value(raw, base_dir, what):
    if raw.startswith("env:") or raw.startswith("file:") or "-----BEGIN" in raw:
        return _secret_value(raw, base_dir, what)
    return _read_path(raw, base_dir, what)


def _read_trust(raw, base_dir):
    """PEM, file:, env:, or a path. A path that is not there yet is absent, not an error."""
    if not raw:
        return None
    value = str(raw).strip()
    if not value:
        return None
    if "-----BEGIN" in value:
        return value
    if value.startswith("env:"):
        return os.environ.get(value[4:]) or None
    path = value[5:] if value.startswith("file:") else value
    full = path if os.path.isabs(path) else os.path.join(base_dir, path)
    try:
        with open(full, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def _signals_on(value):
    if value is None or value is True:
        return True
    if value is False:
        return False
    raise OidcError("config", "signals must be true or false")


def _is_loopback(hostname):
    return hostname in ("localhost", "127.0.0.1", "::1", "[::1]")


def _check_redirect(value, name, allow_insecure):
    from urllib.parse import urlsplit
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise OidcError("config", f"{name} is not a URL: {value}")
    if parts.scheme == "https":
        return value
    if parts.scheme == "http" and (_is_loopback(parts.hostname) or allow_insecure):
        return value
    raise OidcError("config", f"{name} must use https, or http on loopback: {value}")


def resolve_config(raw, base_dir):
    """Reads a configuration object and fills the defaults. base_dir is where relative paths start."""
    doc = _as_object(raw)
    client_id = str(doc.get("clientId") if doc.get("clientId") is not None else doc.get("client_id") or "").strip()
    if not client_id:
        raise OidcError("config", "client_id is required")
    method_raw = str(doc.get("tokenEndpointAuthMethod") or "client_secret_basic")
    if method_raw == "none":
        raise OidcError("config", 'tokenEndpointAuthMethod "none" is a public client; this library authenticates a confidential client')
    if method_raw not in AUTH_METHODS:
        raise OidcError("config", f"tokenEndpointAuthMethod must be {', '.join(AUTH_METHODS)}, not {method_raw}")
    redirect_uri = str(doc.get("redirectUri") if doc.get("redirectUri") is not None else doc.get("redirect_uri") or "").strip()
    if not redirect_uri:
        raise OidcError("config", "redirectUri is required")
    allow_insecure = doc.get("allowInsecure") is True
    signals_present = "signals" in doc
    signals = _signals_on(doc.get("signals") if signals_present else None)
    if "scopes" not in doc or doc.get("scopes") is None:
        scopes = DEFAULT_SCOPES.strip()
    elif isinstance(doc.get("scopes"), list):
        scopes = " ".join(part for part in (str(item).strip() for item in doc["scopes"]) if part)
    else:
        scopes = str(doc.get("scopes")).strip()
    if not signals:
        scopes = " ".join(part for part in scopes.split() if part not in ("ssf.read", "ssf.manage"))
    if "openid" not in scopes.split():
        raise OidcError("config", "scopes must include openid")
    par = doc.get("par") if "par" in doc and doc.get("par") is not None else "auto"
    if par not in ("auto", "always", "never"):
        raise OidcError("config", "par must be auto, always, or never")

    issuer = str(doc["issuer"]).strip() if doc.get("issuer") else None
    metadata_url = str(doc["metadataUrl"]).strip() if doc.get("metadataUrl") else None
    if metadata_url:
        from_url = issuer_from_metadata_url(metadata_url)
        if issuer and issuer != from_url:
            raise OidcError("config", f"issuer {issuer} is not the issuer of {metadata_url} ({from_url})")
        issuer = from_url
    metadata = None
    if doc.get("metadataFile"):
        full = doc["metadataFile"] if os.path.isabs(doc["metadataFile"]) else os.path.join(base_dir, doc["metadataFile"])
        try:
            with open(full, encoding="utf-8") as handle:
                body = json.loads(handle.read())
        except Exception as err:
            raise OidcError("config", f"could not read metadata at {full}: {err}", cause=err) from err
        metadata = validate_provider_metadata(body, issuer)
        issuer = metadata["issuer"]
    if not metadata_url and not metadata:
        raise OidcError("config", "metadataUrl or metadataFile is required")

    needs_secret = method_raw != "private_key_jwt"
    client_secret = None
    if doc.get("clientSecret"):
        client_secret = _secret_value(str(doc["clientSecret"]), base_dir, "the client secret")
    if needs_secret and not client_secret:
        raise OidcError("config", f"{method_raw} needs clientSecret")
    private_key_pem = None
    if doc.get("privateKey"):
        private_key_pem = _key_value(str(doc["privateKey"]), base_dir, "the private key")
    if method_raw == "private_key_jwt" and not private_key_pem:
        raise OidcError("config", "private_key_jwt needs privateKey")

    tls_ca = _read_trust(doc.get("tlsCa"), base_dir)
    post_raw = doc.get("postLogoutRedirectUri")
    if post_raw is None:
        post_raw = doc.get("post_logout_redirect_uri")
    post_logout = str(post_raw or "").strip()
    ssf = None
    ssf_doc = doc.get("ssf") if isinstance(doc.get("ssf"), dict) else None
    if signals and ssf_doc and ssf_doc.get("transmitter"):
        transmitter = str(ssf_doc["transmitter"]).rstrip("/")
        if not transmitter.startswith("http://") and not transmitter.startswith("https://"):
            raise OidcError("config", "ssf.transmitter must be an http(s) URL")
        ssf = {"transmitter": transmitter}
        if ssf_doc.get("pollIntervalMs"):
            ssf["pollIntervalMs"] = ssf_doc["pollIntervalMs"]

    out = ResolvedConfig()
    if issuer:
        out["issuer"] = issuer
    if metadata_url:
        out["metadataUrl"] = metadata_url
    if metadata:
        out["metadata"] = metadata
    out["clientId"] = client_id
    if client_secret:
        out["clientSecret"] = client_secret
    if private_key_pem:
        out["privateKeyPem"] = private_key_pem
    out["privateKeyAlg"] = doc.get("privateKeyAlg") or "RS256"
    out["tokenEndpointAuthMethod"] = method_raw
    out["redirectUri"] = _check_redirect(redirect_uri, "redirectUri", allow_insecure)
    if post_logout:
        out["postLogoutRedirectUri"] = _check_redirect(post_logout, "postLogoutRedirectUri", allow_insecure)
    out["scopes"] = scopes
    if doc.get("idTokenSignedResponseAlg"):
        out["idTokenSignedResponseAlg"] = doc["idTokenSignedResponseAlg"]
    out["par"] = par
    out["clockToleranceSec"] = 30 if doc.get("clockToleranceSec") is None else doc["clockToleranceSec"]
    out["maxIdTokenAgeSec"] = 600 if doc.get("maxIdTokenAgeSec") is None else doc["maxIdTokenAgeSec"]
    out["allowInsecure"] = allow_insecure
    if tls_ca:
        out["tlsCa"] = tls_ca
    if not signals:
        out["signals"] = False
    if ssf:
        out["ssf"] = ssf
    return out


def read_config_file(path):
    """Reads a configuration file. Relative paths start in the file's directory."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.loads(handle.read())
    except Exception as err:
        raise OidcError("config", f"could not read {path}: {err}", cause=err) from err
    return resolve_config(raw, os.path.abspath(os.path.join(path, os.pardir)))
