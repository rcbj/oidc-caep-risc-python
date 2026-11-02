# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A confidential OpenID Connect relying party. Tokens stay in this process."""

import hashlib
import hmac
import json
import time
from urllib.parse import urlencode, urlsplit, urlunsplit

from .client_auth import apply_client_auth, load_signing_key
from .config import read_config_file
from .discovery import discover_provider, id_token_algorithms
from .errors import OidcError
from .id_token import fetch_jwks, validate_id_token
from .backchannel import send
from .pkce import code_challenge_s256, random_token

_FRONT = ("access_token", "id_token", "refresh_token", "token_type")


def _same(left, right):
    a = left.encode("utf-8")
    b = right.encode("utf-8")
    return len(a) == len(b) and hmac.compare_digest(a, b)


def _claim_string(claims, name):
    value = claims.get(name)
    return value if isinstance(value, str) and value else None


class Query(dict):
    """Callback parameters. A missing key stays missing; None is ignored."""

    @classmethod
    def from_value(cls, callback):
        if isinstance(callback, Query):
            return callback
        out = cls()
        if hasattr(callback, "items"):
            for key, value in callback.items():
                if value is None:
                    continue
                out[key] = value
        return out

    def has(self, name):
        return name in self and self[name] is not None


def _form_body(pairs):
    return urlencode(list(pairs.items()), doseq=False)


class RelyingParty:
    """A confidential OpenID Connect client. Build it with from_file or create."""

    def __init__(self, config, metadata, key):
        self.config = config
        self.metadata = metadata
        self._key = key
        self._jwks = None
        self._algorithms = id_token_algorithms(
            metadata.get("id_token_signing_alg_values_supported") or [],
            config.get("idTokenSignedResponseAlg"),
        )
        self._used_codes = {}
        self._client_credentials = None

    @classmethod
    def from_file(cls, path):
        """Reads a configuration file, discovers the provider, and returns a client."""
        return cls.create(read_config_file(path))

    @classmethod
    def create(cls, config):
        """Discovers the provider (or uses metadata already loaded) and returns a client."""
        if not isinstance(config, dict):
            raise OidcError("config", "the configuration must be a JSON object")
        method = config.get("tokenEndpointAuthMethod")
        if method == "private_key_jwt" and not config.get("privateKeyPem"):
            raise OidcError("config", "private_key_jwt needs a private key")
        if method != "private_key_jwt" and not config.get("clientSecret"):
            raise OidcError("config", f"{method} needs a client secret")
        tls = {"ca": config["tlsCa"]} if config.get("tlsCa") else {}
        if not config.get("allowInsecure"):
            for name, value in (("issuer", config.get("issuer")), ("metadataUrl", config.get("metadataUrl"))):
                if value and _scheme(value if str(value).startswith("http") else f"https://{value}") == "http" and name == "issuer":
                    raise OidcError("config", "issuer must use https (set allowInsecure for a development provider)")
        metadata = config.get("metadata")
        if not metadata:
            if not config.get("metadataUrl"):
                raise OidcError("config", "metadataUrl or metadata is required")
            if not config.get("allowInsecure") and _scheme(config["metadataUrl"]) != "https":
                raise OidcError("config", "metadataUrl must use https (set allowInsecure for a development provider)")
            metadata = discover_provider(config["metadataUrl"], tls)
        if not config.get("allowInsecure"):
            for name, value in metadata.items():
                http = isinstance(value, str) and value.startswith("http:")
                if (http and name.endswith("endpoint")) or (name == "jwks_uri" and http) or (name == "issuer" and http):
                    raise OidcError("discovery", f"{name} must use https: {value}")
        methods = metadata.get("token_endpoint_auth_methods_supported")
        if methods and method not in methods:
            raise OidcError("discovery", f"the provider does not advertise {method}")
        challenges = metadata.get("code_challenge_methods_supported")
        if challenges and "S256" not in challenges:
            raise OidcError("discovery", "the provider does not advertise PKCE S256")
        key = load_signing_key(config["privateKeyPem"], config.get("privateKeyAlg") or "RS256") if config.get("privateKeyPem") else None
        return cls(config, metadata, key)

    def tls(self):
        """PEM trust anchors for calls to this provider, when the configuration named one."""
        return {"ca": self.config["tlsCa"]} if self.config.get("tlsCa") else {}

    def authorize(self, redirect_uri=None, scope=None, prompt=None, login_hint=None, max_age=None, acr_values=None, expected_sub=None):
        """Builds the Authentication Request. Keep the transaction until complete."""
        redirect_uri = redirect_uri or self.config["redirectUri"]
        scope = scope or self.config["scopes"]
        state = random_token()
        nonce = random_token()
        code_verifier = random_token()
        params = {
            "response_type": "code",
            "client_id": self.config["clientId"],
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge_s256(code_verifier),
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        if login_hint:
            params["login_hint"] = login_hint
        if max_age is not None:
            params["max_age"] = str(max_age)
        if acr_values:
            params["acr_values"] = acr_values
        transaction = {
            "state": state,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        }
        if max_age is not None:
            transaction["max_age"] = max_age
        if expected_sub:
            transaction["expected_sub"] = expected_sub
        par = self.metadata.get("pushed_authorization_request_endpoint")
        use_par = self.config.get("par") == "always" or (self.config.get("par") == "auto" and bool(par))
        if self.config.get("par") == "always" and not par:
            raise OidcError("discovery", "par is always, and the provider has no pushed authorization endpoint")
        if use_par and par:
            pushed = self._form(par, params)
            request_uri = pushed.get("request_uri") if isinstance(pushed.get("request_uri"), str) else ""
            if not request_uri:
                raise OidcError("protocol", "the pushed authorization response has no request_uri")
            url = _with_query(self.metadata["authorization_endpoint"], {
                "client_id": self.config["clientId"],
                "request_uri": request_uri,
            })
            return {**transaction, "url": url}
        return {**transaction, "url": _with_query(self.metadata["authorization_endpoint"], params)}

    def complete(self, callback, transaction):
        """Exchanges the code from the redirect URI. A code is accepted once."""
        params = Query.from_value(callback)
        for name in _FRONT:
            if params.has(name):
                raise OidcError("validation", f"{name} was returned on the redirect, and a code-flow client refuses it")
        if params.get("error"):
            description = params.get("error_description")
            message = f"{params.get('error')}: {description}" if description else str(params.get("error"))
            raise OidcError("protocol", message, oauth_error=params.get("error"))
        state = params.get("state") or ""
        if not transaction.get("state") or not _same(state, transaction["state"]):
            raise OidcError("validation", "the callback state does not match this sign-in")
        if "iss" in params and params.get("iss") != self.metadata["issuer"]:
            raise OidcError("validation", f"iss mismatch in the callback: {params.get('iss')}")
        if "iss" not in params and self.metadata.get("authorization_response_iss_parameter_supported"):
            raise OidcError("validation", "iss is missing from the callback, and the provider requires it")
        code = params.get("code")
        if not code:
            raise OidcError("validation", "the callback has no code")
        self._remember_code(code)
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": transaction["redirect_uri"],
            "code_verifier": transaction["code_verifier"],
        }
        tokens = self._token(body)
        if not tokens.get("id_token"):
            raise OidcError("protocol", "the token response has no id_token")
        extra = {"nonce": transaction["nonce"], "accessToken": tokens["access_token"], "code": code}
        if transaction.get("max_age") is not None:
            extra["maxAge"] = transaction["max_age"]
        claims = self._id_token(tokens["id_token"], extra)
        if transaction.get("expected_sub") and claims.get("sub") != transaction["expected_sub"]:
            raise OidcError("validation", "the provider signed in a different account from the one requested")
        return _login_from(tokens, claims)

    def refresh(self, refresh_token, scope=None, previous=None):
        """Refresh Token grant. A new ID token's subject is checked against previous."""
        if not refresh_token:
            raise OidcError("protocol", "there is no refresh token")
        body = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if scope:
            body["scope"] = scope
        tokens = self._token(body)
        claims = previous.get("claims") if previous else None
        id_token = tokens.get("id_token") or (previous.get("id_token") if previous else None)
        if tokens.get("id_token"):
            if not previous:
                raise OidcError("validation", "the refresh returned an ID token and there is no previous sign-in to check it against")
            claims = self._id_token(tokens["id_token"], {"accessToken": tokens["access_token"], "previousSub": previous["subject"]})
            id_token = tokens["id_token"]
        if not claims or not id_token or (not previous and not tokens.get("id_token")):
            raise OidcError("protocol", "the refresh returned no ID token and no previous sign-in was given")
        merged = dict(tokens)
        merged["refresh_token"] = tokens.get("refresh_token") or refresh_token
        merged["id_token"] = id_token
        return _login_from(merged, claims)

    def client_credentials(self, scope="ssf.manage"):
        """Client Credentials grant. The token is cached until shortly before it expires."""
        now = time.time()
        cached = self._client_credentials
        if cached and cached["scope"] == scope and cached["until"] > now:
            return cached["token"]
        tokens = self._token({"grant_type": "client_credentials", "scope": scope})
        token = _credentials_from(tokens)
        until = token["expires_at"] - 30 if token.get("expires_at") else now + 60
        self._client_credentials = {"scope": scope, "token": token, "until": until}
        return token

    def userinfo(self, access_token, expected_sub):
        """Calls UserInfo and checks that sub is expected_sub."""
        if not expected_sub:
            raise OidcError("validation", "userinfo needs the subject to check the response against")
        if not self.metadata.get("userinfo_endpoint"):
            raise OidcError("discovery", "the provider has no userinfo_endpoint")
        answer = send(self.metadata["userinfo_endpoint"], headers={
            "accept": "application/json, application/jwt",
            "authorization": f"Bearer {access_token}",
        }, tls=self.tls(), code="protocol")
        if answer["status"] == 401:
            raise OidcError("protocol", "userinfo refused the access token", oauth_error="invalid_token")
        if answer["status"] != 200:
            raise OidcError("protocol", f"userinfo answered {answer['status']}")
        if "application/jwt" in answer["content_type"]:
            claims = self._id_token(answer["body"].strip(), {"algorithms": self._algorithms})
        else:
            try:
                body = json.loads(answer["body"])
            except Exception as err:
                raise OidcError("protocol", "userinfo did not answer JSON", cause=err) from err
            if not isinstance(body, dict):
                raise OidcError("validation", "userinfo did not answer a JSON object")
            claims = body
        if claims.get("sub") != expected_sub:
            raise OidcError("validation", "userinfo sub does not match the ID token sub")
        return claims

    def end_session_url(self, id_token=None, post_logout_redirect_uri=None, state=None, logout_hint=None):
        """The RP-Initiated Logout URL, or None when the provider has no end-session endpoint."""
        if not self.metadata.get("end_session_endpoint"):
            return None
        redirect = post_logout_redirect_uri or self.config.get("postLogoutRedirectUri")
        query = {}
        if id_token:
            query["id_token_hint"] = id_token
        if redirect:
            query["post_logout_redirect_uri"] = redirect
        query["client_id"] = self.config["clientId"]
        if logout_hint:
            query["logout_hint"] = logout_hint
        if state:
            query["state"] = state
        return _with_query(self.metadata["end_session_endpoint"], query)

    def _id_token(self, token, extra):
        checks = {
            "issuer": self.metadata["issuer"],
            "clientId": self.config["clientId"],
            "algorithms": extra.get("algorithms") or self._algorithms,
            "jwks": self._keys(),
            "clockToleranceSec": self.config.get("clockToleranceSec"),
            "maxIdTokenAgeSec": self.config.get("maxIdTokenAgeSec"),
        }
        if self.config.get("clientSecret"):
            checks["clientSecret"] = self.config["clientSecret"]
        for key, value in extra.items():
            if key != "algorithms":
                checks[key] = value
        try:
            return validate_id_token(token, checks)
        except OidcError as err:
            if err.code != "signature":
                raise
            self._jwks = None
            checks["jwks"] = self._keys(force=True)
            return validate_id_token(token, checks)

    def _keys(self, force=False):
        if not force and self._jwks is not None:
            return self._jwks
        self._jwks = fetch_jwks(self.metadata["jwks_uri"], self.tls())
        return self._jwks

    def _token(self, body):
        parsed = self._form(self.metadata["token_endpoint"], body)
        access = parsed.get("access_token")
        token_type = parsed.get("token_type")
        if not isinstance(access, str) or not access:
            raise OidcError("protocol", "the token response has no access_token")
        if not isinstance(token_type, str) or not token_type:
            raise OidcError("protocol", "the token response has no token_type")
        if token_type.lower() == "dpop":
            raise OidcError("protocol", "the provider returned a DPoP token; this client asked for a Bearer token")
        if token_type.lower() != "bearer":
            raise OidcError("protocol", f"the token response token_type is {token_type}")
        out = {"access_token": access, "token_type": token_type}
        if isinstance(parsed.get("id_token"), str):
            out["id_token"] = parsed["id_token"]
        if isinstance(parsed.get("refresh_token"), str):
            out["refresh_token"] = parsed["refresh_token"]
        if isinstance(parsed.get("expires_in"), (int, float)) and not isinstance(parsed.get("expires_in"), bool):
            out["expires_in"] = parsed["expires_in"]
        if isinstance(parsed.get("scope"), str):
            out["scope"] = parsed["scope"]
        return out

    def _form(self, url, body):
        headers = {"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}
        fields = dict(body)
        apply_client_auth(self.config, self._key, fields, headers, self.metadata["issuer"])
        answer = send(url, method="POST", headers=headers, body=_form_body(fields), tls=self.tls(), code="protocol")
        try:
            parsed = json.loads(answer["body"]) if answer["body"] else {}
        except Exception as err:
            raise OidcError("protocol", f"{url} answered {answer['status']} with no JSON", cause=err) from err
        doc = parsed if isinstance(parsed, dict) else {}
        if answer["status"] not in (200, 201):
            oauth_error = doc.get("error") if isinstance(doc.get("error"), str) else None
            description = doc.get("error_description") if isinstance(doc.get("error_description"), str) else ""
            message = f"{url} answered {answer['status']}"
            if oauth_error:
                message += f": {oauth_error}"
            if description:
                message += f": {description}"
            raise OidcError("protocol", message, oauth_error=oauth_error)
        return doc

    def _remember_code(self, code):
        """Refuses a code this process has already exchanged."""
        now = time.time()
        cutoff = now - 10 * 60
        for digest, at in list(self._used_codes.items()):
            if at < cutoff:
                del self._used_codes[digest]
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        if digest in self._used_codes:
            raise OidcError("validation", "this authorization code was already used")
        self._used_codes[digest] = now


def _scheme(value):
    return urlsplit(value).scheme


def _with_query(base, params):
    parts = urlsplit(base)
    query = urlencode(list(params.items()))
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


def _login_from(tokens, claims):
    login = {
        "subject": str(claims.get("sub")),
        "issuer": str(claims.get("iss")),
        "claims": claims,
        "access_token": tokens["access_token"],
        "id_token": tokens.get("id_token") or "",
        "token_type": tokens["token_type"],
    }
    for src, dest in (
        ("email", "email"),
        ("name", "name"),
        ("preferred_username", "preferred_username"),
        ("sid", "sid"),
    ):
        value = _claim_string(claims, src)
        if value:
            login[dest] = value
    if tokens.get("refresh_token"):
        login["refresh_token"] = tokens["refresh_token"]
    if tokens.get("expires_in") is not None:
        login["expires_at"] = time.time() + float(tokens["expires_in"])
    if tokens.get("scope"):
        login["scope"] = tokens["scope"]
    return login


def _credentials_from(tokens):
    out = {"access_token": tokens["access_token"], "token_type": tokens["token_type"]}
    if tokens.get("expires_in") is not None:
        out["expires_at"] = time.time() + float(tokens["expires_in"])
    if tokens.get("scope"):
        out["scope"] = tokens["scope"]
    return out
