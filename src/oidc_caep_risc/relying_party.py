# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A confidential OpenID Connect relying party. Tokens stay in this process."""

import hashlib
import hmac
import json
import threading
import time
from urllib.parse import urlencode, urlsplit, urlunsplit

from .client_auth import apply_client_auth, load_signing_key
from .config import apply_defaults, check_redirect, read_config_file
from .discovery import discover_provider, id_token_algorithms
from .dpop import DPOP_ALG, DPoPKey, is_nonce_challenge, load_dpop_key
from .errors import OidcError
from .id_token import fetch_jwks, validate_id_token
from .backchannel import send
from .pkce import code_challenge_s256, random_token
from .session_cache import MemorySessionTokenStore

_FRONT = ("access_token", "id_token", "refresh_token", "token_type")

# A cached sign-in access token is handed out while it has more than this many seconds left.
SESSION_TOKEN_MIN_TTL_SEC = 30


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

    def __init__(self, config, metadata, key=None, session_store=None):
        config = apply_defaults(config)
        self.config = config
        self.metadata = metadata
        if key is None and config.get("privateKeyPem"):
            key = load_signing_key(config["privateKeyPem"], config.get("privateKeyAlg") or "RS256")
        self._key = key
        self._jwks = None
        self._algorithms = id_token_algorithms(
            metadata.get("id_token_signing_alg_values_supported") or [],
            config.get("idTokenSignedResponseAlg"),
            config.get("idTokenSigningAlgs"),
        )
        self._used_codes = {}
        self._client_credentials = None
        self._use_par = _par_decision(config["par"], metadata)
        self._dpop = _dpop_key(config, metadata)
        self.sessions = session_store if session_store is not None else MemorySessionTokenStore()
        self._session_locks = {}
        self._session_locks_guard = threading.Lock()

    @property
    def dpop(self):
        """The DPoP key this client proves possession of, or None when it sends no proofs."""
        return self._dpop

    @classmethod
    def from_file(cls, path, session_store=None):
        """Reads a configuration file, discovers the provider, and returns a client."""
        return cls.create(read_config_file(path), session_store=session_store)

    @classmethod
    def create(cls, config, session_store=None):
        """Discovers the provider (or uses metadata already loaded) and returns a client.

        The same defaults and rules apply as for from_file (apply_defaults).
        """
        if not isinstance(config, dict):
            raise OidcError("config", "the configuration must be a JSON object")
        config = apply_defaults(config)
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
        return cls(config, metadata, key, session_store=session_store)

    def tls(self):
        """PEM trust anchors for calls to this provider, when the configuration named one."""
        return {"ca": self.config["tlsCa"]} if self.config.get("tlsCa") else {}

    def authorize(self, redirect_uri=None, scope=None, prompt=None, login_hint=None, max_age=None, acr_values=None, expected_sub=None):
        """Builds the Authentication Request. Keep the transaction until complete.

        acr_values (a string or a list) overrides the acrValues setting. When either names
        values, complete() requires the ID token's acr to be one of them.
        """
        redirect_uri = check_redirect(redirect_uri, "redirect_uri") if redirect_uri else self.config["redirectUri"]
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
        acr = _acr_string(acr_values) or self.config.get("acrValues")
        if acr:
            params["acr_values"] = acr
        if self._dpop is not None:
            params["dpop_jkt"] = self._dpop.thumbprint
        transaction = {
            "state": state,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        }
        if acr:
            transaction["acr_values"] = acr
        if max_age is not None:
            transaction["max_age"] = max_age
        if expected_sub:
            transaction["expected_sub"] = expected_sub
        par = self.metadata.get("pushed_authorization_request_endpoint")
        if self._use_par:
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

    def complete(self, callback, transaction, session_id=None):
        """Exchanges the code from the redirect URI. A code is accepted once.

        With session_id, the sign-in's tokens are kept in the session cache under it
        (see access_token_for). remember_session does the same afterwards.
        """
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
        requested = str(transaction.get("acr_values") or "").split()
        if requested:
            acr = claims.get("acr")
            if not isinstance(acr, str) or not acr:
                raise OidcError("validation", "acr_values was requested and the ID token has no acr")
            if acr not in requested:
                raise OidcError("validation", f"the ID token acr {acr} is not one of the requested {' '.join(requested)}")
        login = _login_from(tokens, claims)
        if session_id is not None:
            self.remember_session(session_id, login)
        return login

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

    def remember_session(self, session_id, login):
        """Keeps a completed sign-in's tokens under session_id in the session cache."""
        if session_id is None or session_id == "":
            raise OidcError("config", "a session identifier is required")
        if not isinstance(login, dict) or not login.get("access_token"):
            raise OidcError("config", "remember_session needs the sign-in complete() returned")
        self.sessions.set(session_id, login)
        return session_id

    def forget_session(self, session_id):
        """Removes a session's tokens: on sign-out, or when a CAEP session-revoked ends it."""
        self.sessions.delete(session_id)
        with self._session_locks_guard:
            self._session_locks.pop(session_id, None)

    def session(self, session_id):
        """The cached sign-in for session_id, or None."""
        return self.sessions.get(session_id)

    def access_token_for(self, session_id):
        """A valid access token for a session: {access_token, token_type, expires_at}.

        The cached one while it has more than 30 seconds left; otherwise one obtained with the
        refresh token (with a DPoP proof when DPoP is in use), and the cache is updated. A failed
        refresh, or no refresh token, removes the entry and raises OidcError.
        """
        with self._session_lock(session_id):
            login = self.sessions.get(session_id)
            if not login:
                raise OidcError("validation", "there is no signed-in session with that identifier")
            expires_at = login.get("expires_at")
            if expires_at is None or float(expires_at) - time.time() > SESSION_TOKEN_MIN_TTL_SEC:
                return _token_view(login)
            if not login.get("refresh_token"):
                self.forget_session(session_id)
                raise OidcError("protocol", "the session's access token has expired and there is no refresh token")
            try:
                refreshed = self.refresh(login["refresh_token"], previous=login)
            except OidcError as err:
                self.forget_session(session_id)
                raise OidcError(
                    "protocol",
                    f"the session's tokens could not be refreshed, and the session was removed: {err}",
                    cause=err,
                    oauth_error=err.oauth_error,
                ) from err
            self.sessions.set(session_id, refreshed)
            return _token_view(refreshed)

    def _session_lock(self, session_id):
        with self._session_locks_guard:
            lock = self._session_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                self._session_locks[session_id] = lock
            return lock

    def resource_request(self, method, url, access_token, token_type=None, headers=None, body=None, code="protocol", tls=None):
        """One request to a resource server with an access token.

        A DPoP-bound token (token_type DPoP, the default when this client uses DPoP) goes as
        Authorization: DPoP with a proof carrying ath. A 401 DPoP use_dpop_nonce challenge is
        retried once with the nonce it gave.
        """
        kind = (token_type or ("DPoP" if self._dpop is not None else "Bearer"))
        dpop = kind.lower() == "dpop"
        if dpop and self._dpop is None:
            raise OidcError("protocol", "the access token is DPoP-bound and this client has no DPoP key")
        attempt = 0
        while True:
            sent = dict(headers or {})
            if dpop:
                sent["authorization"] = f"DPoP {access_token}"
                sent["dpop"] = self._dpop.proof(method, url, access_token=access_token)
            else:
                sent["authorization"] = f"Bearer {access_token}"
            answer = send(url, method=method, headers=sent, body=body, tls=self.tls() if tls is None else tls, code=code)
            if dpop:
                self._dpop.remember(url, answer.get("headers"))
                challenge = (answer.get("headers") or {}).get("www-authenticate")
                if attempt == 0 and (answer.get("headers") or {}).get("dpop-nonce") and is_nonce_challenge(answer["status"], None, challenge):
                    attempt += 1
                    continue
            return answer

    def userinfo(self, access_token, expected_sub, token_type=None):
        """Calls UserInfo and checks that sub is expected_sub."""
        if not expected_sub:
            raise OidcError("validation", "userinfo needs the subject to check the response against")
        if not self.metadata.get("userinfo_endpoint"):
            raise OidcError("discovery", "the provider has no userinfo_endpoint")
        answer = self.resource_request("GET", self.metadata["userinfo_endpoint"], access_token, token_type, headers={
            "accept": "application/json, application/jwt",
        })
        if answer["status"] == 401:
            raise OidcError("protocol", "userinfo refused the access token", oauth_error="invalid_token")
        if answer["status"] != 200:
            raise OidcError("protocol", f"userinfo answered {answer['status']}")
        if "application/jwt" in answer["content_type"]:
            claims = self._id_token(answer["body"].strip(), {"algorithms": self._algorithms, "userinfo": True})
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
        strict = self.config.get("requireIdTokenTypAndAtHash") is not False
        checks = {
            "issuer": self.metadata["issuer"],
            "clientId": self.config["clientId"],
            "algorithms": extra.get("algorithms") or self._algorithms,
            "jwks": self._keys(),
            "clockToleranceSec": self.config.get("clockToleranceSec"),
            "maxIdTokenAgeSec": self.config.get("maxIdTokenAgeSec"),
            "requireTyp": strict and not extra.get("userinfo"),
            "requireAtHash": strict,
        }
        if self.config.get("clientSecret"):
            checks["clientSecret"] = self.config["clientSecret"]
        for key, value in extra.items():
            if key not in ("algorithms", "userinfo"):
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
        if self._dpop is not None and token_type.lower() != "dpop":
            raise OidcError("protocol", f"this client sent a DPoP proof and the token response token_type is {token_type}, not DPoP")
        if self._dpop is None and token_type.lower() != "bearer":
            raise OidcError("protocol", f"this client sent no DPoP proof and the token response token_type is {token_type}, not Bearer")
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
        """A POST to the token or pushed authorization endpoint. With DPoP it carries a proof,
        and a 400 use_dpop_nonce is retried once with the nonce the response gave."""
        attempt = 0
        while True:
            headers = {"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}
            fields = dict(body)
            apply_client_auth(self.config, self._key, fields, headers, self.metadata["issuer"])
            if self._dpop is not None:
                headers["dpop"] = self._dpop.proof("POST", url)
            answer = send(url, method="POST", headers=headers, body=_form_body(fields), tls=self.tls(), code="protocol")
            nonce = self._dpop.remember(url, answer.get("headers")) if self._dpop is not None else None
            try:
                parsed = json.loads(answer["body"]) if answer["body"] else {}
            except Exception as err:
                raise OidcError("protocol", f"{url} answered {answer['status']} with no JSON", cause=err) from err
            doc = parsed if isinstance(parsed, dict) else {}
            oauth_error = doc.get("error") if isinstance(doc.get("error"), str) else None
            if attempt == 0 and nonce and is_nonce_challenge(answer["status"], oauth_error, None):
                attempt += 1
                continue
            break
        if answer["status"] not in (200, 201):
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


def _par_decision(mode, metadata):
    """Whether authorize() pushes. A provider that requires PAR makes auto push and never fail."""
    endpoint = metadata.get("pushed_authorization_request_endpoint")
    required = metadata.get("require_pushed_authorization_requests") is True
    if mode == "never":
        if required:
            raise OidcError("discovery", "par is never, and the provider requires pushed authorization requests")
        return False
    if not endpoint:
        if mode == "always":
            raise OidcError("discovery", "par is always, and the provider has no pushed authorization endpoint")
        if required:
            raise OidcError("discovery", "the provider requires pushed authorization requests and has no pushed authorization endpoint")
        return False
    return True


def _dpop_key(config, metadata):
    """The DPoP key, or None. auto uses DPoP when the provider advertises ES256 for it."""
    mode = config["dpop"]
    supplied = load_dpop_key(config["dpopKeyPem"]) if config.get("dpopKeyPem") else None
    if mode == "never":
        return None
    advertised = [str(item) for item in (metadata.get("dpop_signing_alg_values_supported") or [])]
    if DPOP_ALG not in advertised:
        if mode == "always":
            if not advertised:
                raise OidcError("discovery", "dpop is always, and the provider does not advertise dpop_signing_alg_values_supported")
            raise OidcError("discovery", f"dpop is always, and the provider does not advertise {DPOP_ALG} for DPoP ({', '.join(advertised)})")
        return None
    return DPoPKey(supplied)


def _acr_string(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        joined = " ".join(str(item).strip() for item in value if str(item).strip())
    else:
        joined = " ".join(str(value).split())
    return joined or None


def _token_view(login):
    out = {"access_token": login["access_token"], "token_type": login["token_type"]}
    if login.get("expires_at") is not None:
        out["expires_at"] = login["expires_at"]
    return out


def _credentials_from(tokens):
    out = {"access_token": tokens["access_token"], "token_type": tokens["token_type"]}
    if tokens.get("expires_in") is not None:
        out["expires_at"] = time.time() + float(tokens["expires_in"])
    if tokens.get("scope"):
        out["scope"] = tokens["scope"]
    return out
