# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The confidential client against a stub OpenID Provider."""

import base64
import hashlib
import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from oidc_caep_risc import DEFAULT_SCOPES, OidcError, RelyingParty, hash_claim, resolve_config
from oidc_caep_risc.b64 import b64url_encode
from oidc_caep_risc.keys import verify_signature

CLIENT = "oidc-caep-risc-demo"
SECRET = "test-secret"
SCOPES = "openid profile email offline_access ssf.read ssf.manage"

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_CLIENT = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64_uint(number):
    length = max(1, (number.bit_length() + 7) // 8)
    return b64url_encode(number.to_bytes(length, "big"))


def _public_jwk(key, kid):
    numbers = key.public_key().public_numbers()
    return {"kty": "RSA", "n": _b64_uint(numbers.n), "e": _b64_uint(numbers.e), "kid": kid, "alg": "RS256", "use": "sig"}


_JWK = _public_jwk(_PRIVATE, "op")
_CLIENT_PEM = _CLIENT.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode("ascii")
_CLIENT_PUBLIC = _CLIENT.public_key()


def _id_token(payload, corrupt=False, typ="JWT", alg="RS256"):
    head = {"alg": alg, "kid": "op"}
    if typ is not None:
        head["typ"] = typ
    header = b64url_encode(json.dumps(head, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = _PRIVATE.sign(f"{header}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    sig = b64url_encode(signature)
    if corrupt:
        sig = ("B" if sig[0] == "A" else "A") + sig[1:]
    return f"{header}.{body}.{sig}"


def _client_ok(assertion, audience):
    parts = assertion.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        signature = base64.urlsafe_b64decode(parts[2] + "==")
    except Exception:
        return False
    if header.get("alg") != "RS256":
        return False
    signing = f"{parts[0]}.{parts[1]}".encode("ascii")
    if not verify_signature(_CLIENT_PUBLIC, "RS256", signing, signature):
        return False
    aud = payload.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    return payload.get("iss") == CLIENT and payload.get("sub") == CLIENT and audience in audiences


def _b64json(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def check_proof(header, method, url, access_token=None):
    """Verifies a DPoP proof the way an RFC 9449 server does, and returns header, payload, jkt."""
    from cryptography.hazmat.primitives.asymmetric import ec
    parts = header.split(".")
    assert len(parts) == 3, "not a compact JWS"
    head = _b64json(parts[0])
    payload = _b64json(parts[1])
    assert head.get("typ") == "dpop+jwt", f"typ {head.get('typ')}"
    assert head.get("alg") == "ES256", f"alg {head.get('alg')}"
    jwk = head.get("jwk") or {}
    assert jwk.get("kty") == "EC" and jwk.get("crv") == "P-256", "jwk"
    assert "d" not in jwk, "the jwk header carries the private key"
    x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big")
    key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    assert verify_signature(key, "ES256", f"{parts[0]}.{parts[1]}".encode("ascii"), signature), "signature"
    assert payload.get("htm") == method, f"htm {payload.get('htm')}"
    assert payload.get("htu") == url, f"htu {payload.get('htu')} is not {url}"
    assert isinstance(payload.get("jti"), str) and payload["jti"], "jti"
    assert abs(payload.get("iat", 0) - time.time()) < 60, "iat"
    if access_token is not None:
        ath = b64url_encode(hashlib.sha256(access_token.encode()).digest())
        assert payload.get("ath") == ath, "ath"
    else:
        assert "ath" not in payload, "ath on a token request"
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    jkt = b64url_encode(hashlib.sha256(canonical.encode()).digest())
    return {"header": head, "payload": payload, "jkt": jkt}


class _Provider(ThreadingHTTPServer):
    daemon_threads = True


def _start_provider():
    stub = {
        "url": "",
        "par": False,
        "corrupt": False,
        "aud": CLIENT,
        "exp": None,
        "bad_at_hash": False,
        # Issue 16: what the stub advertises and how it answers.
        "dpop_algs": None,
        "require_par": False,
        "id_token_algs": ["RS256"],
        "dpop_nonce": None,
        "rs_nonce": None,
        "acr": None,
        "typ": "JWT",
        "omit_at_hash": False,
        "iat_offset": 0,
        "expires_in": 300,
        "token_type": None,
        "refresh_fails": False,
        "seen": [],
    }
    codes = {}
    refresh = {}
    access = {}
    pushed = {}

    def metadata():
        doc = {
            "issuer": stub["url"],
            "authorization_endpoint": f"{stub['url']}/authorize",
            "token_endpoint": f"{stub['url']}/token",
            "jwks_uri": f"{stub['url']}/jwks",
            "userinfo_endpoint": f"{stub['url']}/userinfo",
            "end_session_endpoint": f"{stub['url']}/end-session",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": list(stub["id_token_algs"]),
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
            "scopes_supported": SCOPES.split(" "),
        }
        if stub["par"]:
            doc["pushed_authorization_request_endpoint"] = f"{stub['url']}/par"
        if stub["require_par"]:
            doc["require_pushed_authorization_requests"] = True
        if stub["dpop_algs"] is not None:
            doc["dpop_signing_alg_values_supported"] = list(stub["dpop_algs"])
        return doc

    def token_for(row, proof=None):
        access_token = os.urandom(16).hex()
        refresh_token = os.urandom(16).hex()
        now = int(time.time())
        payload = {
            "iss": stub["url"],
            "sub": row["sub"],
            "aud": stub["aud"],
            "exp": stub["exp"] if stub["exp"] is not None else now + 300,
            "iat": stub["exp"] if stub["exp"] else now + stub["iat_offset"],
            "nonce": row["nonce"],
            "email": row["email"],
            "name": "Demo User",
            "preferred_username": row["sub"],
            "sid": row["sid"],
            "at_hash": "aaaa" if stub["bad_at_hash"] else hash_claim(access_token, "RS256"),
        }
        if stub["omit_at_hash"]:
            payload.pop("at_hash")
        if stub["acr"] is not None:
            payload["acr"] = stub["acr"]
        token = _id_token(payload, stub["corrupt"], typ=stub["typ"])
        refresh[refresh_token] = row
        access[access_token] = {**payload, "_jkt": proof["jkt"] if proof else None}
        stub["aud"] = CLIENT
        stub["corrupt"] = False
        stub["bad_at_hash"] = False
        stub["exp"] = None
        return {
            "access_token": access_token,
            "token_type": stub["token_type"] or ("DPoP" if proof else "Bearer"),
            "expires_in": stub["expires_in"],
            "refresh_token": refresh_token,
            "id_token": token,
            "scope": SCOPES,
        }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _json(self, status, body, headers=None):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(raw)

        def _proof(self, path, access_token=None):
            """Checks a DPoP header. None when absent; raises AssertionError when malformed."""
            header = self.headers.get("dpop")
            if not header:
                stub["seen"].append({"path": path, "proof": None})
                return None
            proof = check_proof(header, self.command, f"{stub['url']}{path}", access_token)
            stub["seen"].append({"path": path, "proof": proof})
            return proof

        def _needs_nonce(self, proof, wanted):
            return proof is not None and wanted is not None and proof["payload"].get("nonce") != wanted

        def _authorized(self, body):
            header = self.headers.get("authorization") or ""
            if header.startswith("Basic "):
                decoded = base64.b64decode(header[6:]).decode()
                from urllib.parse import quote
                encoded = f"{quote(CLIENT, safe='-_.!~*()')}:{quote(SECRET, safe='-_.!~*()')}"
                return decoded == encoded or decoded == f"{CLIENT}:{SECRET}"
            params = parse_qs(body, keep_blank_values=True)
            if params.get("client_secret"):
                return (params.get("client_id") or [""])[0] == CLIENT and params["client_secret"][0] == SECRET
            assertion = (params.get("client_assertion") or [""])[0]
            if not assertion:
                return False
            return _client_ok(assertion, stub["url"])

        def _handle(self):
            length = int(self.headers.get("content-length") or 0)
            text = self.rfile.read(length).decode() if length else ""
            url = urlsplit(self.path)
            path = url.path
            if path == "/.well-known/openid-configuration":
                return self._json(200, metadata())
            if path == "/jwks":
                return self._json(200, {"keys": [_JWK]})
            if path == "/userinfo":
                authorization = self.headers.get("authorization") or ""
                scheme, _, token = authorization.partition(" ")
                claims = access.get(token.strip())
                if not claims:
                    return self._json(401, {"error": "invalid_token"})
                if claims["_jkt"]:
                    if scheme != "DPoP":
                        return self._json(401, {"error": "invalid_token"})
                    try:
                        proof = self._proof(path, token.strip())
                    except AssertionError as err:
                        return self._json(401, {"error": "invalid_dpop_proof", "error_description": str(err)})
                    if proof is None or proof["jkt"] != claims["_jkt"]:
                        return self._json(401, {"error": "invalid_dpop_proof"})
                    if self._needs_nonce(proof, stub["rs_nonce"]):
                        return self._json(401, {"error": "use_dpop_nonce"}, {
                            "WWW-Authenticate": 'DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"',
                            "DPoP-Nonce": stub["rs_nonce"],
                        })
                elif scheme != "Bearer":
                    return self._json(401, {"error": "invalid_token"})
                return self._json(200, {key: value for key, value in claims.items() if not key.startswith("_")})
            if path == "/par" and self.command == "POST":
                if not self._authorized(text):
                    return self._json(401, {"error": "invalid_client"})
                try:
                    proof = self._proof(path)
                except AssertionError as err:
                    return self._json(400, {"error": "invalid_dpop_proof", "error_description": str(err)})
                if self._needs_nonce(proof, stub["dpop_nonce"]):
                    return self._json(400, {"error": "use_dpop_nonce"}, {"DPoP-Nonce": stub["dpop_nonce"]})
                params = parse_qs(text, keep_blank_values=True)
                request_uri = "urn:par:" + os.urandom(8).hex()
                pushed[request_uri] = params
                stub["pushed"] = params
                return self._json(201, {"request_uri": request_uri, "expires_in": 60})
            if path == "/authorize":
                query = parse_qs(url.query, keep_blank_values=True)
                stored = (query.get("request_uri") or [None])[0]
                params = pushed.get(stored) if stored else query
                if not params:
                    return self._json(400, {"error": "invalid_request"})
                if stub["require_par"] and not stored:
                    return self._json(400, {"error": "invalid_request", "error_description": "PAR is required"})
                stub["authorize_params"] = params
                redirect = (params.get("redirect_uri") or [""])[0]
                state = (params.get("state") or [""])[0]
                challenge = (params.get("code_challenge") or [""])[0]
                if (params.get("code_challenge_method") or [""])[0] != "S256" or not challenge:
                    return self._json(400, {"error": "invalid_request"})
                row = {"sub": "user-1", "email": "user-1@example.com", "sid": "sid-1", "nonce": (params.get("nonce") or [""])[0]}
                code = os.urandom(16).hex()
                codes[code] = {**row, "redirect": redirect, "challenge": challenge}
                from urllib.parse import urlencode, urlunsplit, urlsplit as split
                back = split(redirect)
                q = urlencode({"code": code, "state": state, "iss": stub["url"]})
                location = urlunsplit((back.scheme, back.netloc, back.path or "/", q, ""))
                self.send_response(302)
                self.send_header("location", location)
                self.send_header("content-length", "0")
                self.end_headers()
                return
            if path == "/token" and self.command == "POST":
                if not self._authorized(text):
                    return self._json(401, {"error": "invalid_client", "error_description": "client authentication failed"})
                try:
                    proof = self._proof(path)
                except AssertionError as err:
                    return self._json(400, {"error": "invalid_dpop_proof", "error_description": str(err)})
                if self._needs_nonce(proof, stub["dpop_nonce"]):
                    return self._json(400, {"error": "use_dpop_nonce"}, {"DPoP-Nonce": stub["dpop_nonce"]})
                params = parse_qs(text, keep_blank_values=True)
                grant = (params.get("grant_type") or [""])[0]
                if grant == "client_credentials":
                    return self._json(200, {
                        "access_token": "cc-token",
                        "token_type": stub["token_type"] or ("DPoP" if proof else "Bearer"),
                        "expires_in": 120,
                        "scope": (params.get("scope") or [""])[0],
                    })
                if grant == "refresh_token":
                    if stub["refresh_fails"]:
                        return self._json(400, {"error": "invalid_grant"})
                    row = refresh.get((params.get("refresh_token") or [""])[0])
                    if not row:
                        return self._json(400, {"error": "invalid_grant"})
                    minted = token_for(row, proof)
                    claims = {key: value for key, value in access[minted["access_token"]].items() if not key.startswith("_")}
                    claims.pop("nonce", None)
                    minted["id_token"] = _id_token(claims)
                    return self._json(200, minted)
                code = (params.get("code") or [""])[0]
                row = codes.get(code)
                if not row:
                    return self._json(400, {"error": "invalid_grant"})
                if (params.get("redirect_uri") or [""])[0] != row["redirect"]:
                    return self._json(400, {"error": "invalid_grant"})
                verifier = (params.get("code_verifier") or [""])[0]
                got = b64url_encode(hashlib.sha256(verifier.encode()).digest())
                if got != row["challenge"]:
                    return self._json(400, {"error": "invalid_grant", "error_description": "pkce"})
                del codes[code]
                return self._json(200, token_for(row, proof))
            return self._json(404, {"error": "not_found"})

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

    server = _Provider(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stub["url"] = f"http://127.0.0.1:{server.server_address[1]}"
    stub["close"] = server.shutdown
    return stub


def _config(stub, **over):
    doc = {
        "metadataUrl": f"{stub['url']}/.well-known/openid-configuration",
        "clientId": CLIENT,
        "clientSecret": SECRET,
        "tokenEndpointAuthMethod": "client_secret_basic",
        "redirectUri": "http://127.0.0.1/callback",
        "postLogoutRedirectUri": "http://127.0.0.1/",
        "scopes": SCOPES,
        "privateKeyAlg": "RS256",
        "par": "auto",
        "clockToleranceSec": 30,
        "maxIdTokenAgeSec": 600,
        "allowInsecure": True,
    }
    doc.update(over)
    return doc


def _manual(url):
    import http.client
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    conn.request("GET", path)
    response = conn.getresponse()
    location = response.getheader("location")
    response.read()
    conn.close()
    return response.status, location


def _query(location):
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query, keep_blank_values=True).items()}


def _sign_in(rp, **options):
    request = rp.authorize(**options)
    status, location = _manual(request["url"])
    assert location, f"the provider did not redirect ({status})"
    query = _query(location)
    login = rp.complete(query, request)
    return {"request": request, "query": query, "login": login}


@pytest.fixture(scope="module")
def stub():
    running = _start_provider()
    yield running
    running["close"]()


def test_default_scopes_and_at_hash():
    digest = hashlib.sha256(b"abc").digest()
    assert DEFAULT_SCOPES == SCOPES
    assert hash_claim("abc", "RS256") == b64url_encode(digest[: len(digest) // 2])


def test_signs_in_with_pkce(stub):
    rp = RelyingParty.create(_config(stub))
    signed = _sign_in(rp)
    login = signed["login"]
    request = signed["request"]
    assert login["subject"] == "user-1"
    assert login["email"] == "user-1@example.com"
    assert login["sid"] == "sid-1"
    assert login["issuer"] == stub["url"]
    assert login["preferred_username"] == "user-1"
    assert login.get("refresh_token")
    assert "code_challenge=" in request["url"]
    assert "code_challenge_method=S256" in request["url"]
    assert "client_secret" not in request["url"]
    info = rp.userinfo(login["access_token"], login["subject"])
    assert info["sub"] == "user-1"
    end = rp.end_session_url(id_token=login["id_token"], state="bye")
    assert "/end-session" in end
    assert "id_token_hint=" in end
    assert "client_id=" in end


def test_refuses_a_callback_that_is_not_this_sign_in(stub):
    rp = RelyingParty.create(_config(stub))
    request = rp.authorize()
    _status, location = _manual(request["url"])
    query = _query(location)
    with pytest.raises(OidcError, match="state"):
        rp.complete(query, {**request, "state": "nope"})
    with pytest.raises(OidcError, match="nonce"):
        rp.complete(query, {**request, "nonce": "nope"})
    query["iss"] = "https://elsewhere.example"
    with pytest.raises(OidcError, match="iss mismatch"):
        rp.complete(query, request)
    query["iss"] = stub["url"]
    query["access_token"] = "should-not-be-here"
    with pytest.raises(OidcError, match="access_token"):
        rp.complete(query, request)


def test_accepts_a_code_once(stub):
    rp = RelyingParty.create(_config(stub))
    signed = _sign_in(rp)
    assert signed["login"]["subject"] == "user-1"
    with pytest.raises(OidcError, match="already used"):
        rp.complete(signed["query"], signed["request"])


def test_refuses_bad_tokens(stub):
    rp = RelyingParty.create(_config(stub))
    wrong = RelyingParty.create(_config(stub, clientSecret="nope"))
    request = wrong.authorize()
    _status, location = _manual(request["url"])
    query = _query(location)
    with pytest.raises(OidcError) as caught:
        wrong.complete(query, request)
    assert caught.value.oauth_error == "invalid_client"

    stub["corrupt"] = True
    with pytest.raises(OidcError, match="signature"):
        _sign_in(rp)
    stub["aud"] = "other-client"
    with pytest.raises(OidcError, match="audience|aud"):
        _sign_in(rp)
    stub["exp"] = int(time.time()) - 3600
    with pytest.raises(OidcError, match="exp|timestamp|old|iat"):
        _sign_in(rp)
    stub["bad_at_hash"] = True
    with pytest.raises(OidcError, match="at_hash"):
        _sign_in(rp)


def test_refresh_and_client_credentials(stub):
    rp = RelyingParty.create(_config(stub))
    login = _sign_in(rp)["login"]
    refreshed = rp.refresh(login["refresh_token"], previous=login)
    assert refreshed["subject"] == login["subject"]
    assert refreshed["access_token"] != login["access_token"]
    own = rp.client_credentials("ssf.manage")
    assert own["access_token"] == "cc-token"
    again = rp.client_credentials("ssf.manage")
    assert again["access_token"] == "cc-token"


def test_par(stub):
    stub["par"] = True
    try:
        rp = RelyingParty.create(_config(stub))
        signed = _sign_in(rp)
        assert "request_uri=" in signed["request"]["url"]
        assert "code_challenge=" not in signed["request"]["url"]
        assert signed["login"]["subject"] == "user-1"
    finally:
        stub["par"] = False


def test_post_and_private_key_jwt(stub):
    posted = RelyingParty.create(_config(stub, tokenEndpointAuthMethod="client_secret_post"))
    assert _sign_in(posted)["login"]["subject"] == "user-1"
    jwt_rp = RelyingParty.create(_config(
        stub,
        tokenEndpointAuthMethod="private_key_jwt",
        clientSecret=None,
        privateKeyPem=_CLIENT_PEM,
    ))
    assert _sign_in(jwt_rp)["login"]["subject"] == "user-1"


def test_reads_configuration_file_names():
    with tempfile.TemporaryDirectory(prefix="oidc-config-") as directory:
        secret_path = os.path.join(directory, "secret")
        with open(secret_path, "w", encoding="utf-8") as handle:
            handle.write("from-file\n")
        os.environ["OIDC_TEST_SECRET"] = "from-env"
        try:
            file = {
                "metadataUrl": "https://localhost:8081/.well-known/openid-configuration",
                "client_id": CLIENT,
                "clientSecret": "env:OIDC_TEST_SECRET",
                "redirectUri": "http://localhost:3000/callback",
                "scopes": SCOPES.split(" "),
            }
            env = resolve_config(file, directory)
            assert env["clientId"] == CLIENT
            assert env["clientSecret"] == "from-env"
            assert env["issuer"] == "https://localhost:8081"
            assert env["scopes"] == SCOPES
            assert env["tokenEndpointAuthMethod"] == "client_secret_basic"
            from_file = resolve_config({**file, "clientSecret": "file:secret"}, directory)
            assert from_file["clientSecret"] == "from-file"
            chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n"
            with open(os.path.join(directory, "ca.pem"), "w", encoding="utf-8") as handle:
                handle.write(chain)
            assert resolve_config({**file, "tlsCa": "ca.pem"}, directory)["tlsCa"] == chain
            assert resolve_config({**file, "tlsCa": "file:ca.pem"}, directory)["tlsCa"] == chain
            assert resolve_config({**file, "tlsCa": chain}, directory)["tlsCa"] == chain.strip()
            os.environ["OIDC_TEST_CA"] = chain
            assert resolve_config({**file, "tlsCa": "env:OIDC_TEST_CA"}, directory)["tlsCa"] == chain
            del os.environ["OIDC_TEST_CA"]
            assert resolve_config({**file, "tlsCa": "env:OIDC_TEST_CA"}, directory).get("tlsCa") is None
            assert resolve_config({**file, "tlsCa": "missing.pem"}, directory).get("tlsCa") is None
            with pytest.raises(OidcError, match="public client"):
                resolve_config({**file, "tokenEndpointAuthMethod": "none"}, directory)
            with pytest.raises(OidcError, match="openid"):
                resolve_config({**file, "scopes": "profile email"}, directory)
        finally:
            os.environ.pop("OIDC_TEST_SECRET", None)
            os.environ.pop("OIDC_TEST_CA", None)


def test_signals_flag():
    with tempfile.TemporaryDirectory(prefix="oidc-signals-") as directory:
        file = {
            "metadataUrl": "https://localhost:8081/.well-known/openid-configuration",
            "client_id": CLIENT,
            "clientSecret": "secret",
            "redirectUri": "http://localhost:3000/callback",
            "ssf": {"transmitter": "https://localhost:8081/", "pollIntervalMs": 3000},
        }
        omitted = resolve_config(file, directory)
        assert omitted["scopes"] == SCOPES
        assert "signals" not in omitted
        assert omitted["ssf"] == {"transmitter": "https://localhost:8081", "pollIntervalMs": 3000}
        explicit = resolve_config({**file, "signals": True, "scopes": SCOPES}, directory)
        assert explicit["scopes"] == SCOPES
        assert "signals" not in explicit
        assert explicit["ssf"] == omitted["ssf"]

        listed = resolve_config({
            **file,
            "signals": False,
            "scopes": SCOPES,
            "ssf": {"transmitter": "not-a-url"},
        }, directory)
        assert listed["signals"] is False
        assert listed.get("ssf") is None
        assert listed["scopes"] == "openid profile email offline_access"
        assert "ssf.read" not in listed["scopes"].split()
        assert "ssf.manage" not in listed["scopes"].split()

        defaults = resolve_config({**file, "signals": False}, directory)
        assert defaults["signals"] is False
        assert defaults.get("ssf") is None
        assert defaults["scopes"] == "openid profile email offline_access"
        assert "openid" in defaults["scopes"].split()

        with pytest.raises(OidcError, match="openid"):
            resolve_config({**file, "signals": False, "scopes": "ssf.read ssf.manage"}, directory)
        with pytest.raises(OidcError) as caught:
            resolve_config({**file, "signals": "no"}, directory)
        assert caught.value.code == "config"
        assert str(caught.value) == "signals must be true or false"
