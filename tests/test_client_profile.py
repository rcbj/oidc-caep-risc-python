# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Issue 16: DPoP, acr, PAR required, the ID token algorithm allow-list, typ and at_hash,
the same defaults on every way of creating a client, and the per-session token cache."""

import json
import os
import tempfile
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from oidc_caep_risc import (
    DEFAULT_ID_TOKEN_SIGNING_ALGS,
    MemorySessionTokenStore,
    OidcError,
    RelyingParty,
    SessionTokenStore,
    resolve_config,
    validate_id_token,
)
from oidc_caep_risc.discovery import discover_provider, id_token_algorithms
from oidc_caep_risc.dpop import DPoPKey, htu_of
from oidc_caep_risc.keys import sign_jws
from oidc_caep_risc.b64 import b64url_encode

from test_rp import CLIENT, SECRET, _manual, _query, _sign_in, _start_provider

_DEFAULTS = {
    "par": False,
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
}


@pytest.fixture(scope="module")
def provider():
    running = _start_provider()
    yield running
    running["close"]()


@pytest.fixture()
def stub(provider):
    provider.update(_DEFAULTS)
    provider["seen"] = []
    provider.pop("pushed", None)
    provider.pop("authorize_params", None)
    yield provider
    provider.update(_DEFAULTS)


def _minimal(stub, **over):
    """A configuration naming only what has no default."""
    doc = {
        "metadataUrl": f"{stub['url']}/.well-known/openid-configuration",
        "clientId": CLIENT,
        "clientSecret": SECRET,
        "tokenEndpointAuthMethod": "client_secret_basic",
        "redirectUri": "http://127.0.0.1/callback",
        "scopes": "openid profile email offline_access",
        "allowInsecure": True,
    }
    doc.update(over)
    return doc


def _proofs(stub, path):
    return [row["proof"] for row in stub["seen"] if row["path"] == path]


def _ec_pem(curve=None):
    key = ec.generate_private_key(curve or ec.SECP256R1())
    return key, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")


# 1. DPoP


def test_dpop_auto_binds_every_token_and_resource_request(stub):
    stub["dpop_algs"] = ["ES256", "PS256"]
    rp = RelyingParty.create(_minimal(stub))
    assert rp.config["dpop"] == "auto"
    assert rp.dpop is not None
    signed = _sign_in(rp)
    login = signed["login"]
    assert login["token_type"] == "DPoP"
    assert signed["query"]["code"]
    assert stub["authorize_params"]["dpop_jkt"] == [rp.dpop.thumbprint]
    token_proofs = _proofs(stub, "/token")
    assert len(token_proofs) == 1 and token_proofs[0] is not None
    assert token_proofs[0]["jkt"] == rp.dpop.thumbprint
    assert "ath" not in token_proofs[0]["payload"]

    info = rp.userinfo(login["access_token"], login["subject"])
    assert info["sub"] == "user-1"
    resource = _proofs(stub, "/userinfo")[-1]
    assert resource["payload"]["htm"] == "GET"
    assert "ath" in resource["payload"]

    refreshed = rp.refresh(login["refresh_token"], previous=login)
    assert refreshed["token_type"] == "DPoP"
    assert len(_proofs(stub, "/token")) == 2

    credentials = rp.client_credentials("ssf.manage")
    assert credentials["token_type"] == "DPoP"
    assert len(_proofs(stub, "/token")) == 3
    assert all(proof["jkt"] == rp.dpop.thumbprint for proof in _proofs(stub, "/token"))


def test_dpop_jkt_goes_in_the_pushed_request(stub):
    stub["dpop_algs"] = ["ES256"]
    stub["par"] = True
    rp = RelyingParty.create(_minimal(stub))
    signed = _sign_in(rp)
    assert "request_uri=" in signed["request"]["url"]
    assert "dpop_jkt" not in signed["request"]["url"]
    assert stub["pushed"]["dpop_jkt"] == [rp.dpop.thumbprint]
    par_proof = _proofs(stub, "/par")[0]
    assert par_proof["payload"]["htu"] == f"{stub['url']}/par"
    assert signed["login"]["token_type"] == "DPoP"


def test_dpop_auto_is_skipped_without_es256(stub):
    rp = RelyingParty.create(_minimal(stub))
    assert rp.dpop is None
    login = _sign_in(rp)["login"]
    assert login["token_type"] == "Bearer"
    assert _proofs(stub, "/token") == [None]
    assert "dpop_jkt" not in stub["authorize_params"]
    stub["dpop_algs"] = ["PS256"]
    assert RelyingParty.create(_minimal(stub)).dpop is None


def test_dpop_always_fails_at_creation_without_es256(stub):
    with pytest.raises(OidcError, match="dpop_signing_alg_values_supported"):
        RelyingParty.create(_minimal(stub, dpop="always"))
    stub["dpop_algs"] = ["PS256"]
    with pytest.raises(OidcError, match="ES256"):
        RelyingParty.create(_minimal(stub, dpop="always"))
    stub["dpop_algs"] = ["ES256"]
    assert RelyingParty.create(_minimal(stub, dpop="always")).dpop is not None
    with pytest.raises(OidcError, match="dpop must be"):
        RelyingParty.create(_minimal(stub, dpop="sometimes"))


def test_dpop_never_sends_no_proof(stub):
    stub["dpop_algs"] = ["ES256"]
    rp = RelyingParty.create(_minimal(stub, dpop="never"))
    assert rp.dpop is None
    assert _sign_in(rp)["login"]["token_type"] == "Bearer"
    assert _proofs(stub, "/token") == [None]


def test_dpop_key_from_pem(stub):
    stub["dpop_algs"] = ["ES256"]
    key, pem = _ec_pem()
    rp = RelyingParty.create(_minimal(stub, dpopKey=pem))
    assert rp.dpop.thumbprint == DPoPKey(key).thumbprint
    _sign_in(rp)
    assert _proofs(stub, "/token")[0]["jkt"] == rp.dpop.thumbprint
    with tempfile.TemporaryDirectory(prefix="oidc-dpop-") as directory:
        with open(os.path.join(directory, "dpop.pem"), "w", encoding="utf-8") as handle:
            handle.write(pem)
        resolved = resolve_config(_minimal(stub, dpopKey="dpop.pem"), directory)
        assert RelyingParty.create(resolved).dpop.thumbprint == rp.dpop.thumbprint
    _other, p384 = _ec_pem(ec.SECP384R1())
    with pytest.raises(OidcError, match="P-256"):
        RelyingParty.create(_minimal(stub, dpopKey=p384))
    with pytest.raises(OidcError, match="dpopKey"):
        RelyingParty.create(_minimal(stub, dpopKey="dpop.pem"))
    # Two clients without dpopKey hold different in-memory keys.
    assert RelyingParty.create(_minimal(stub)).dpop.thumbprint != RelyingParty.create(_minimal(stub)).dpop.thumbprint


def test_dpop_nonce_from_the_authorization_server(stub):
    stub["dpop_algs"] = ["ES256"]
    stub["par"] = True
    stub["dpop_nonce"] = "as-nonce-1"
    rp = RelyingParty.create(_minimal(stub))
    login = _sign_in(rp)["login"]
    assert login["token_type"] == "DPoP"
    par = _proofs(stub, "/par")
    assert [proof["payload"].get("nonce") for proof in par] == [None, "as-nonce-1"]
    # The nonce is per origin: the token endpoint shares the origin, so its first proof carries it.
    token = _proofs(stub, "/token")
    assert [proof["payload"].get("nonce") for proof in token] == ["as-nonce-1"]
    stub["dpop_nonce"] = "as-nonce-2"
    rp.refresh(login["refresh_token"], previous=login)
    token = _proofs(stub, "/token")
    assert [proof["payload"].get("nonce") for proof in token[1:]] == ["as-nonce-1", "as-nonce-2"]
    assert len({proof["payload"]["jti"] for proof in token}) == len(token)


def test_dpop_nonce_retried_once_only(stub):
    stub["dpop_algs"] = ["ES256"]
    rp = RelyingParty.create(_minimal(stub))
    stub["dpop_nonce"] = "fixed"
    request = rp.authorize()
    _status, location = _manual(request["url"])
    # Every proof carries a stale nonce from now on: the server keeps asking.
    original = rp.dpop.proof

    def stale(method, url, access_token=None, nonce=None):
        return original(method, url, access_token=access_token, nonce="stale")

    rp.dpop.proof = stale
    with pytest.raises(OidcError) as caught:
        rp.complete(_query(location), request)
    assert caught.value.oauth_error == "use_dpop_nonce"
    assert len(_proofs(stub, "/token")) == 2


def test_dpop_nonce_from_a_resource_server(stub):
    stub["dpop_algs"] = ["ES256"]
    rp = RelyingParty.create(_minimal(stub))
    login = _sign_in(rp)["login"]
    stub["rs_nonce"] = "rs-nonce-1"
    assert rp.userinfo(login["access_token"], login["subject"])["sub"] == "user-1"
    calls = _proofs(stub, "/userinfo")
    assert [proof["payload"].get("nonce") for proof in calls] == [None, "rs-nonce-1"]
    rp.userinfo(login["access_token"], login["subject"])
    assert _proofs(stub, "/userinfo")[-1]["payload"]["nonce"] == "rs-nonce-1"
    assert len(_proofs(stub, "/userinfo")) == 3


def test_token_type_must_match_the_proof(stub):
    stub["dpop_algs"] = ["ES256"]
    rp = RelyingParty.create(_minimal(stub))
    stub["token_type"] = "Bearer"
    with pytest.raises(OidcError, match="not DPoP"):
        _sign_in(rp)
    stub["token_type"] = "dpop"
    assert _sign_in(rp)["login"]["token_type"] == "dpop"
    plain = RelyingParty.create(_minimal(stub, dpop="never"))
    stub["token_type"] = "DPoP"
    with pytest.raises(OidcError, match="not Bearer"):
        _sign_in(plain)
    stub["token_type"] = "bEaReR"
    assert _sign_in(plain)["login"]["token_type"] == "bEaReR"


def test_proof_shape():
    key = DPoPKey()
    proof = key.proof("post", "https://op.example/token?x=1#frag")
    head, payload = (json.loads(_unb64(part)) for part in proof.split(".")[:2])
    assert head["typ"] == "dpop+jwt"
    assert head["alg"] == "ES256"
    assert set(head["jwk"]) == {"kty", "crv", "x", "y"}
    assert payload["htm"] == "POST"
    assert payload["htu"] == "https://op.example/token"
    assert htu_of("https://op.example:8443/a/b?c#d") == "https://op.example:8443/a/b"
    assert set(payload) == {"jti", "htm", "htu", "iat"}
    with_token = json.loads(_unb64(key.proof("GET", "https://rs.example/x", access_token="tok").split(".")[1]))
    import hashlib
    assert with_token["ath"] == b64url_encode(hashlib.sha256(b"tok").digest())


def _unb64(part):
    import base64
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


# 2. acr


def test_acr_is_enforced(stub):
    rp = RelyingParty.create(_minimal(stub, acrValues="urn:acr:mfa urn:acr:hwk"))
    stub["acr"] = "urn:acr:hwk"
    signed = _sign_in(rp)
    assert signed["request"]["acr_values"] == "urn:acr:mfa urn:acr:hwk"
    assert stub["authorize_params"]["acr_values"] == ["urn:acr:mfa urn:acr:hwk"]
    stub["acr"] = None
    with pytest.raises(OidcError, match="no acr"):
        _sign_in(rp)
    stub["acr"] = "urn:acr:pwd"
    with pytest.raises(OidcError, match="not one of the requested"):
        _sign_in(rp)
    plain = RelyingParty.create(_minimal(stub))
    assert _sign_in(plain)["login"]["subject"] == "user-1"
    with pytest.raises(OidcError, match="not one of the requested"):
        _sign_in(plain, acr_values=["urn:acr:mfa"])
    stub["acr"] = "urn:acr:mfa"
    login = _sign_in(plain, acr_values=["urn:acr:mfa"])["login"]
    # The refresh path does not re-check acr.
    stub["acr"] = None
    assert plain.refresh(login["refresh_token"], previous=login)["subject"] == "user-1"


# 3. PAR required by the provider


def test_par_required_by_the_provider(stub):
    stub["par"] = True
    stub["require_par"] = True
    metadata = discover_provider(f"{stub['url']}/.well-known/openid-configuration")
    assert metadata["require_pushed_authorization_requests"] is True
    with pytest.raises(OidcError, match="requires pushed"):
        RelyingParty.create(_minimal(stub, par="never"))
    rp = RelyingParty.create(_minimal(stub))
    assert "request_uri=" in _sign_in(rp)["request"]["url"]
    stub["par"] = False
    with pytest.raises(OidcError, match="no pushed authorization endpoint"):
        RelyingParty.create(_minimal(stub))
    stub["require_par"] = False
    with pytest.raises(OidcError, match="par is always"):
        RelyingParty.create(_minimal(stub, par="always"))


# 4. ID token algorithms


def test_rs256_only_by_default(stub):
    assert DEFAULT_ID_TOKEN_SIGNING_ALGS == ("RS256",)
    stub["id_token_algs"] = ["ES256", "RS256", "HS256"]
    rp = RelyingParty.create(_minimal(stub))
    assert rp.config["idTokenSigningAlgs"] == ["RS256"]
    assert rp._algorithms == ["RS256"]
    stub["id_token_algs"] = ["ES256", "PS256"]
    with pytest.raises(OidcError, match="none of the allowed"):
        RelyingParty.create(_minimal(stub))
    widened = RelyingParty.create(_minimal(stub, idTokenSigningAlgs=["PS256", "RS256", "ES384"]))
    assert widened._algorithms == ["PS256"]
    stub["id_token_algs"] = ["RS256", "PS256"]
    pinned = RelyingParty.create(_minimal(stub, idTokenSignedResponseAlg="PS256"))
    assert pinned._algorithms == ["PS256"]
    with pytest.raises(OidcError, match="does not advertise"):
        RelyingParty.create(_minimal(stub, idTokenSignedResponseAlg="ES256"))
    for bad in (["none"], ["RS256", "None"]):
        with pytest.raises(OidcError, match="none"):
            RelyingParty.create(_minimal(stub, idTokenSigningAlgs=bad))
    with pytest.raises(OidcError, match="none"):
        RelyingParty.create(_minimal(stub, idTokenSignedResponseAlg="none"))
    with pytest.raises(OidcError, match="idTokenSigningAlgs"):
        RelyingParty.create(_minimal(stub, idTokenSigningAlgs="RS256"))


def test_symmetric_only_when_named():
    assert id_token_algorithms(["HS256", "RS256"]) == ["RS256"]
    assert id_token_algorithms(["HS256", "RS256"], allowed=["HS256"]) == ["HS256"]
    with pytest.raises(OidcError):
        id_token_algorithms(["HS256"])
    now = int(time.time())
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url_encode(json.dumps({"iss": "https://op", "aud": CLIENT, "sub": "u", "exp": now + 60, "iat": now}).encode())
    token = f"{header}.{body}.{b64url_encode(sign_jws(SECRET.encode(), 'HS256', f'{header}.{body}'.encode()))}"
    checks = {"issuer": "https://op", "clientId": CLIENT, "clientSecret": SECRET, "requireTyp": True}
    with pytest.raises(OidcError, match="HS256"):
        validate_id_token(token, {**checks, "algorithms": ["RS256"]})
    assert validate_id_token(token, {**checks, "algorithms": ["HS256"]})["sub"] == "u"


# 5. typ and at_hash


def test_typ_is_required(stub):
    rp = RelyingParty.create(_minimal(stub))
    stub["typ"] = None
    with pytest.raises(OidcError, match="no typ"):
        _sign_in(rp)
    stub["typ"] = "at+jwt"
    with pytest.raises(OidcError, match="typ"):
        _sign_in(rp)
    stub["typ"] = "Application/JWT"
    assert _sign_in(rp)["login"]["subject"] == "user-1"
    relaxed = RelyingParty.create(_minimal(stub, requireIdTokenTypAndAtHash=False))
    stub["typ"] = None
    assert _sign_in(relaxed)["login"]["subject"] == "user-1"
    stub["typ"] = "logout+jwt"
    with pytest.raises(OidcError, match="typ"):
        _sign_in(relaxed)


def test_at_hash_is_required(stub):
    rp = RelyingParty.create(_minimal(stub))
    stub["omit_at_hash"] = True
    with pytest.raises(OidcError, match="no at_hash"):
        _sign_in(rp)
    relaxed = RelyingParty.create(_minimal(stub, requireIdTokenTypAndAtHash=False))
    assert _sign_in(relaxed)["login"]["subject"] == "user-1"
    stub["omit_at_hash"] = False
    stub["bad_at_hash"] = True
    with pytest.raises(OidcError, match="at_hash"):
        _sign_in(relaxed)
    with pytest.raises(OidcError, match="requireIdTokenTypAndAtHash"):
        RelyingParty.create(_minimal(stub, requireIdTokenTypAndAtHash="no"))


# 6. The same checks on every way of creating a client


def test_defaults_when_created_directly(stub):
    rp = RelyingParty.create(_minimal(stub))
    for key, value in (
        ("par", "auto"),
        ("dpop", "auto"),
        ("clockToleranceSec", 30),
        ("maxIdTokenAgeSec", 600),
        ("idTokenSigningAlgs", ["RS256"]),
        ("requireIdTokenTypAndAtHash", True),
    ):
        assert rp.config[key] == value, key
    with tempfile.TemporaryDirectory(prefix="oidc-defaults-") as directory:
        resolved = resolve_config(_minimal(stub), directory)
    for key in ("par", "dpop", "clockToleranceSec", "maxIdTokenAgeSec", "idTokenSigningAlgs", "requireIdTokenTypAndAtHash"):
        assert resolved[key] == rp.config[key], key
    metadata = discover_provider(f"{stub['url']}/.well-known/openid-configuration")
    built = RelyingParty(_minimal(stub), metadata)
    assert built.config["maxIdTokenAgeSec"] == 600
    assert built._algorithms == ["RS256"]
    stub["par"] = True
    assert "request_uri=" in RelyingParty.create(_minimal(stub)).authorize()["url"]


def test_redirect_uri_rule_everywhere(stub):
    good = (
        "https://app.example/cb",
        "http://localhost/cb",
        "http://localhost:3000/cb",
        "http://127.0.0.1:8080/cb",
        "http://[::1]:3000/cb",
    )
    bad = ("http://app.example/cb", "http://10.0.0.1/cb", "ftp://localhost/cb", "not a url", "http://localhost.evil.example/cb")
    metadata = discover_provider(f"{stub['url']}/.well-known/openid-configuration")
    for uri in good:
        assert RelyingParty.create(_minimal(stub, redirectUri=uri)).config["redirectUri"] == uri
    with tempfile.TemporaryDirectory(prefix="oidc-redirect-") as directory:
        for uri in bad:
            with pytest.raises(OidcError, match="redirectUri"):
                RelyingParty.create(_minimal(stub, redirectUri=uri))
            with pytest.raises(OidcError, match="redirectUri"):
                resolve_config(_minimal(stub, redirectUri=uri), directory)
            with pytest.raises(OidcError, match="redirectUri"):
                RelyingParty(_minimal(stub, redirectUri=uri), metadata)
        with pytest.raises(OidcError, match="postLogoutRedirectUri"):
            resolve_config(_minimal(stub, postLogoutRedirectUri="http://app.example/"), directory)
    rp = RelyingParty.create(_minimal(stub))
    assert rp.authorize(redirect_uri="http://localhost:4000/cb")["redirect_uri"] == "http://localhost:4000/cb"
    for uri in bad:
        with pytest.raises(OidcError, match="redirect_uri"):
            rp.authorize(redirect_uri=uri)


def test_iat_in_the_future_is_refused(stub):
    rp = RelyingParty.create(_minimal(stub))
    stub["iat_offset"] = 120
    with pytest.raises(OidcError, match="iat is in the future"):
        _sign_in(rp)
    stub["iat_offset"] = 10
    assert _sign_in(rp)["login"]["subject"] == "user-1"


# 7. The per-session token cache


def test_session_cache_serves_and_refreshes(stub):
    stub["dpop_algs"] = ["ES256"]
    rp = RelyingParty.create(_minimal(stub))
    request = rp.authorize()
    _status, location = _manual(request["url"])
    login = rp.complete(_query(location), request, session_id="browser-1")
    cached = rp.access_token_for("browser-1")
    assert cached["access_token"] == login["access_token"]
    assert cached["token_type"] == "DPoP"
    assert len(_proofs(stub, "/token")) == 1

    # 20 seconds left is not enough: the next call refreshes, with a DPoP proof.
    stub["expires_in"] = 20
    second = _sign_in(rp)["login"]
    rp.remember_session("browser-2", second)
    stub["expires_in"] = 300
    fresh = rp.access_token_for("browser-2")
    assert fresh["access_token"] != second["access_token"]
    assert fresh["token_type"] == "DPoP"
    assert _proofs(stub, "/token")[-1] is not None
    assert rp.session("browser-2")["access_token"] == fresh["access_token"]
    assert rp.access_token_for("browser-2")["access_token"] == fresh["access_token"]

    stub["expires_in"] = 5
    third = _sign_in(rp)["login"]
    rp.remember_session("browser-3", third)
    stub["refresh_fails"] = True
    with pytest.raises(OidcError, match="refreshed") as caught:
        rp.access_token_for("browser-3")
    assert caught.value.oauth_error == "invalid_grant"
    assert rp.session("browser-3") is None
    with pytest.raises(OidcError, match="no signed-in session"):
        rp.access_token_for("browser-3")

    rp.forget_session("browser-1")
    assert rp.session("browser-1") is None
    with pytest.raises(OidcError):
        rp.access_token_for("browser-1")


def test_session_store_can_be_replaced(stub):
    class Shared(SessionTokenStore):
        def __init__(self):
            self.rows = {}

        def get(self, session_id):
            raw = self.rows.get(session_id)
            return json.loads(raw) if raw else None

        def set(self, session_id, entry):
            self.rows[session_id] = json.dumps(entry)

        def delete(self, session_id):
            self.rows.pop(session_id, None)

    store = Shared()
    rp = RelyingParty.create(_minimal(stub), session_store=store)
    other = RelyingParty.create(_minimal(stub), session_store=store)
    request = rp.authorize()
    _status, location = _manual(request["url"])
    login = rp.complete(_query(location), request, session_id="s")
    assert "s" in store.rows
    assert other.access_token_for("s")["access_token"] == login["access_token"]
    other.forget_session("s")
    assert store.rows == {}
    assert isinstance(RelyingParty.create(_minimal(stub)).sessions, MemorySessionTokenStore)


def test_a_session_without_a_refresh_token_is_removed_when_it_expires(stub):
    rp = RelyingParty.create(_minimal(stub))
    login = _sign_in(rp)["login"]
    login.pop("refresh_token")
    login["expires_at"] = time.time() + 10
    rp.remember_session("x", login)
    with pytest.raises(OidcError, match="no refresh token"):
        rp.access_token_for("x")
    assert rp.session("x") is None
