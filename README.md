# oidc-caep-risc

A confidential OpenID Connect relying party for a traditional Python application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. The only cryptographic dependency is `cryptography`.

JSON configuration keys are the same names the Node library `oidc-caep-risc-nodejs` reads. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. `develop` and `main` are the same commit. A pull request merged into `main` publishes the package to PyPI after the test workflow succeeds on that commit. A direct push does not. There is no API token: PyPI Trusted Publishing trades the workflow's GitHub OIDC token for a short-lived upload token, from the `pypi` environment, and PyPI holds the publisher for this repository and `publish.yml`. A version already on PyPI stays there; the next release is a new `version` in `pyproject.toml` (and `VERSION`).

## Usage

```python
from oidc_caep_risc import RelyingParty

rp = RelyingParty.from_file("oidc.json")
request = rp.authorize()
# redirect the browser to request["url"]; keep state, nonce, and code_verifier
who = rp.complete(query, request)
```

Tokens stay in this process. Keep the transaction until the browser returns.

## Settings and defaults

The JSON keys are the same in all seven `oidc-caep-risc` libraries. The same defaults and rules apply whether the client is read from a file (`RelyingParty.from_file`, `resolve_config`) or built directly (`RelyingParty.create(dict)`, `RelyingParty(config, metadata)`).

| Key | Default | Meaning |
|---|---|---|
| `par` | `auto` | Pushed authorization requests (RFC 9126). `auto` pushes when the provider has a PAR endpoint, `always` fails at creation without one, `never` does not push. When discovery says `require_pushed_authorization_requests: true`, `never` fails at creation and `auto` always pushes. |
| `dpop` | `auto` | DPoP (RFC 9449). `auto` uses DPoP when the provider advertises ES256 in `dpop_signing_alg_values_supported`; `always` fails at creation when it does not; `never` sends no proofs. |
| `dpopKey` | none | A PEM P-256 private key (or `file:`, `env:`, a path) for an application that runs several processes. Without it the client generates an ES256 key pair when it is created and holds it in memory only. |
| `acrValues` | none | `acr_values` for every authorization request (a string or a list). `authorize(acr_values=...)` overrides it. When either names values, the ID token from the code exchange must carry `acr`, and it must be one of them. The refresh path does not re-check `acr`. |
| `idTokenSigningAlgs` | `["RS256"]` | The ID token algorithm allow-list. Only algorithms the provider also advertises remain, and none left fails at creation. `none` is never accepted. An HMAC algorithm (`HS256`, `HS384`, `HS512`) is accepted only when named here. |
| `idTokenSignedResponseAlg` | none | One pinned algorithm. It replaces the list and must be advertised. |
| `requireIdTokenTypAndAtHash` | `true` | The ID token header must carry `typ` `JWT` or `application/jwt` (case-insensitive), and when the token response carries an access token the ID token must carry a matching `at_hash`. `false` checks both only when present. |
| `clockToleranceSec` | `30` | Skew allowed on `exp`, `nbf` and `iat`. An `iat` more than this in the future is refused. |
| `maxIdTokenAgeSec` | `600` | The oldest `iat` accepted. |

`redirectUri`, `postLogoutRedirectUri`, and a per-request `authorize(redirect_uri=...)` must be `https`, or `http` on a loopback host (`localhost`, `127.0.0.1`, `[::1]`). `allowInsecure` does not relax that rule; it only lets the provider's own endpoints use `http`.

### DPoP

With DPoP on, a proof (`typ` `dpop+jwt`, the public `jwk`, `jti`, `htm`, `htu` without query or fragment, `iat`) goes on every request to the PAR endpoint and the token endpoint (code, refresh and client-credentials grants), and on every resource request made with a DPoP-bound token: `userinfo()`, `resource_request()`, and every call the Shared Signals receiver makes to the transmitter. A resource proof carries `ath`. The authorization request carries `dpop_jkt` (in the PAR body when PAR is used). A 400 `use_dpop_nonce` from the authorization server, or a 401 `WWW-Authenticate: DPoP error="use_dpop_nonce"` from a resource server, is retried once with the nonce the response gave, and the latest nonce per server origin goes on the next proof. When a proof was sent the token response's `token_type` must be `DPoP`; when none was, it must be `Bearer` (both case-insensitive).

```python
rp.userinfo(login["access_token"], login["subject"])                    # DPoP or Bearer, as the token is
answer = rp.resource_request("GET", "https://api.example/x", token["access_token"], token["token_type"])
```

Give `SignalsReceiver` the client with `relying_party=rp` (and `scope`, default `ssf.manage`). It then calls the transmitter with the client-credentials token, a DPoP proof on each call when that token is DPoP-bound, and removes the tokens of each session an event ends from the session token cache. `headers=` (a callable returning the authorization header) still works for a Bearer token from elsewhere.

### Sign-in tokens per session

```python
login = rp.complete(query, request, session_id=sid)   # or rp.remember_session(sid, login)
token = rp.access_token_for(sid)                       # {"access_token", "token_type", "expires_at"}
rp.forget_session(sid)                                 # sign-out
```

`access_token_for` returns the cached access token while it has more than 30 seconds left; otherwise it refreshes with the refresh token (with a DPoP proof when DPoP is in use) and updates the cache. A failed refresh, or an expired token with no refresh token, removes the entry and raises `OidcError`. The default store is `MemorySessionTokenStore`. Pass `session_store=` to `create` or `from_file` with a `SessionTokenStore` (`get`, `set`, `delete`; JSON-serializable entries) to share entries across processes. The entries hold tokens; a shared store must keep them confidential.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

The tests build an in-process stub provider and a stub transmitter. They do not start iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It starts the latest main branch of iya-sts in memory mode with persistence and clustering off, runs the install script in a scratch copy of this checkout (which writes the `tlsCa` chain), then builds this demo image from it, checks the image carries the chain, starts the demo with no CA mount and no refresh, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It binds two high ports, never 3000 or 8081. The nightly workflow runs the unit suite and this script once every 24 hours.

## Layout

| Path | What it is |
|---|---|
| `src/oidc_caep_risc` | The library. `relying_party.py`, `client_auth.py`, `id_token.py`, `pkce.py`, `discovery.py`, `config.py`, `dpop.py`, `session_cache.py`, `ssf/`. |
| `tests` | pytest ports of the Node relying-party and Shared Signals tests. |
| `demo` | `demo/app.py`, a stdlib `http.server` application. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts and creates the test user `oidc-demo-user`. A generated client secret goes to the file `secretFile` names, and a generated password to `demo/generated/oidc-demo-user.password`, each mode 0600; the script prints neither. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library adds every certificate in it to the default trust store.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client secret stays out of the image. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python scripts/trust_chain.py --config demo/oidc.json` refreshes it by hand.

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `authorize` and redirects. `GET /callback` completes the code exchange and keeps the tokens in the library's session token cache under the local session id. `GET /` asks `access_token_for` for that session, which refreshes when the token is nearly expired and ends the local session when it cannot. `POST /logout` signs the local session out and clears its cache entry. `GET /live-status` is JSON: `signedIn`, `subject`, `tokenType` (`DPoP` against an iya-sts that advertises it), the receiver state, and the Shared Signals events this process has accepted. The receiver is given the relying party, so its calls to the transmitter carry DPoP proofs, and a session-revoked event clears the session's tokens.

`scripts/configure_iya_sts.py` registers the client with `id_token_signed_response_alg` `RS256` (`oauthIdTokenSignedResponseAlg`), the library's default allow-list.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
