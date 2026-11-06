# oidc-caep-risc

A confidential OpenID Connect relying party for a traditional Python application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied. The shipped demo omits `signals`, so they stay on.

The license is the MIT License in `LICENSE`. A pull request merged into `main` publishes the package to PyPI after the test workflow succeeds on that commit. A direct push does not. There is no API token: PyPI Trusted Publishing trades the workflow's GitHub OIDC token for a short-lived upload token, from the `pypi` environment, and PyPI holds the publisher for this repository and `publish.yml`. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `develop` and `main` are the same commit.

Python 3.11 or later. The dependency is `cryptography`.

## Layout

| Path | What it is |
|---|---|
| `src/oidc_caep_risc` | The library. Source is `relying_party.py`, `client_auth.py`, `id_token.py`, `pkce.py`, `discovery.py`, `config.py`, `dpop.py`, `session_cache.py`, `ssf/`. |
| `tests` | pytest. A stub provider and a stub transmitter. `test_client_profile.py` covers issue #16 point by point against the stub provider (which verifies DPoP proofs with `check_proof`). `test_trust_chain.py`: the install script writes the whole chain to `tlsCa`'s path, and the library trusts an HTTPS provider through that file. |
| `demo` | `demo/app.py` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client and writes the listener CA trust chain to the file `tlsCa` names. `trust_chain.py` holds `save_trust_chain()` and refreshes that file. Scripts never print a secret: a generated password goes to `demo/generated/<user>.password` and the client secret to `secretFile`'s file, each created 0600; no trace line carries a URL or value derived from a password; secrets reach `docker run` as `-e NAME`; every `ssl.SSLContext` sets `minimum_version = TLSv1_2`. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Usage

```python
from oidc_caep_risc import RelyingParty, OidcError

rp = RelyingParty.from_file("oidc.json")
request = rp.authorize()
who = rp.complete(query, request)
```

Keep the transaction (`state`, nonce, code verifier, and `acr_values` when requested) until the browser returns. Tokens stay in this process.

## Client profile (issue #16)

The same settings and defaults are in all seven `oidc-caep-risc` libraries; README's *Settings and defaults* is the table. Keep the JSON key names identical to the siblings.

- `config.apply_defaults()` holds every default and the redirect-URI rule. `resolve_config`, `RelyingParty.create` and `RelyingParty.__init__` all call it, so a client built directly gets what a file gets. Do not add a default anywhere else.
- Redirect URIs: https, or http on `localhost`, `127.0.0.1`, `[::1]`. `allowInsecure` relaxes only the provider's endpoints, never a redirect URI. `authorize(redirect_uri=...)` is held to the same rule.
- `par` and `dpop` are `auto`/`always`/`never`. Both are decided in `__init__` (`_par_decision`, `_dpop_key`), so a misconfiguration fails at creation. `discovery.py` keeps `require_pushed_authorization_requests` and `dpop_signing_alg_values_supported`.
- DPoP lives in `dpop.py` (`DPoPKey`: the ES256 key, proofs, the RFC 7638 thumbprint for `dpop_jkt`, the latest `DPoP-Nonce` per origin). `_form` (PAR and token) and `resource_request` (UserInfo, the SSF transmitter) send proofs and retry a nonce challenge once. `_token` refuses a `token_type` that does not match whether a proof was sent. `backchannel.send()` returns response headers for this.
- The SSF receiver takes `relying_party=`; with it every transmitter call goes through `rp.resource_request` with the client-credentials token, and an ended session is also removed from `rp.sessions`.
- ID tokens: `idTokenSigningAlgs` default `["RS256"]`, intersected with the advertised list; `none` never; HMAC only when named. `requireIdTokenTypAndAtHash` (default true) makes `typ` and `at_hash` required (UserInfo JWTs are not held to `typ`). `iat` beyond `clockToleranceSec` in the future is refused.
- `acr`: requested values travel in the transaction; `complete()` requires a matching `acr`. `refresh()` does not check it.
- `session_cache.py`: `SessionTokenStore` (get/set/delete) and the default `MemorySessionTokenStore`. `complete(session_id=)`, `remember_session`, `access_token_for` (30 s floor, refresh on demand, entry removed on failure), `forget_session`.
- The demo keeps its tokens only in that cache and gives the receiver the relying party. `scripts/configure_iya_sts.py` registers `oauthIdTokenSignedResponseAlg: RS256`.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `pip install --no-cache-dir ".[dev]" && pytest` in `python:3.11-slim`. GitHub Actions uses that command on every push. Do not run pytest on the host. The demo image does not run the suite.

`python3 scripts/live_iya_sts.py` starts iya-sts from the latest main branch in memory mode, runs the install script in a scratch copy of this checkout (it writes the `tlsCa` chain), then builds the demo image (which carries the chain), starts it with `TLS_CA_REFRESH=0` and no CA mount, signs in, and checks two Shared Signals events on `GET /live-status`. The nightly workflow runs both halves. It does not bind port 3000 or 8081.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library adds every certificate in it to the default trust store.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client secret stays out of the image. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing `demo/generated` and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python scripts/trust_chain.py --config demo/oidc.json` refreshes it by hand.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. `GET /live-status` reports the sign-in and the Shared Signals events this process has accepted.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 while another demo is already using it.
