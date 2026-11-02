# oidc-caep-risc

A confidential OpenID Connect relying party for a traditional Python application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied. The shipped demo omits `signals`, so they stay on.

The license is the MIT License in `LICENSE`. Publishing to PyPI is not set up yet. `develop` and `main` are the same commit.

Python 3.11 or later. The dependency is `cryptography`.

## Layout

| Path | What it is |
|---|---|
| `src/oidc_caep_risc` | The library. Source is `relying_party.py`, `client_auth.py`, `id_token.py`, `pkce.py`, `discovery.py`, `ssf/`. |
| `tests` | pytest. A stub provider and a stub transmitter. |
| `demo` | `demo/app.py` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client. `trust_chain.py` refreshes the listener CA file named by `tlsCa`. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Usage

```python
from oidc_caep_risc import RelyingParty, OidcError

rp = RelyingParty.from_file("oidc.json")
request = rp.authorize()
who = rp.complete(query, request)
```

Keep the transaction (`state`, nonce, code verifier) until the browser returns. Tokens stay in this process.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `pip install --no-cache-dir ".[dev]" && pytest` in `python:3.11-slim`. GitHub Actions uses that command on every push. Do not run pytest on the host. The demo image does not run the suite.

`python3 scripts/live_iya_sts.py` starts iya-sts from the latest main branch in memory mode, registers the demo, signs in, and checks two Shared Signals events on `GET /live-status`. The nightly workflow runs both halves. It does not bind port 3000 or 8081.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. `GET /live-status` reports the sign-in and the Shared Signals events this process has accepted.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 while another demo is already using it.
