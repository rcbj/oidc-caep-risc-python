# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Demo: a server-rendered confidential OpenID Connect client.

GET /healthz, GET /, GET /login, GET /callback, POST /logout.
GET /live-status is JSON: whether this process is signed in, and the Shared
Signals events it has accepted.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from configure_iya_sts import redirects_for  # noqa: E402
from oidc_caep_risc import OidcError, RelyingParty, SignalsReceiver, resolve_config, tracked_from_login  # noqa: E402

HERE = Path(__file__).resolve().parent
STYLES = (HERE / "public" / "styles.css").read_bytes()
APP_JS = (HERE / "public" / "app.js").read_bytes()
SECRET = os.environ["SESSION_SECRET"].encode() if os.environ.get("SESSION_SECRET") else secrets.token_bytes(32)
SESSIONS = {}
PENDING = {}
RECEIVER = {"obj": None, "state": ""}
EVENTS = []


def _mac(value):
    return base64.urlsafe_b64encode(hmac.new(SECRET, value.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()


def _seal(value):
    body = base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    return f"{body}.{_mac(body)}"


def _unseal(token):
    if not token or "." not in token:
        return None
    body, tag = token.split(".", 1)
    if not hmac.compare_digest(_mac(body), tag):
        return None
    pad = "=" * ((4 - len(body) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(body + pad))
    except Exception:
        return None


def _cookies(header):
    out = {}
    for part in (header or "").split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        out[name.strip()] = value.strip()
    return out


def _esc(value):
    return (str(value if value is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def _page(title, body):
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title><link rel="stylesheet" href="/styles.css"></head>
<body><header><a href="/">oidc-caep-risc demo</a></header><main>
{body}
</main><footer>A traditional web application signing in with OpenID Connect through oidc-caep-risc.</footer></body>
</html>
"""


class Demo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    secure_cookies = True
    config_path = str(HERE / "oidc.json")
    rp = None
    rp_error = None

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _cookie(self, name, value, path="/", max_age=None):
        parts = [f"{name}={value}", f"Path={path}", "HttpOnly", "SameSite=Lax"]
        if self.secure_cookies:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "; ".join(parts)

    def _send(self, status, body, content_type="text/html; charset=utf-8", extra=None, cookies=None):
        raw = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(raw)))
        self.send_header("cache-control", "no-store")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("x-frame-options", "DENY")
        self.send_header("content-security-policy", "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for cookie in cookies or []:
            self.send_header("set-cookie", cookie)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, status, location, cookies=None):
        self.send_response(status)
        self.send_header("location", location)
        self.send_header("content-length", "0")
        self.send_header("cache-control", "no-store")
        self.send_header("referrer-policy", "no-referrer")
        for cookie in cookies or []:
            self.send_header("set-cookie", cookie)
        self.end_headers()

    def _rp(self):
        if Demo.rp is not None:
            return Demo.rp
        try:
            Demo.rp = _load_rp()
            _start_receiver(Demo.rp)
            return Demo.rp
        except Exception as err:
            Demo.rp = None
            Demo.rp_error = err
            raise

    def _session(self):
        sid = _cookies(self.headers.get("cookie")).get("oidc_session")
        session = SESSIONS.get(sid)
        if not session:
            return None, None
        if session["expires"] <= __import__("time").time():
            SESSIONS.pop(sid, None)
            return None, None
        return sid, session

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method):
        try:
            path = urlsplit(self.path).path
            if path == "/healthz":
                return self._send(200, "ok", "text/plain")
            if path == "/live-status" and method == "GET":
                return self._live_status()
            if path == "/styles.css":
                return self._send(200, STYLES, "text/css; charset=utf-8")
            if path == "/app.js":
                return self._send(200, APP_JS, "text/javascript; charset=utf-8")
            if path == "/" and method == "GET":
                return self._home()
            if path == "/login" and method == "GET":
                return self._login()
            if path == "/callback" and method == "GET":
                return self._callback()
            if path == "/logout" and method == "POST":
                return self._logout()
            self._send(404, _page("Not found", "<h1>Not found</h1>"))
        except Exception as err:
            traceback.print_exc()
            if not self.wfile.closed:
                try:
                    self._send(500, _page("Error", f"<h1>Something went wrong</h1><p class=\"problem\">{_esc(err)}</p><p><a href=\"/\">Home</a></p>"))
                except Exception:
                    pass

    def _home(self):
        _sid, session = self._session()
        problem = None
        rp = None
        try:
            rp = self._rp()
        except Exception as err:
            problem = f"The relying party is not configured yet: {err}. Run scripts/configure_iya_sts.py."
        if session and rp is not None:
            sid, _session = self._session()
            try:
                # The library's session token cache: the cached access token while it has more
                # than 30 seconds left, otherwise a refreshed one (with a DPoP proof when bound).
                token = rp.access_token_for(sid)
            except OidcError as err:
                _end_many([sid])
                body = f"<h1>Signed out</h1><p class=\"problem\">{_esc(err)}</p><p><a href=\"/\">Sign in again</a></p>"
                return self._send(200, _page("Signed out", body), cookies=[self._cookie("oidc_session", "", max_age=0)])
            login = session["login"]
            who = login.get("preferred_username") or login.get("email") or login.get("subject")
            rows = "".join(
                f"<tr><th>{_esc(name)}</th><td>{_esc(value)}</td></tr>"
                for name, value in (
                    ("Subject", login.get("subject")),
                    ("Issuer", login.get("issuer")),
                    ("Email", login.get("email")),
                    ("Name", login.get("name")),
                    ("Username", login.get("preferred_username")),
                    ("Access token", f"{token.get('token_type')}-bound" if str(token.get("token_type")).lower() == "dpop" else token.get("token_type")),
                ) if value
            )
            body = f"<h1>Signed in as {_esc(who)}</h1><table class=\"facts\">{rows}</table><p><small>The access token and the refresh token stay in this process, in the relying party's session token cache. This page does not show them.</small></p><p><small>Shared Signals: {_esc(RECEIVER['state'])}</small></p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>"
            return self._send(200, _page("Signed in", body))
        issuer = ""
        if rp:
            issuer = f" of {_esc(rp.metadata.get('issuer'))}"
        problem_html = f"<p class=\"problem\">{_esc(problem)}</p>" if problem else ""
        body = f"<h1>Sign in with OpenID Connect</h1>{problem_html}<p>This application is a confidential client{issuer}. It sends the browser to the authorization endpoint (Authorization Code, PKCE S256) and takes the tokens on the back channel.</p><p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with OpenID Connect</a></p>"
        return self._send(200, _page("Sign in", body))

    def _live_status(self):
        try:
            self._rp()
        except Exception as err:
            if not RECEIVER["state"]:
                RECEIVER["state"] = f"not running: {err}"
        _sid, session = self._session()
        login = session["login"] if session else None
        subject = None
        if login:
            subject = login.get("preferred_username") or login.get("email") or login.get("subject")
        cached = Demo.rp.session(_sid) if (session and Demo.rp is not None) else None
        body = {
            "signedIn": bool(session),
            "subject": subject,
            "tokenType": cached.get("token_type") if cached else None,
            "receiver": RECEIVER["state"],
            "events": list(EVENTS),
        }
        return self._send(200, json.dumps(body), "application/json")

    def _login(self):
        rp = self._rp()
        request = rp.authorize()
        txn = {
            key: request[key]
            for key in ("state", "nonce", "code_verifier", "redirect_uri", "acr_values", "max_age", "expected_sub")
            if key in request
        }
        cookie = self._cookie("oidc_txn", _seal(txn), path="/callback", max_age=600)
        self._redirect(302, request["url"], cookies=[cookie])

    def _callback(self):
        rp = self._rp()
        query = {key: values[0] for key, values in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}
        txn = _unseal(_cookies(self.headers.get("cookie")).get("oidc_txn"))
        clear = self._cookie("oidc_txn", "", path="/callback", max_age=0)
        try:
            if not txn:
                raise OidcError("validation", "this callback is not a sign-in this browser started")
            sid = secrets.token_urlsafe(32)
            # The tokens go into the library's session token cache under sid; this page keeps
            # only what it shows.
            login = rp.complete(query, txn, session_id=sid)
            shown = {key: login[key] for key in ("subject", "issuer", "email", "name", "preferred_username") if login.get(key)}
            SESSIONS[sid] = {"login": shown, "expires": __import__("time").time() + 8 * 3600}
            if RECEIVER["obj"] is not None:
                RECEIVER["obj"].track(tracked_from_login(sid, login))
            cookie = self._cookie("oidc_session", sid, max_age=8 * 3600)
            self._redirect(303, "/", cookies=[clear, cookie])
        except Exception as err:
            what = f"{err.code}: {err}" if isinstance(err, OidcError) else str(err)
            self._send(400, _page("Sign-in failed", f"<h1>Sign-in failed</h1><p class=\"problem\">{_esc(what)}</p><p><a href=\"/\">Start again</a></p>"), cookies=[clear])

    def _logout(self):
        sid, _session = self._session()
        if sid:
            SESSIONS.pop(sid, None)
            if Demo.rp is not None:
                Demo.rp.forget_session(sid)
            if RECEIVER["obj"] is not None:
                RECEIVER["obj"].untrack(sid)
        self._redirect(303, "/", cookies=[self._cookie("oidc_session", "", max_age=0)])


def _load_raw():
    path = os.environ.get("OIDC_CONFIG") or str(HERE / "oidc.json")
    with open(path, encoding="utf-8") as handle:
        raw = json.loads(handle.read())
    if os.environ.get("OIDC_METADATA_FILE"):
        raw["metadataFile"] = os.environ["OIDC_METADATA_FILE"]
        raw.pop("metadataUrl", None)
        raw.pop("issuer", None)
    return path, raw


def _apply_redirects(raw):
    port = int(os.environ.get("PORT") or 3000)
    public = os.environ.get("PUBLIC_URL") or ""
    given = bool(os.environ.get("PUBLIC_URL")) or bool(os.environ.get("OIDC_PUBLIC_URL_GIVEN"))
    if getattr(_apply_redirects, "public_url", None):
        public = _apply_redirects.public_url
        given = True
    redirect = str(raw.get("redirectUri") or raw.get("redirect_uri") or "")
    post = str(raw.get("postLogoutRedirectUri") or raw.get("post_logout_redirect_uri") or "")
    moved = redirects_for(redirect, post, public_url=public, public_url_given=given, port=port)
    if raw.get("redirectUri") or not raw.get("redirect_uri"):
        raw["redirectUri"] = moved["redirectUri"]
    else:
        raw["redirect_uri"] = moved["redirectUri"]
    if raw.get("postLogoutRedirectUri") or raw.get("post_logout_redirect_uri") or post:
        if raw.get("post_logout_redirect_uri") and not raw.get("postLogoutRedirectUri"):
            raw["post_logout_redirect_uri"] = moved["postLogoutRedirectUri"]
        else:
            raw["postLogoutRedirectUri"] = moved["postLogoutRedirectUri"]
    return port


def _load_rp():
    path, raw = _load_raw()
    _apply_redirects(raw)
    if raw.get("signals") is False:
        RECEIVER["state"] = "not configured (signals are off)"
    elif not (isinstance(raw.get("ssf"), dict) and raw["ssf"].get("transmitter")):
        RECEIVER["state"] = "not configured (no ssf block in the configuration file)"
    else:
        RECEIVER["state"] = "starting"
    return RelyingParty.create(resolve_config(raw, str(Path(path).resolve().parent)))


def _start_receiver(rp):
    if rp.config.get("signals") is False or not rp.config.get("ssf") or RECEIVER["obj"] is not None:
        if rp.config.get("signals") is False:
            RECEIVER["state"] = "not configured (signals are off)"
        return
    ssf = rp.config["ssf"]
    # relying_party: every call to the transmitter carries the client-credentials token for
    # ssf.manage, with a DPoP proof when that token is DPoP-bound, and an ended session's tokens
    # leave the relying party's session token cache.
    receiver = SignalsReceiver(
        transmitter=ssf["transmitter"],
        tls=rp.tls(),
        relying_party=rp,
        scope="ssf.manage",
        description=f"oidc-caep-risc demo ({rp.config['clientId']})",
        poll_interval_ms=ssf.get("pollIntervalMs") or 5000,
        on_end_sessions=lambda ids, event: _end_many(ids),
    )
    receiver.on("*", _remember_event)
    RECEIVER["obj"] = receiver
    try:
        receiver.start()
        RECEIVER["state"] = f"polling stream {receiver.stream.get('stream_id')} at {ssf['transmitter']}"
    except Exception as err:
        RECEIVER["obj"] = None
        RECEIVER["state"] = f"not running: {err}"
        print(f"ssf: the receiver did not start: {err}", file=sys.stderr)


def _remember_event(event):
    EVENTS.append({"type": event.get("type"), "jti": event.get("jti")})


def _end_many(ids):
    for sid in ids:
        SESSIONS.pop(sid, None)
        if Demo.rp is not None:
            Demo.rp.forget_session(sid)
        if RECEIVER["obj"] is not None:
            RECEIVER["obj"].untrack(sid)


def main(argv=None):
    parser = argparse.ArgumentParser(description="oidc-caep-risc demo")
    parser.add_argument("--public-url", default=None)
    parser.add_argument("--config", default=None)
    args = parser.parse_args(argv)
    if args.config:
        os.environ["OIDC_CONFIG"] = args.config
    if args.public_url:
        _apply_redirects.public_url = args.public_url.rstrip("/")
    port = int(os.environ.get("PORT") or 3000)
    try:
        _path, raw = _load_raw()
        _apply_redirects(raw)
        redirect = urlsplit(str(raw.get("redirectUri") or raw.get("redirect_uri") or "http://localhost/"))
        Demo.secure_cookies = redirect.scheme == "https" or redirect.hostname in ("localhost", "127.0.0.1")
    except Exception as err:
        print(f"cannot read configuration: {err}", file=sys.stderr)
    server = ThreadingHTTPServer(("0.0.0.0", port), Demo)
    print(f"oidc-caep-risc demo on port {port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if RECEIVER["obj"] is not None:
            RECEIVER["obj"].stop()
        server.server_close()


if __name__ == "__main__":
    main()
