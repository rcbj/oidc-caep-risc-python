# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The Shared Signals receiver against a stub transmitter."""

import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from oidc_caep_risc import EVENT, OidcError, SignalsReceiver, subject_of
from oidc_caep_risc.b64 import b64url_encode
from oidc_caep_risc.ssf.jws import verify_compact_jws

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64_uint(number):
    length = max(1, (number.bit_length() + 7) // 8)
    return b64url_encode(number.to_bytes(length, "big"))


def _jwk(key, kid):
    numbers = key.public_key().public_numbers()
    return {"kty": "RSA", "n": _b64_uint(numbers.n), "e": _b64_uint(numbers.e), "kid": kid, "alg": "RS256", "use": "sig"}


_JWK = _jwk(_PRIVATE, "k1")


def _jws(payload, key=_PRIVATE, header=None):
    header = header or {"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url_encode(key.sign(f"{h}.{p}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()))
    return f"{h}.{p}.{sig}"


class _Server(ThreadingHTTPServer):
    daemon_threads = True


def _start_transmitter():
    queue = {}
    acked = []
    errs = {}
    streams = []
    state = {"created": 0, "authorization": "", "base": ""}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _out(self, status, body=None):
            raw = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def _handle(self):
            length = int(self.headers.get("content-length") or 0)
            text = self.rfile.read(length).decode() if length else ""
            state["authorization"] = self.headers.get("authorization") or ""
            path = urlsplit(self.path).path
            if state["authorization"] != "Bearer app-token" and path != "/.well-known/ssf-configuration" and not path.startswith("/jwks"):
                return self._out(401, {"error": "invalid_token"})
            base = state["base"]
            if path == "/.well-known/ssf-configuration":
                return self._out(200, {
                    "issuer": base,
                    "jwks_uri": f"{base}/jwks",
                    "configuration_endpoint": f"{base}/ssf/stream",
                    "verification_endpoint": f"{base}/ssf/verify",
                    "delivery_methods_supported": ["urn:ietf:rfc:8936"],
                })
            if path == "/jwks":
                return self._out(200, {"keys": [_JWK]})
            if path == "/ssf/stream" and self.command == "GET":
                return self._out(200, streams)
            if path == "/ssf/stream" and self.command == "POST":
                body = json.loads(text)
                state["created"] += 1
                created = state["created"]
                stream = {
                    "stream_id": f"s{created}",
                    "iss": base,
                    "aud": "my-app",
                    "delivery": {"method": body["delivery"]["method"], "endpoint_url": f"{base}/ssf/poll/s{created}"},
                    "events_requested": body["events_requested"],
                    "events_delivered": body["events_requested"],
                }
                streams.append(stream)
                return self._out(201, stream)
            if path == "/ssf/verify":
                return self._out(204)
            if path.startswith("/ssf/poll/"):
                body = json.loads(text or "{}")
                for jti in body.get("ack") or []:
                    acked.append(jti)
                    queue.pop(jti, None)
                errs.update(body.get("setErrs") or {})
                for jti in (body.get("setErrs") or {}):
                    queue.pop(jti, None)
                return self._out(200, {"sets": dict(queue), "moreAvailable": False})
            return self._out(404, {"error": "not_found"})

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

    server = _Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["base"] = f"http://127.0.0.1:{server.server_address[1]}"
    return {
        "url": state["base"],
        "queue": queue,
        "acked": acked,
        "errs": errs,
        "state": state,
        "close": server.shutdown,
    }


def _deliver(stub, event_type, sub_id, extra=None, key=None, aud=None, iss=None):
    jti = str(uuid.uuid4())
    payload = {
        "iss": iss or stub["url"],
        "aud": aud or "my-app",
        "jti": jti,
        "iat": int(time.time()),
        "sub_id": sub_id,
        "events": {event_type: {"event_timestamp": 1, **(extra or {})}},
    }
    stub["queue"][jti] = _jws(payload, key or _PRIVATE)
    return jti


def _session(local_id, person, sid):
    return {"local_id": local_id, "person": f"urn:uuid:{person}", "email": f"{person}@example.com", "idp_session": sid}


@pytest.fixture(scope="module")
def stub():
    running = _start_transmitter()
    yield running
    running["close"]()


def test_verifies_a_set_against_the_jwks():
    assert verify_compact_jws(_jws({"a": 1}), [_JWK])["payload"] == {"a": 1}
    with pytest.raises(OidcError, match="does not verify"):
        verify_compact_jws(_jws({"a": 1}, _OTHER), [_JWK])
    with pytest.raises(OidcError, match="kid nope"):
        verify_compact_jws(_jws({"a": 1}, _PRIVATE, {"alg": "RS256", "kid": "nope"}), [_JWK])
    with pytest.raises(OidcError, match="does not verify"):
        verify_compact_jws(_jws({"a": 1}, _PRIVATE, {"alg": "none"}), [_JWK])


def test_reads_subject_forms():
    assert EVENT["sessionRevoked"] == "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    assert EVENT["credentialCompromise"] == "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
    assert subject_of({
        "format": "complex",
        "user": {"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"},
        "session": {"format": "opaque", "id": "S1"},
    }, "https://i") == {"person": "urn:uuid:a", "idpSession": "S1"}
    assert subject_of({"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}, "https://i") == {}
    assert subject_of({"format": "email", "email": "A@x.com"}, "https://i") == {"email": "A@x.com"}


def test_polls_and_ends_only_the_named_session(stub):
    ended = []
    seen = []

    class Log:
        def info(self, message):
            return None

        def warn(self, message):
            return None

        def error(self, message):
            return None

    receiver = SignalsReceiver(
        transmitter=stub["url"],
        headers=lambda: {"authorization": "Bearer app-token"},
        on_end_sessions=lambda ids, event: ended.append(ids),
        poll_interval_ms=60_000,
        log=Log(),
    )
    receiver.on("*", lambda event: seen.append(event))
    receiver.start()
    receiver.stop()
    assert stub["state"]["created"] == 1
    assert stub["state"]["authorization"] == "Bearer app-token"
    assert receiver.stream["stream_id"] == "s1"

    receiver.track(_session("L-a1", "alice", "IDP-A1"))
    receiver.track(_session("L-a2", "alice", "IDP-A2"))
    receiver.track(_session("L-b1", "bob", "IDP-B1"))

    revoked = _deliver(stub, EVENT["sessionRevoked"], {
        "format": "complex",
        "user": {"format": "iss_sub", "iss": stub["url"], "sub": "urn:uuid:alice"},
        "session": {"format": "opaque", "id": "IDP-A1"},
    })
    _deliver(stub, EVENT["credentialChange"], {"format": "iss_sub", "iss": stub["url"], "sub": "urn:uuid:bob"}, {"credential_type": "password"})
    receiver.poll_once()
    assert ended == [["L-a1"]]
    assert len(seen) == 2
    assert seen[0]["ended"] is True
    assert seen[1]["type"] == EVENT["credentialChange"]
    assert seen[1]["ended"] is False

    receiver.poll_once()
    assert stub["acked"] == [revoked, *[item for item in stub["acked"] if item != revoked]]
    bad = _deliver(
        stub,
        EVENT["accountDisabled"],
        {"format": "email", "email": "alice@example.com"},
        key=_OTHER,
    )
    receiver.poll_once()
    receiver.poll_once()
    assert stub["errs"][bad]["err"] == "invalid_key"
    receiver.verify("abc")
    receiver.stop()


def test_oidc_error_is_exported():
    assert OidcError is not None
