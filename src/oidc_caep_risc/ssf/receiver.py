# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A Shared Signals receiver: one poll stream of CAEP and RISC events (RFC 8936)."""

import json
import re
import threading
import time

from ..backchannel import send
from ..discovery import well_known_urls
from ..errors import OidcError
from .events import DEFAULT_ENDING_EVENTS, DEFAULT_EVENTS_REQUESTED, EVENT, subject_of
from .jws import verify_compact_jws
from .session_index import MemorySessionIndex

_POLL_METHOD = "urn:ietf:rfc:8936"


class _Logger:
    def info(self, message):
        print(message)

    def warn(self, message):
        print(message)

    def error(self, message):
        print(message)


class SignalsReceiver:
    """Finds or creates this application's poll stream and turns events into local sessions."""

    def __init__(self, transmitter, on_end_sessions, tls=None, headers=None, events_requested=None,
                 end_on=None, session_index=None, description=None, poll_interval_ms=5000, max_events=50, log=None):
        if not callable(on_end_sessions):
            raise OidcError("config", "onEndSessions is required")
        if not re.match(r"https?://", transmitter or ""):
            raise OidcError("config", "transmitter must be an http(s) URL")
        self._transmitter = transmitter.rstrip("/")
        self._on_end = on_end_sessions
        self._tls = tls or {}
        self._headers = headers
        self._events_requested = list(events_requested or DEFAULT_EVENTS_REQUESTED)
        self._end_on = list(end_on or DEFAULT_ENDING_EVENTS)
        self._description = description
        self._poll_interval_ms = poll_interval_ms
        self._max_events = max_events
        self._log = log or _Logger()
        self._index = session_index or MemorySessionIndex()
        self._config = None
        self._stream = None
        self._keys = []
        self._keys_at = 0
        self._running = False
        self._ack = []
        self._errs = {}
        self._handlers = {}
        self._lock = threading.Lock()
        self._inflight = None
        self._stop = threading.Event()
        self._thread = None

    @property
    def stream(self):
        """The stream the receiver is polling, once started."""
        return self._stream

    def track(self, session):
        """Remembers a local session after a sign-in."""
        self._index.add(session)

    def untrack(self, local_id):
        """Forgets a local session, after a sign-out."""
        self._index.remove(local_id)

    def on(self, event_type, handler):
        """Adds a handler for one event type, or '*' for every event."""
        self._handlers.setdefault(event_type, []).append(handler)
        return self

    def _call(self, method, url, body=None):
        headers = {"accept": "application/json"}
        if self._headers:
            extra = self._headers()
            if extra:
                headers.update(extra)
        if body is not None:
            headers["content-type"] = "application/json"
        answer = send(url, method=method, headers=headers, body=None if body is None else json.dumps(body), tls=self._tls, code="ssf")
        parsed = None
        if answer["body"]:
            try:
                parsed = json.loads(answer["body"])
            except json.JSONDecodeError:
                parsed = answer["body"]
        return {"status": answer["status"], "json": parsed}

    def _discover(self):
        urls = well_known_urls(self._transmitter, "ssf-configuration")
        last = OidcError("ssf", f"no transmitter configuration at {' or '.join(urls)}")
        for url in urls:
            answer = self._call("GET", url)
            doc = answer["json"]
            if answer["status"] == 404 and url != urls[-1]:
                continue
            if answer["status"] != 200 or not isinstance(doc, dict) or not doc.get("configuration_endpoint") or not doc.get("jwks_uri"):
                last = OidcError("ssf", f"{url} answered {answer['status']} without a usable transmitter configuration")
                continue
            methods = doc.get("delivery_methods_supported")
            if methods and _POLL_METHOD not in methods:
                raise OidcError("ssf", "the transmitter does not offer poll delivery (RFC 8936)")
            return doc
        raise last

    def _jwks(self, force=False):
        if not force and self._keys and time.time() - self._keys_at < 3600:
            return self._keys
        answer = self._call("GET", self._config["jwks_uri"])
        keys = answer["json"].get("keys") if isinstance(answer["json"], dict) else None
        if answer["status"] != 200 or not isinstance(keys, list):
            raise OidcError("ssf", f"the transmitter's JWKS answered {answer['status']}")
        self._keys = keys
        self._keys_at = time.time()
        return keys

    def _ensure_stream(self):
        endpoint = self._config["configuration_endpoint"]
        listed = self._call("GET", endpoint)
        if listed["status"] == 200:
            raw = listed["json"]
            all_streams = raw if isinstance(raw, list) else ([raw] if raw else [])
            for stream in all_streams:
                if isinstance(stream, dict) and stream.get("delivery", {}).get("method") == _POLL_METHOD and stream.get("stream_id"):
                    return stream
        elif listed["status"] != 404:
            raise OidcError("ssf", f"listing the streams at {endpoint} answered {listed['status']}: {json.dumps(listed['json'])[:300]}")
        body = {"delivery": {"method": _POLL_METHOD}, "events_requested": self._events_requested}
        if self._description:
            body["description"] = self._description
        created = self._call("POST", endpoint, body)
        stream = created["json"] if isinstance(created["json"], dict) else {}
        if created["status"] not in (200, 201) or not stream.get("stream_id"):
            raise OidcError("ssf", f"creating a stream at {endpoint} answered {created['status']}: {json.dumps(created['json'])[:300]}")
        return stream

    def start(self):
        """Finds the transmitter and the stream, then polls until stop."""
        if self._running:
            return
        self._config = self._discover()
        self._jwks(force=True)
        self._stream = self._ensure_stream()
        delivery = self._stream.get("delivery") or {}
        if not delivery.get("endpoint_url"):
            raise OidcError("ssf", "the stream has no poll endpoint_url")
        self._running = True
        self._stop.clear()
        delivered = self._stream.get("events_delivered") or []
        self._log.info(
            f"ssf: polling stream {self._stream.get('stream_id')} at {delivery.get('endpoint_url')}, delivering {len(delivered)} event type(s)"
        )
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stops polling. Acknowledgements not yet sent go out on the next start's first poll.

        Waits until the poll loop has left. A later poll_once then starts a new
        poll instead of joining the one start() already had in flight.
        """
        self._running = False
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=20)
            if self._thread is thread:
                self._thread = None

    def _loop(self):
        while self._running:
            delay = self._poll_interval_ms / 1000
            try:
                more = self.poll_once()
                if more:
                    delay = 0
            except Exception as err:
                self._log.warn(f"ssf: poll failed: {err}")
                delay = min(self._poll_interval_ms * 4, 60_000) / 1000
            if not self._running:
                return
            if self._stop.wait(delay):
                return

    def poll_once(self):
        """One poll. A call while a poll is in flight joins it."""
        with self._lock:
            inflight = self._inflight
            if inflight is None or inflight["done"].is_set():
                done = threading.Event()
                holder = {}
                inflight = {"done": done, "holder": holder}

                def run():
                    try:
                        holder["result"] = self._poll_now()
                    except Exception as err:
                        holder["error"] = err
                    finally:
                        done.set()

                threading.Thread(target=run, daemon=True).start()
                self._inflight = inflight
        inflight["done"].wait()
        holder = inflight["holder"]
        if "error" in holder:
            raise holder["error"]
        return holder.get("result")

    def _poll_now(self):
        url = self._stream["delivery"]["endpoint_url"]
        ack = self._ack
        self._ack = []
        set_errs = self._errs
        self._errs = {}
        body = {"maxEvents": self._max_events, "returnImmediately": True}
        if ack:
            body["ack"] = ack
        if set_errs:
            body["setErrs"] = set_errs
        answer = self._call("POST", url, body)
        if answer["status"] != 200:
            self._ack = list(ack) + self._ack
            self._errs.update(set_errs)
            raise OidcError("ssf", f"the poll answered {answer['status']}: {json.dumps(answer['json'])[:300]}")
        payload = answer["json"] if isinstance(answer["json"], dict) else {}
        sets = payload.get("sets") or {}
        if not isinstance(sets, dict):
            sets = {}
        for jti, token in sets.items():
            try:
                self._handle(jti, token)
                self._ack.append(jti)
            except Exception as err:
                description = str(err)
                self._log.warn(f"ssf: SET {jti} refused: {description}")
                err_code = "invalid_key" if isinstance(err, OidcError) and err.code == "signature" else "invalid_request"
                self._errs[jti] = {"err": err_code, "description": description}
        return bool(payload.get("moreAvailable"))

    def _handle(self, jti, token):
        try:
            verified = verify_compact_jws(token, self._jwks())
        except OidcError as err:
            if err.code != "signature" or not re.search(r"publishes no|does not verify", err.args[0] if err.args else ""):
                raise
            verified = verify_compact_jws(token, self._jwks(force=True))
        header = verified["header"]
        payload = verified["payload"]
        if header.get("typ") is not None and str(header.get("typ")).lower() != "secevent+jwt":
            raise OidcError("validation", f"the SET's typ is {header.get('typ')}")
        if payload.get("iss") != self._config["issuer"]:
            raise OidcError("validation", f"the SET was issued by {payload.get('iss')}, not {self._config['issuer']}")
        raw_aud = self._stream.get("aud")
        want = list(raw_aud) if isinstance(raw_aud, list) else ([raw_aud] if raw_aud else [])
        got = payload.get("aud")
        aud = [str(item) for item in got] if isinstance(got, list) else ([str(got)] if got is not None else [])
        if want and not any(one in want for one in aud):
            raise OidcError("validation", f"the SET is for {', '.join(aud)}, not this stream")
        if payload.get("jti") is not None and payload.get("jti") != jti:
            raise OidcError("validation", "the SET's jti is not the one it was delivered under")
        events = payload.get("events")
        if not isinstance(events, dict) or not events:
            raise OidcError("validation", "the SET carries no events")
        for event_type, body in events.items():
            subject = subject_of(payload.get("sub_id") if payload.get("sub_id") is not None else (body or {}).get("subject"), self._config["issuer"])
            sessions = self._sessions_for(event_type, subject)
            ends = event_type in self._end_on and len(sessions) > 0
            event = {
                "type": event_type,
                "payload": body or {},
                "subject": subject,
                "jti": jti,
                "sessions": sessions,
                "ended": ends,
            }
            if isinstance(payload.get("iat"), (int, float)) and not isinstance(payload.get("iat"), bool):
                event["iat"] = payload["iat"]
            if isinstance(payload.get("txn"), str):
                event["txn"] = payload["txn"]
            if ends:
                try:
                    self._on_end(sessions, event)
                except Exception as err:
                    self._log.error(f"ssf: onEndSessions threw for {event_type} (SET {jti} is still acknowledged): {err}")
                    event["ended"] = False
                if event["ended"]:
                    for local_id in sessions:
                        self._index.remove(local_id)
            for handler in list(self._handlers.get(event_type, [])) + list(self._handlers.get("*", [])):
                try:
                    handler(event)
                except Exception as err:
                    self._log.error(f"ssf: a handler for {event_type} threw (SET {jti} is still acknowledged): {err}")

    def _sessions_for(self, event_type, subject):
        if event_type in (EVENT["verification"], EVENT["streamUpdated"]):
            return []
        if subject.get("idpSession"):
            found = self._index.by_idp_session(subject["idpSession"])
            if found or event_type == EVENT["sessionRevoked"]:
                return found
        if subject.get("person"):
            return self._index.by_person(subject["person"])
        if subject.get("email"):
            return self._index.by_email(subject["email"])
        return []

    def verify(self, state=None):
        """Asks the transmitter for a verification event."""
        endpoint = (self._config or {}).get("verification_endpoint")
        if not isinstance(endpoint, str):
            raise OidcError("ssf", "the transmitter publishes no verification_endpoint")
        body = {"stream_id": self._stream["stream_id"]}
        if state:
            body["state"] = state
        answer = self._call("POST", endpoint, body)
        if answer["status"] not in (200, 204):
            raise OidcError("ssf", f"verification answered {answer['status']}")
