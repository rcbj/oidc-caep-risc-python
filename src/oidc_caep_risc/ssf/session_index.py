# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Which local sessions belong to which person and which provider session."""

import time
from collections import OrderedDict


class MemorySessionIndex:
    """One process's memory, bounded: expired sessions go first, then the oldest."""

    def __init__(self, max_sessions=100_000):
        self._sessions = OrderedDict()
        self._max = max_sessions

    def add(self, session):
        local_id = session["local_id"]
        if len(self._sessions) >= self._max and local_id not in self._sessions:
            now = time.time()
            for key, value in list(self._sessions.items()):
                expires = value.get("expires_at")
                if expires is not None and _stamp(expires) <= now:
                    del self._sessions[key]
            while len(self._sessions) >= self._max:
                oldest = next(iter(self._sessions), None)
                if oldest is None:
                    break
                del self._sessions[oldest]
        stored = dict(session)
        if stored.get("email"):
            stored["email"] = stored["email"].lower()
        self._sessions[local_id] = stored

    def remove(self, local_id):
        self._sessions.pop(local_id, None)

    def _find(self, match):
        now = time.time()
        out = []
        for key, value in list(self._sessions.items()):
            expires = value.get("expires_at")
            if expires is not None and _stamp(expires) <= now:
                del self._sessions[key]
                continue
            if match(value):
                out.append(key)
        return out

    def by_person(self, person):
        return self._find(lambda session: session.get("person") == person)

    def by_email(self, email):
        wanted = email.lower()
        return self._find(lambda session: session.get("email") == wanted)

    def by_idp_session(self, idp_session):
        return self._find(lambda session: session.get("idp_session") == idp_session)


def _stamp(value):
    if hasattr(value, "timestamp"):
        return value.timestamp()
    return float(value)


def tracked_from_login(local_id, login, expires_at=None):
    """What an OpenID Connect sign-in says about the session, for the index."""
    session = {"local_id": local_id, "person": login.get("subject")}
    if login.get("email"):
        session["email"] = login["email"]
    if login.get("sid"):
        session["idp_session"] = login["sid"]
    if expires_at is not None:
        session["expires_at"] = expires_at
    return session
