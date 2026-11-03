# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The tokens of completed sign-ins, keyed by a session identifier the application chooses."""

import threading


class SessionTokenStore:
    """The interface. Replace MemorySessionTokenStore with one of these to share entries across processes.

    An entry is the dict complete() returns: JSON-serializable, and it holds the access token,
    the refresh token, the ID token and its claims. A shared store must keep it confidential.
    """

    def get(self, session_id):
        """The entry, or None."""
        raise NotImplementedError

    def set(self, session_id, entry):
        """Stores or replaces the entry."""
        raise NotImplementedError

    def delete(self, session_id):
        """Removes the entry. Removing an absent entry is not an error."""
        raise NotImplementedError


class MemorySessionTokenStore(SessionTokenStore):
    """This process's memory. The default."""

    def __init__(self):
        self._entries = {}
        self._lock = threading.Lock()

    def get(self, session_id):
        with self._lock:
            entry = self._entries.get(session_id)
            return dict(entry) if entry is not None else None

    def set(self, session_id, entry):
        with self._lock:
            self._entries[session_id] = dict(entry)

    def delete(self, session_id):
        with self._lock:
            self._entries.pop(session_id, None)

    def __len__(self):
        with self._lock:
            return len(self._entries)
