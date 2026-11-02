# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Failures reported by this library."""


class OidcError(Exception):
    """Every failure this module reports is one of these.

    code is config, discovery, protocol, validation, signature, or ssf.
    oauth_error is the OAuth error code when the provider named one.
    """

    def __init__(self, code, message, cause=None, oauth_error=None):
        super().__init__(message)
        self.code = code
        self.oauth_error = oauth_error
        if cause is not None:
            self.__cause__ = cause
