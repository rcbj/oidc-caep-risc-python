# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Base64url without padding, the form JOSE and PKCE use."""

import base64
import re

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value, what="value"):
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise ValueError(f"{what} is not base64url")
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)
