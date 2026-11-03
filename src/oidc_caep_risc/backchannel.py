# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The back channel. TLS is always verified; ca is added to the default trust store."""

import http.client
import socket
import ssl
from urllib.parse import urlsplit

from .errors import OidcError

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 15


def _ssl_context(tls):
    tls = tls or {}
    context = ssl.create_default_context()
    ca = tls.get("ca")
    if ca:
        context.load_verify_locations(cadata=ca)
    cert = tls.get("cert")
    key = tls.get("key")
    if cert and key:
        # load_cert_chain wants paths. PEM strings go through temporary files only if needed;
        # SSLContext has no string API, so use a memory BIO via cadata is not for keys.
        import os
        import tempfile
        cert_file = tempfile.NamedTemporaryFile("w", delete=False)
        key_file = tempfile.NamedTemporaryFile("w", delete=False)
        try:
            cert_file.write(cert)
            cert_file.close()
            key_file.write(key)
            key_file.close()
            context.load_cert_chain(cert_file.name, key_file.name)
        finally:
            os.unlink(cert_file.name)
            os.unlink(key_file.name)
    return context


def send(url, method="GET", headers=None, body=None, tls=None, code="protocol"):
    """One HTTP(S) request. Redirects are not followed. The body is capped.

    headers in the answer are the response headers, names lower-cased, repeats joined with ", ".
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise OidcError(code, f"{url} is not an http(s) URL")
    if not parts.hostname:
        raise OidcError(code, f"{url} is not an http(s) URL")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    payload = None if body is None else (body.encode("utf-8") if isinstance(body, str) else body)
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    if payload is not None:
        hdrs["content-length"] = str(len(payload))
    connection = None
    try:
        if parts.scheme == "https":
            connection = http.client.HTTPSConnection(parts.hostname, port, timeout=TIMEOUT_S, context=_ssl_context(tls))
        else:
            connection = http.client.HTTPConnection(parts.hostname, port, timeout=TIMEOUT_S)
        connection.request(method, path, body=payload, headers=hdrs)
        response = connection.getresponse()
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise OidcError(code, f"{url} answered more than {MAX_BYTES} bytes")
        content_type = response.getheader("content-type") or ""
        received = {}
        for name, value in response.getheaders():
            key = name.lower()
            received[key] = f"{received[key]}, {value}" if key in received else value
        return {
            "status": response.status,
            "content_type": content_type,
            "headers": received,
            "body": raw.decode("utf-8", "replace"),
        }
    except OidcError:
        raise
    except socket.timeout as err:
        raise OidcError(code, f"{url} did not answer within {TIMEOUT_S} s", cause=err) from err
    except Exception as err:
        raise OidcError(code, f"{url}: {err}", cause=err) from err
    finally:
        if connection is not None:
            connection.close()
