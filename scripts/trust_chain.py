# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Fetch the provider's listener CA trust chain and write the file tlsCa names.

The first fetch does not verify TLS. If GET /tls/server-certificate is missing,
the handshake's own chain is used. A failure leaves the file as it is and exits 0
when this file is the process entry point.
"""

import os
import re
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

TIMEOUT = 10


def trust_path(raw, base_dir):
    """A path or file: path. PEM and env: are not a file to write."""
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value or "-----BEGIN" in value or value.startswith("env:"):
        return None
    path = value[5:] if value.startswith("file:") else value
    if not path:
        return None
    return path if os.path.isabs(path) else os.path.abspath(os.path.join(base_dir, path))


def _certs_of(pem):
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", str(pem))
    return [x509.load_pem_x509_certificate(block.encode()) for block in blocks]


def _fingerprint(cert):
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{byte:02X}" for byte in digest)


def _bundle(certs):
    if not certs:
        raise RuntimeError("the trust chain has no certificates")
    anchor = next((cert for cert in reversed(certs) if cert.subject == cert.issuer), certs[-1])
    pem = "".join(cert.public_bytes(Encoding.PEM).decode() for cert in certs)
    if not pem.endswith("\n"):
        pem += "\n"
    return {"pem": pem, "anchor": anchor, "count": len(certs), "fingerprint": _fingerprint(anchor)}


def _servername(hostname):
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return None
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return None
    except OSError:
        return hostname


def fetch_published(origin):
    target = urlsplit(origin)
    url = f"{target.scheme}://{target.netloc}/tls/server-certificate"
    context = ssl._create_unverified_context()
    request = Request(url, headers={"accept": "text/plain"})
    with urlopen(request, context=context, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError(f"{url} answered {response.status}")
        return _bundle(_certs_of(response.read().decode()))


def fetch_handshake(origin):
    target = urlsplit(origin)
    host = target.hostname
    port = target.port or 443
    command = ["openssl", "s_client", "-showcerts", "-connect", f"{host}:{port}"]
    name = _servername(host)
    if name:
        command[2:2] = ["-servername", name]
    proc = subprocess.run(command, input=b"", capture_output=True, timeout=TIMEOUT, check=False)
    text = proc.stdout.decode("utf-8", "replace")
    return _bundle(_certs_of(text))


def fetch_trust_chain(origin):
    try:
        return fetch_published(origin)
    except Exception:
        return fetch_handshake(origin)


def save_trust_chain(origin, dest):
    chain = fetch_trust_chain(origin)
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    Path(dest).write_text(chain["pem"], encoding="utf-8")
    return {**chain, "path": dest, "origin": origin}


def _config_from_argv(argv):
    config = os.environ.get("OIDC_CONFIG") or ""
    i = 0
    while i < len(argv):
        if argv[i] == "--config":
            i += 1
            if i >= len(argv) or not argv[i]:
                raise RuntimeError("--config needs a value")
            config = argv[i]
        i += 1
    if not config:
        raise RuntimeError("trust-chain needs --config <file> or OIDC_CONFIG")
    return os.path.abspath(config)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    config_path = _config_from_argv(argv)
    raw = __import__("json").loads(Path(config_path).read_text(encoding="utf-8"))
    metadata_url = str(raw.get("metadataUrl") or "").strip()
    if not metadata_url:
        raise RuntimeError(f"{config_path} has no metadataUrl")
    dest = trust_path(raw.get("tlsCa"), str(Path(config_path).parent))
    if not dest:
        raise RuntimeError(f"{config_path} tlsCa is not a file this process can update")
    saved = save_trust_chain(f"{urlsplit(metadata_url).scheme}://{urlsplit(metadata_url).netloc}", dest)
    subject = saved["anchor"].subject.rfc4514_string().replace("\n", ", ")
    print(f"Saved {saved['origin']}'s listener CA trust chain ({saved['count']} certificate(s)) to {saved['path']}")
    print(f"  trust anchor {subject}")
    print(f"  sha256 {saved['fingerprint']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"tls ca: not updated: {err}", file=sys.stderr)
        sys.exit(0)
