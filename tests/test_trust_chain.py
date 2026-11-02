# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""tlsCa: the install script writes the whole listener CA trust chain to the
file the parameter names, and the library takes that file as its trust store.

The stub provider is HTTPS on a four-certificate chain shaped like iya-sts's
(leaf, TLS Issuing CA, Intermediate, Root) and publishes it, leaf first, at
GET /tls/server-certificate.
"""

import datetime
import ipaddress
import json
import ssl
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

from oidc_caep_risc import OidcError, resolve_config
from oidc_caep_risc.backchannel import send

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import configure_iya_sts  # noqa: E402
import trust_chain  # noqa: E402

SHIPPED_CONFIG = ROOT / "demo" / "oidc.json"
DEFAULT_TLS_CA = "generated/idp-ca.pem"


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _cert(subject, key, issuer, issuer_key, ca, leaf_ip=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    if leaf_ip:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(leaf_ip))]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert):
    return cert.public_bytes(Encoding.PEM).decode()


@pytest.fixture(scope="module")
def provider():
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
    root = _cert("sts Root CA", keys[0], "sts Root CA", keys[0], True)
    intermediate = _cert("sts Intermediate CA", keys[1], "sts Root CA", keys[0], True)
    issuing = _cert("sts TLS Issuing CA", keys[2], "sts Intermediate CA", keys[1], True)
    leaf = _cert("127.0.0.1", keys[3], "sts TLS Issuing CA", keys[2], False, leaf_ip="127.0.0.1")
    published = "".join(_pem(cert) for cert in (leaf, issuing, intermediate, root))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path == "/tls/server-certificate":
                body, kind = published.encode(), "text/plain"
            elif self.path == "/.well-known/openid-configuration":
                body, kind = json.dumps({"issuer": origin}).encode(), "application/json"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("content-type", kind)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with tempfile.TemporaryDirectory(prefix="trust-chain-server-") as directory:
        chain_file = Path(directory, "server.pem")
        key_file = Path(directory, "server.key")
        chain_file.write_text("".join(_pem(cert) for cert in (leaf, issuing, intermediate)), encoding="utf-8")
        key_file.write_bytes(keys[3].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(chain_file), str(key_file))
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        origin = f"https://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield {"origin": origin, "published": published, "root": root}
        finally:
            server.shutdown()
            server.server_close()


def _demo_dir(directory, origin):
    """A demo directory whose oidc.json is the shipped one, pointed at the stub."""
    demo = Path(directory, "demo")
    demo.mkdir()
    raw = json.loads(SHIPPED_CONFIG.read_text(encoding="utf-8"))
    raw["metadataUrl"] = origin + "/.well-known/openid-configuration"
    (demo / "oidc.json").write_text(json.dumps(raw), encoding="utf-8")
    return demo


def test_the_shipped_demo_names_generated_idp_ca_pem():
    assert json.loads(SHIPPED_CONFIG.read_text(encoding="utf-8"))["tlsCa"] == DEFAULT_TLS_CA


def test_the_install_script_writes_the_whole_chain_to_tls_ca(provider):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        target = demo / DEFAULT_TLS_CA
        files = configure_iya_sts.files_of(str(demo / "oidc.json"), "http://127.0.0.1:3000")
        assert files["tlsCa"] == str(target.resolve())
        saved = trust_chain.save_trust_chain(provider["origin"], files["tlsCa"])
        assert target.read_text(encoding="utf-8") == provider["published"]
        assert saved["count"] == 4
        assert saved["anchor"] == provider["root"]
        assert saved["fingerprint"] == ":".join(
            f"{byte:02X}" for byte in provider["root"].fingerprint(hashes.SHA256())
        )


def test_the_refresh_entry_point_writes_tls_ca_and_names_the_anchor(provider, capsys):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        trust_chain.main(["--config", str(demo / "oidc.json")])
        assert (demo / DEFAULT_TLS_CA).read_text(encoding="utf-8") == provider["published"]
        printed = capsys.readouterr().out
        assert str((demo / DEFAULT_TLS_CA).resolve()) in printed
        assert "(4 certificate(s))" in printed
        assert "CN=sts Root CA" in printed
        assert "sha256 " in printed


def test_the_library_trusts_the_provider_through_the_saved_file(provider):
    with tempfile.TemporaryDirectory(prefix="trust-chain-") as directory:
        demo = _demo_dir(directory, provider["origin"])
        url = provider["origin"] + "/.well-known/openid-configuration"
        with pytest.raises(OidcError):
            send(url)
        trust_chain.save_trust_chain(provider["origin"], str(demo / DEFAULT_TLS_CA))
        (demo / "generated" / "client-secret").write_text("the install script's secret\n", encoding="utf-8")
        config = resolve_config(json.loads((demo / "oidc.json").read_text(encoding="utf-8")), str(demo))
        assert config["tlsCa"] == provider["published"]
        answered = send(url, tls={"ca": config["tlsCa"]})
        assert answered["status"] == 200
        assert json.loads(answered["body"])["issuer"] == provider["origin"]
