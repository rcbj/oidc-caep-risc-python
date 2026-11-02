# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Reads a configuration file and says whether it names a confidential client. It does not print secrets."""

import sys

from .config import read_config_file
from .errors import OidcError


def usage():
    return """oidc-caep-risc — a confidential OpenID Connect client

Usage
  oidc-caep-risc check --config <file>   read the file and print the client, without its secret
  oidc-caep-risc help

The library is RelyingParty, imported from oidc_caep_risc."""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv else "help"
    if command in ("help", "--help", "-h"):
        print(usage())
        return 0
    if command != "check":
        print(f"unknown command {command}\n{usage()}", file=sys.stderr)
        return 1
    try:
        at = argv.index("--config")
    except ValueError:
        at = -1
    file = argv[at + 1] if at >= 0 and at + 1 < len(argv) else None
    if not file:
        print(f"check needs --config <file>\n{usage()}", file=sys.stderr)
        return 1
    try:
        config = read_config_file(file)
    except OidcError as err:
        print(err, file=sys.stderr)
        return 1
    metadata = config.get("metadataUrl") or (config.get("metadata") or {}).get("issuer") or "(file)"
    print(f"client_id:  {config['clientId']}")
    print(f"auth:       {config['tokenEndpointAuthMethod']}")
    print(f"redirect:   {config['redirectUri']}")
    print(f"scopes:     {config['scopes']}")
    print(f"metadata:   {metadata}")
    print(f"secret:     {'present' if config.get('clientSecret') else 'absent'}")
    print(f"tls ca:     {'present' if config.get('tlsCa') else 'absent'}")
    print(f"ssf:        {(config.get('ssf') or {}).get('transmitter') or 'not configured'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
