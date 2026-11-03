# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A server-side OpenID Connect confidential client, and one CAEP/RISC poll stream.

    rp = RelyingParty.from_file("oidc.json")
    request = rp.authorize()
    who = rp.complete(query, request)
"""

from .config import apply_defaults, check_redirect, read_config_file, resolve_config
from .discovery import (
    ASYMMETRIC_JWS_ALGS,
    DEFAULT_ID_TOKEN_SIGNING_ALGS,
    DEFAULT_SCOPES,
    discover_provider,
    issuer_from_metadata_url,
    validate_provider_metadata,
    well_known_urls,
)
from .dpop import DPoPKey
from .errors import OidcError
from .id_token import hash_claim, validate_id_token
from .pkce import code_challenge_s256, random_token
from .relying_party import RelyingParty
from .session_cache import MemorySessionTokenStore, SessionTokenStore
from .ssf import (
    CAEP_EVENTS,
    DEFAULT_ENDING_EVENTS,
    DEFAULT_EVENTS_REQUESTED,
    EVENT,
    RISC_EVENTS,
    MemorySessionIndex,
    SignalsReceiver,
    subject_of,
    tracked_from_login,
)

__all__ = [
    "ASYMMETRIC_JWS_ALGS",
    "CAEP_EVENTS",
    "DEFAULT_ENDING_EVENTS",
    "DEFAULT_ID_TOKEN_SIGNING_ALGS",
    "DPoPKey",
    "DEFAULT_EVENTS_REQUESTED",
    "DEFAULT_SCOPES",
    "EVENT",
    "RISC_EVENTS",
    "MemorySessionIndex",
    "MemorySessionTokenStore",
    "OidcError",
    "RelyingParty",
    "SessionTokenStore",
    "SignalsReceiver",
    "apply_defaults",
    "check_redirect",
    "code_challenge_s256",
    "discover_provider",
    "hash_claim",
    "issuer_from_metadata_url",
    "random_token",
    "read_config_file",
    "resolve_config",
    "subject_of",
    "tracked_from_login",
    "validate_id_token",
    "validate_provider_metadata",
    "well_known_urls",
]
