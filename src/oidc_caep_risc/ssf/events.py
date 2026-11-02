# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""CAEP, RISC, and SSF event types, and what an event's subject names."""

_CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
_RISC = "https://schemas.openid.net/secevent/risc/event-type/"
_SSF = "https://schemas.openid.net/secevent/ssf/event-type/"

EVENT = {
    "sessionRevoked": f"{_CAEP}session-revoked",
    "tokenClaimsChange": f"{_CAEP}token-claims-change",
    "credentialChange": f"{_CAEP}credential-change",
    "assuranceLevelChange": f"{_CAEP}assurance-level-change",
    "deviceComplianceChange": f"{_CAEP}device-compliance-change",
    "sessionEstablished": f"{_CAEP}session-established",
    "sessionPresented": f"{_CAEP}session-presented",
    "riskLevelChange": f"{_CAEP}risk-level-change",
    "accountCredentialChangeRequired": f"{_RISC}account-credential-change-required",
    "accountPurged": f"{_RISC}account-purged",
    "accountDisabled": f"{_RISC}account-disabled",
    "accountEnabled": f"{_RISC}account-enabled",
    "identifierChanged": f"{_RISC}identifier-changed",
    "identifierRecycled": f"{_RISC}identifier-recycled",
    "credentialCompromise": f"{_RISC}credential-compromise",
    "optIn": f"{_RISC}opt-in",
    "optOutInitiated": f"{_RISC}opt-out-initiated",
    "optOutCancelled": f"{_RISC}opt-out-cancelled",
    "optOutEffective": f"{_RISC}opt-out-effective",
    "recoveryActivated": f"{_RISC}recovery-activated",
    "recoveryInformationChanged": f"{_RISC}recovery-information-changed",
    "sessionsRevoked": f"{_RISC}sessions-revoked",
    "verification": f"{_SSF}verification",
    "streamUpdated": f"{_SSF}stream-updated",
}

CAEP_EVENTS = tuple(uri for uri in EVENT.values() if uri.startswith(_CAEP))
RISC_EVENTS = tuple(uri for uri in EVENT.values() if uri.startswith(_RISC))

DEFAULT_EVENTS_REQUESTED = (
    EVENT["sessionRevoked"], EVENT["credentialChange"], EVENT["assuranceLevelChange"], EVENT["tokenClaimsChange"],
    EVENT["accountDisabled"], EVENT["accountEnabled"], EVENT["accountPurged"], EVENT["credentialCompromise"],
    EVENT["sessionsRevoked"], EVENT["accountCredentialChangeRequired"],
)

DEFAULT_ENDING_EVENTS = (
    EVENT["sessionRevoked"], EVENT["accountDisabled"], EVENT["accountPurged"],
    EVENT["credentialCompromise"], EVENT["sessionsRevoked"],
)


def _present(document, *names):
    for name in names:
        if name in document and document[name] is not None:
            return document[name]
    return None


def _simple(identifier, issuer):
    if not isinstance(identifier, dict):
        return {}
    fmt = str(_present(identifier, "format", "subject_type") or "")
    if fmt == "iss_sub" and isinstance(identifier.get("sub"), str) and (identifier.get("iss") is None or identifier.get("iss") == issuer):
        return {"sub": identifier["sub"]}
    if fmt == "email" and isinstance(identifier.get("email"), str):
        return {"email": identifier["email"]}
    if fmt == "opaque" and isinstance(identifier.get("id"), str):
        return {"opaque": identifier["id"]}
    if fmt == "aliases" and isinstance(identifier.get("identifiers"), list):
        merged = {}
        for one in identifier["identifiers"]:
            merged.update(_simple(one, issuer))
        return merged
    return {}


def subject_of(sub_id, issuer):
    """Reads an event's subject. A complex subject's user is the person and its session the provider session."""
    if not isinstance(sub_id, dict):
        return {}
    fmt = str(_present(sub_id, "format", "subject_type") or "")
    if fmt == "complex" or (not fmt and (sub_id.get("user") or sub_id.get("session"))):
        user = _simple(sub_id.get("user"), issuer)
        session = _simple(sub_id.get("session"), issuer)
        out = {}
        if user.get("sub"):
            out["person"] = user["sub"]
        if user.get("email"):
            out["email"] = user["email"]
        session_id = session.get("opaque") or session.get("sub")
        if session_id:
            out["idpSession"] = session_id
        return out
    one = _simple(sub_id, issuer)
    out = {}
    if one.get("sub"):
        out["person"] = one["sub"]
    if one.get("email"):
        out["email"] = one["email"]
    return out
