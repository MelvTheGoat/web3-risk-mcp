"""Findings about a single address: is it on a list of known bad actors?"""

from __future__ import annotations

from typing import Any

from web3_risk_mcp.analysis.common import flag
from web3_risk_mcp.models import Finding, KnownLabel, Severity

# Every bad-behaviour flag GoPlus can set on an address, with a plain meaning.
GOPLUS_ADDRESS_FLAGS: dict[str, tuple[Severity, str]] = {
    "sanctioned": ("critical", "is on a government sanctions list"),
    "stealing_attack": ("critical", "has been linked to stealing attacks"),
    "phishing_activities": (
        "critical",
        "has been linked to phishing (tricking people into signing away funds)",
    ),
    "cybercrime": ("high", "has been linked to cybercrime"),
    "money_laundering": ("high", "has been linked to money laundering"),
    "financial_crime": ("high", "has been linked to financial crime"),
    "blackmail_activities": ("high", "has been linked to blackmail"),
    "darkweb_transactions": ("high", "has been linked to darkweb transactions"),
    "honeypot_related_address": ("high", "is linked to honeypot tokens (tokens you cannot sell)"),
    "fake_token": ("high", "has been linked to fake tokens"),
    "malicious_mining_activities": ("medium", "has been linked to malicious mining"),
    "mixer": ("medium", "is or uses a mixer (a service that hides where funds came from)"),
    "fake_kyc": ("medium", "has been linked to fake identity checks"),
    "blacklist_doubt": ("medium", "is suspected of being on a blacklist"),
    "reinit": ("medium", "can be redeployed with different code at the same address"),
    "gas_abuse": ("medium", "has been linked to gas abuse (tricking wallets into paying fees)"),
    "fake_standard_interface": ("medium", "pretends to follow a token standard but does not"),
}

_KNOWN_LABEL_SEVERITY: dict[str, Severity] = {
    "sanctioned": "critical",
    "exploit": "critical",
    "scam": "critical",
    "mixer": "high",
}


def goplus_flags(result: dict[str, Any] | None) -> list[str]:
    """Names of the GoPlus flags that are switched on."""
    if not result:
        return []
    return [name for name in GOPLUS_ADDRESS_FLAGS if flag(result.get(name))]


def address_findings(
    address: str,
    goplus_result: dict[str, Any] | None,
    known: KnownLabel | None,
    *,
    subject: str = "This address",
) -> list[Finding]:
    """Turn GoPlus address labels and our local list into findings."""
    findings: list[Finding] = []
    for name in goplus_flags(goplus_result):
        severity, meaning = GOPLUS_ADDRESS_FLAGS[name]
        findings.append(
            Finding(
                id=f"address.{name}",
                severity=severity,
                title=f"Flagged: {name.replace('_', ' ')}",
                detail=f"{subject} {meaning}, according to GoPlus.",
                source="GoPlus",
            )
        )
    created = int((goplus_result or {}).get("number_of_malicious_contracts_created") or 0)
    if created > 0:
        findings.append(
            Finding(
                id="address.malicious_contracts_created",
                severity="high",
                title="Created malicious contracts",
                detail=f"{subject} created {created} contract(s) that GoPlus marks as malicious.",
                source="GoPlus",
            )
        )
    if known is not None and known.category in _KNOWN_LABEL_SEVERITY:
        findings.append(
            Finding(
                id=f"address.known_{known.category}",
                severity=_KNOWN_LABEL_SEVERITY[known.category],
                title=f"Known address: {known.name}",
                detail=f"{subject} is {known.name} ({known.category}). {known.note or ''}".strip(),
                source="Local list",
            )
        )
    return findings
