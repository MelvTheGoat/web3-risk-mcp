"""score_risk: run the right checks for an address and combine them into one score."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field

from web3_risk_mcp import labels
from web3_risk_mcp.analysis.address import address_findings
from web3_risk_mcp.analysis.arc import (
    BLOCKLIST_SOURCE,
    SendCheck,
    blocklist_findings,
    blocklisted_by,
    send_check,
)
from web3_risk_mcp.analysis.common import Collector
from web3_risk_mcp.analysis.contract import inspect_contract
from web3_risk_mcp.analysis.token import check_token_risk
from web3_risk_mcp.analysis.trace import trace_funds
from web3_risk_mcp.analysis.wallet import get_wallet_profile
from web3_risk_mcp.chains import Chain
from web3_risk_mcp.clients.rpc import is_contract_code
from web3_risk_mcp.models import Finding, Report, SourceStatus
from web3_risk_mcp.scoring import RULES_VERSION, ScoreResult, score_findings

AddressType = Literal["wallet", "token", "contract", "unknown"]


class RiskScore(ScoreResult):
    chain: str
    address: str
    address_type: AddressType
    checks_run: list[str]
    data_gaps: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    sources: list[SourceStatus] = Field(default_factory=list)
    rules_version: int = Field(
        default=RULES_VERSION, description="Version of the rule table that made this score."
    )
    send_check: SendCheck | None = Field(
        default=None,
        description="Arc only: would a USDC payment to this address go through? "
        "Simulated, nothing is sent. It does not change the score.",
    )
    method: str = Field(
        default="Read the resource risk://scoring-method for the full rule table.",
    )


class _AddressLabels(Report):
    """A tiny report for contracts: the known-bad-address labels and, on Arc,
    the USDC and EURC blocklists."""


async def _address_labels(services, chain: Chain, address: str) -> _AddressLabels:
    c = Collector()
    calls = [c.run("GoPlus", services.goplus.address_security(chain, address))]
    if chain.blocklist_tokens:
        calls.append(c.run(BLOCKLIST_SOURCE, blocklisted_by(services, chain, address)))
    security, *blocked = await asyncio.gather(*calls)
    report = _AddressLabels(chain=chain.key, address=address)
    report.findings = address_findings(address, security, labels.lookup(chain.key, address))
    report.findings += blocklist_findings(chain, (blocked[0] if blocked else None) or [])
    if c.failed("GoPlus"):
        report.data_gaps.append(f"Address labels from GoPlus are missing: {c.error('GoPlus')}")
    if c.failed(BLOCKLIST_SOURCE):
        names = " and ".join(symbol for symbol, _ in chain.blocklist_tokens)
        report.data_gaps.append(
            f"The {names} blocklists could not be read. Reason: {c.error(BLOCKLIST_SOURCE)}"
        )
    report.sources = c.statuses
    return report


async def score_risk(
    services,
    chain: Chain,
    address: str,
    *,
    include_trace: bool = True,
    now: datetime | None = None,
) -> RiskScore:
    now = now or datetime.now(UTC)
    c = Collector()
    code_call = c.run("RPC", services.rpc.code(chain, address))
    if chain.native_transfer_emitter:
        # Arc: also test whether a USDC payment to this address would go through.
        code, payment = await asyncio.gather(
            code_call, c.run("RPC", send_check(services, chain, address))
        )
    else:
        code, payment = await code_call, None

    reports: dict[str, Report] = {}
    if code is not None and is_contract_code(code):
        token, contract, address_labels = await asyncio.gather(
            check_token_risk(services, chain, address, now=now),
            inspect_contract(services, chain, address, now=now),
            _address_labels(services, chain, address),
        )
        reports = {
            "check_token_risk": token,
            "inspect_contract": contract,
            "address_labels": address_labels,
        }
        is_token = bool(token.pools or token.symbol or token.holder_count)
        if is_token:
            address_labels.findings = [
                _supersede_honeypot_label(f) for f in address_labels.findings
            ]
        address_type: AddressType = "token" if is_token else "contract"
        if not is_token and not any(s.source == "GoPlus" and not s.ok for s in token.sources):
            # Not a token: token checks do not apply, so leave them out of the score.
            del reports["check_token_risk"]
    else:
        tasks = [get_wallet_profile(services, chain, address, now=now)]
        if include_trace:
            tasks.append(trace_funds(services, chain, address, hops=1))
        results = await asyncio.gather(*tasks)
        reports["get_wallet_profile"] = results[0]
        if include_trace:
            reports["trace_funds"] = results[1]
        address_type = "wallet" if code is not None else "unknown"

    findings: list[Finding] = [f for r in reports.values() for f in r.findings]
    sources = _merge_sources([*c.statuses, *(s for r in reports.values() for s in r.sources)])
    gaps = list(dict.fromkeys(g for r in reports.values() for g in r.data_gaps))
    notes = list(dict.fromkeys(n for r in reports.values() for n in r.notes))
    if code is None:
        gaps.insert(0, f"Could not tell if this is a wallet or a contract: {c.error('RPC')}")
    if chain.native_transfer_emitter and payment is None:
        gaps.append(f"Could not test a {chain.native_symbol} payment to this address.")

    result = score_findings(findings, sources)
    return RiskScore(
        **result.model_dump(),
        chain=chain.key,
        address=address,
        address_type=address_type,
        checks_run=list(reports),
        data_gaps=gaps,
        notes=notes,
        sources=sources,
        send_check=payment,
    )


def _supersede_honeypot_label(finding: Finding) -> Finding:
    """For a token, "linked to honeypots" is weak evidence: popular tokens like WETH
    are paired with many honeypots. check_token_risk tests the token directly, so
    that result is used instead and this label is kept for information only."""
    if finding.id != "address.honeypot_related_address":
        return finding
    return finding.model_copy(
        update={
            "id": "address.honeypot_related_token",
            "severity": "info",
            "detail": finding.detail
            + " For a token this usually means it is paired with honeypots in trading "
            "pools. The direct honeypot test in check_token_risk is used instead.",
        }
    )


def _merge_sources(statuses: list[SourceStatus]) -> list[SourceStatus]:
    """One status per source. If any call to a source failed, the source counts as failed."""
    merged: dict[str, SourceStatus] = {}
    for status in statuses:
        current = merged.get(status.source)
        if current is None or (current.ok and not status.ok):
            merged[status.source] = status
    return list(merged.values())
