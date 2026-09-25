"""score_risk: run the right checks for an address and combine them into one score."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field

from web3_risk_mcp import labels
from web3_risk_mcp.analysis.address import address_findings
from web3_risk_mcp.analysis.common import Collector
from web3_risk_mcp.analysis.contract import inspect_contract
from web3_risk_mcp.analysis.token import check_token_risk
from web3_risk_mcp.analysis.trace import trace_funds
from web3_risk_mcp.analysis.wallet import get_wallet_profile
from web3_risk_mcp.chains import Chain
from web3_risk_mcp.models import Finding, Report, SourceStatus
from web3_risk_mcp.scoring import ScoreResult, score_findings

AddressType = Literal["wallet", "token", "contract", "unknown"]


class RiskScore(ScoreResult):
    chain: str
    address: str
    address_type: AddressType
    checks_run: list[str]
    data_gaps: list[str] = Field(default_factory=list)
    sources: list[SourceStatus] = Field(default_factory=list)
    method: str = Field(
        default="Read the resource risk://scoring-method for the full rule table.",
    )


class _AddressLabels(Report):
    """A tiny report for contracts: only the known-bad-address labels."""


async def _address_labels(services, chain: Chain, address: str) -> _AddressLabels:
    c = Collector()
    security = await c.run("GoPlus", services.goplus.address_security(chain, address))
    report = _AddressLabels(chain=chain.key, address=address)
    report.findings = address_findings(address, security, labels.lookup(chain.key, address))
    if c.failed("GoPlus"):
        report.data_gaps.append(f"Address labels from GoPlus are missing: {c.error('GoPlus')}")
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
    code = await c.run("RPC", services.rpc.code(chain, address))

    reports: dict[str, Report] = {}
    if code is not None and code != "0x":
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
        is_token = bool(token.pools) or token.is_open_source is not None or token.holder_count
        address_type: AddressType = "token" if is_token else "contract"
        if not is_token:
            # Token-specific gaps ("may not be a token") are noise for a plain contract.
            token.data_gaps = [g for g in token.data_gaps if "may not be a token" not in g]
    else:
        tasks = [get_wallet_profile(services, chain, address, now=now)]
        if include_trace:
            tasks.append(trace_funds(services, chain, address, hops=1))
        results = await asyncio.gather(*tasks)
        reports["get_wallet_profile"] = results[0]
        if include_trace:
            reports["trace_funds"] = results[1]
        address_type = "wallet" if code == "0x" else "unknown"

    findings: list[Finding] = [f for r in reports.values() for f in r.findings]
    sources = _merge_sources([*c.statuses, *(s for r in reports.values() for s in r.sources)])
    gaps = list(dict.fromkeys(g for r in reports.values() for g in r.data_gaps))
    if code is None:
        gaps.insert(0, f"Could not tell if this is a wallet or a contract: {c.error('RPC')}")

    result = score_findings(findings, sources)
    return RiskScore(
        **result.model_dump(),
        chain=chain.key,
        address=address,
        address_type=address_type,
        checks_run=list(reports),
        data_gaps=gaps,
        sources=sources,
    )


def _merge_sources(statuses: list[SourceStatus]) -> list[SourceStatus]:
    """One status per source. If any call to a source failed, the source counts as failed."""
    merged: dict[str, SourceStatus] = {}
    for status in statuses:
        current = merged.get(status.source)
        if current is None or (current.ok and not status.ok):
            merged[status.source] = status
    return list(merged.values())
