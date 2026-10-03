"""Wallet profile: who is this address and how does it behave?"""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

from web3_risk_mcp import labels
from web3_risk_mcp.analysis.address import address_findings, goplus_flags
from web3_risk_mcp.analysis.arc import (
    BLOCKLIST_SOURCE,
    arc_history_note,
    blocklist_findings,
    blocklisted_by,
    other_tokens,
    without_value,
)
from web3_risk_mcp.analysis.common import (
    Collector,
    days_between,
    from_unix,
    wei_to_coin,
)
from web3_risk_mcp.chains import Chain
from web3_risk_mcp.clients.rpc import delegation_target, is_contract_code
from web3_risk_mcp.models import (
    ActivityPattern,
    Counterparty,
    Finding,
    TokenActivity,
    WalletProfile,
)
from web3_risk_mcp.services import Services

RECENT_LIMIT = 100
OLDEST_LIMIT = 20
TOP_COUNTERPARTIES = 8
TOP_TOKENS = 10


async def get_wallet_profile(
    services: Services, chain: Chain, address: str, *, now: datetime | None = None
) -> WalletProfile:
    now = now or datetime.now(UTC)
    c = Collector()
    es, rpc = services.etherscan, services.rpc
    logs_native_moves = chain.native_transfer_emitter is not None

    calls = {
        "balance": c.run("RPC", rpc.balance(chain, address)),
        "nonce": c.run("RPC", rpc.nonce(chain, address)),
        "code": c.run("RPC", rpc.code(chain, address)),
        "recent": c.run(
            "Etherscan", es.transactions(chain, address, sort="desc", limit=RECENT_LIMIT)
        ),
        "oldest": c.run(
            "Etherscan", es.transactions(chain, address, sort="asc", limit=OLDEST_LIMIT)
        ),
        "token_txs": c.run("Etherscan", es.token_transfers(chain, address, limit=RECENT_LIMIT)),
        "security": c.run("GoPlus", services.goplus.address_security(chain, address)),
    }
    if logs_native_moves:
        # Arc: the system Transfer stream already includes payouts from contracts,
        # so "internal" transactions are not needed.
        calls["native_recent"] = c.run(
            "Etherscan", es.native_transfers(chain, address, sort="desc", limit=RECENT_LIMIT)
        )
        calls["native_oldest"] = c.run(
            "Etherscan", es.native_transfers(chain, address, sort="asc", limit=OLDEST_LIMIT)
        )
    else:
        calls["internal"] = c.run(
            "Etherscan", es.internal_transactions(chain, address, limit=RECENT_LIMIT)
        )
    if chain.blocklist_tokens:
        calls["blocked"] = c.run(BLOCKLIST_SOURCE, blocklisted_by(services, chain, address))
    data: dict[str, Any] = dict(zip(calls, await asyncio.gather(*calls.values()), strict=True))
    balance, nonce, code, security = (
        data["balance"],
        data["nonce"],
        data["code"],
        data["security"],
    )

    known = labels.lookup(chain.key, address)
    profile = WalletProfile(
        chain=chain.key,
        address=address,
        native_symbol=chain.native_symbol,
        native_balance=wei_to_coin(balance) if balance is not None else None,
        transactions_sent=nonce,
        is_contract=is_contract_code(code) if code is not None else None,
        delegated_to=delegation_target(code),
        known_label=known,
        security_flags=goplus_flags(security),
        blocklisted_by=data.get("blocked") or [],
    )
    profile.findings.extend(address_findings(address, security, known))
    profile.findings.extend(blocklist_findings(chain, profile.blocklisted_by))
    if profile.delegated_to:
        profile.findings.append(
            Finding(
                id="wallet.delegated_code",
                severity="info",
                title="Wallet runs delegated code (EIP-7702)",
                detail=f"This wallet has chosen to run the code at {profile.delegated_to}. It is "
                "still controlled by its private key. Delegating to an unknown contract can be "
                "risky for the wallet's own owner, so check what that code does.",
                source="RPC",
            )
        )

    history_ok = not c.failed("Etherscan")
    if history_ok:
        recent_txs = list(data["recent"] or [])
        oldest_txs = list(data["oldest"] or [])
        token_txs = list(data["token_txs"] or [])
        if logs_native_moves:
            native_recent = list(data["native_recent"] or [])
            native_oldest = list(data["native_oldest"] or [])
            profile.activity = _activity(
                address, recent_txs, oldest_txs, now, native_recent, native_oldest
            )
            profile.top_counterparties = _counterparties(
                chain, address, without_value(recent_txs), native_recent
            )
            profile.recent_tokens = [
                *_native_token_activity(chain, address, native_recent),
                *_tokens(address, other_tokens(chain, token_txs)),
            ][:TOP_TOKENS]
            funder = _first_funder(address, native_oldest)
            profile.notes.append(arc_history_note(chain))
        else:
            profile.activity = _activity(address, recent_txs, oldest_txs, now)
            profile.top_counterparties = _counterparties(
                chain, address, recent_txs, list(data["internal"] or [])
            )
            profile.recent_tokens = _tokens(address, token_txs)
            funder = _first_funder(address, oldest_txs)
        if funder:
            profile.first_funded_by = funder
            funder_label = labels.lookup(chain.key, funder)
            profile.first_funded_by_label = funder_label.name if funder_label else None
        profile.findings.extend(_history_findings(chain, profile))
    else:
        profile.data_gaps.append(
            "Transaction history (age, counterparties, activity) could not be checked. "
            f"Reason: {c.error('Etherscan')}"
        )

    if c.failed("GoPlus"):
        profile.data_gaps.append(
            f"Security labels from GoPlus are missing. Reason: {c.error('GoPlus')}"
        )
    if c.failed("RPC"):
        profile.data_gaps.append(f"Balance and contract check failed. Reason: {c.error('RPC')}")
    if c.failed(BLOCKLIST_SOURCE):
        names = " and ".join(symbol for symbol, _ in chain.blocklist_tokens)
        profile.data_gaps.append(
            f"The {names} blocklists could not be read. Reason: {c.error(BLOCKLIST_SOURCE)}"
        )
    if profile.is_contract:
        profile.data_gaps.append(
            "This address is a smart contract, not a personal wallet. "
            "Use inspect_contract (or check_token_risk for a token) for a deeper look."
        )

    profile.sources = c.statuses
    return profile


def _activity(
    address: str,
    recent: list[dict[str, Any]],
    oldest: list[dict[str, Any]],
    now: datetime,
    native_recent: list[dict[str, Any]] = (),
    native_oldest: list[dict[str, Any]] = (),
) -> ActivityPattern:
    """Age and habits of a wallet, from its normal transactions.

    On Arc, a wallet can receive USDC without ever being the target of a
    transaction (for example an ERC-20 transfer or a bridge mint), so the
    first and last dates also look at the USDC Transfer stream.
    """
    firsts = [from_unix(rows[0].get("timeStamp")) for rows in (oldest, native_oldest) if rows]
    lasts = [from_unix(rows[0].get("timeStamp")) for rows in (recent, native_recent) if rows]
    first_seen = min((t for t in firsts if t), default=None)
    last_seen = max((t for t in lasts if t), default=None)
    pattern = ActivityPattern(
        first_seen=first_seen,
        last_seen=last_seen,
        age_days=days_between(first_seen, now),
        days_since_last_activity=days_between(last_seen, now),
        sample_size=len(recent),
        sample_is_complete=len(recent) < RECENT_LIMIT,
    )
    if not recent:
        return pattern
    times = [t for t in (from_unix(tx.get("timeStamp")) for tx in recent) if t]
    total = len(recent)
    pattern.active_days_in_sample = len({t.date() for t in times})
    pattern.outgoing_share = round(
        sum(1 for tx in recent if tx.get("from", "").lower() == address) / total, 2
    )
    pattern.contract_call_share = round(
        sum(1 for tx in recent if (tx.get("input") or "0x") != "0x") / total, 2
    )
    pattern.failed_share = round(sum(1 for tx in recent if tx.get("isError") == "1") / total, 2)
    if times:
        pattern.busiest_hour_utc = Counter(t.hour for t in times).most_common(1)[0][0]
    return pattern


def _counterparties(
    chain: Chain,
    address: str,
    txs: list[dict[str, Any]],
    internal: list[dict[str, Any]],
) -> list[Counterparty]:
    stats: dict[str, dict[str, float]] = defaultdict(
        lambda: {"count": 0, "sent": 0.0, "received": 0.0}
    )
    for tx in [*txs, *internal]:
        sender = (tx.get("from") or "").lower()
        receiver = (tx.get("to") or tx.get("contractAddress") or "").lower()
        value = wei_to_coin(tx.get("value"))
        if sender == address and receiver:
            stats[receiver]["count"] += 1
            stats[receiver]["sent"] += value
        elif receiver == address and sender:
            stats[sender]["count"] += 1
            stats[sender]["received"] += value

    ranked = sorted(
        stats.items(),
        key=lambda item: (item[1]["count"], item[1]["sent"] + item[1]["received"]),
        reverse=True,
    )
    result = []
    for other, s in ranked[:TOP_COUNTERPARTIES]:
        label = labels.lookup(chain.key, other)
        result.append(
            Counterparty(
                address=other,
                tx_count=int(s["count"]),
                sent_to_them=round(s["sent"], 6),
                received_from_them=round(s["received"], 6),
                label=label.name if label else None,
                label_category=label.category if label else None,
            )
        )
    # Risky counterparties matter even if they are not in the top list.
    shown = {cp.address for cp in result}
    for other, s in ranked[TOP_COUNTERPARTIES:]:
        label = labels.lookup(chain.key, other)
        if labels.is_risky(label) and other not in shown:
            result.append(
                Counterparty(
                    address=other,
                    tx_count=int(s["count"]),
                    sent_to_them=round(s["sent"], 6),
                    received_from_them=round(s["received"], 6),
                    label=label.name,
                    label_category=label.category,
                )
            )
    return result


def _tokens(address: str, transfers: list[dict[str, Any]]) -> list[TokenActivity]:
    counts: dict[str, dict[str, Any]] = {}
    for tx in transfers:
        token = (tx.get("contractAddress") or "").lower()
        if not token:
            continue
        entry = counts.setdefault(
            token, {"symbol": tx.get("tokenSymbol") or "?", "in": 0, "out": 0}
        )
        if (tx.get("to") or "").lower() == address:
            entry["in"] += 1
        else:
            entry["out"] += 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1]["in"] + kv[1]["out"], reverse=True)
    return [
        TokenActivity(token=t, symbol=e["symbol"], transfers_in=e["in"], transfers_out=e["out"])
        for t, e in ranked[:TOP_TOKENS]
    ]


def _native_token_activity(
    chain: Chain, address: str, native: list[dict[str, Any]]
) -> list[TokenActivity]:
    """One row for USDC on Arc, counted from the system Transfer stream."""
    if not native or not chain.native_erc20:
        return []
    incoming = sum(1 for tx in native if (tx.get("to") or "").lower() == address)
    return [
        TokenActivity(
            token=chain.native_erc20,
            symbol=chain.native_symbol,
            transfers_in=incoming,
            transfers_out=len(native) - incoming,
        )
    ]


def _first_funder(address: str, oldest: list[dict[str, Any]]) -> str | None:
    """The sender of the first transaction that brought coins into this address."""
    for tx in oldest:
        if (tx.get("to") or "").lower() == address and int(tx.get("value") or 0) > 0:
            return (tx.get("from") or "").lower() or None
    return None


def _history_findings(chain: Chain, profile: WalletProfile) -> list[Finding]:
    findings: list[Finding] = []
    activity = profile.activity
    age = activity.age_days if activity else None

    if activity and activity.first_seen is None and not profile.transactions_sent:
        findings.append(
            Finding(
                id="wallet.no_history",
                severity="low",
                title="No transaction history",
                detail="This address has never sent or received a normal transaction.",
                source="Etherscan",
            )
        )
    elif age is not None and age < 7:
        findings.append(
            Finding(
                id="wallet.very_new",
                severity="medium",
                title="Very new wallet",
                detail=f"The first transaction was only {age} days ago. "
                "Scammers often use fresh wallets that have no track record.",
                source="Etherscan",
            )
        )
    elif age is not None and age < 30:
        findings.append(
            Finding(
                id="wallet.new",
                severity="low",
                title="New wallet",
                detail=f"The first transaction was {age} days ago.",
                source="Etherscan",
            )
        )

    if profile.first_funded_by_label:
        label = labels.lookup(chain.key, profile.first_funded_by or "")
        if labels.is_risky(label):
            findings.append(
                Finding(
                    id="wallet.funded_by_risky",
                    severity="high",
                    title="First funded by a risky source",
                    detail=f"The wallet's first coins came from {label.name} ({label.category}).",
                    source="Etherscan + local list",
                )
            )

    risky = [
        cp for cp in profile.top_counterparties if cp.label_category in labels.RISKY_CATEGORIES
    ]
    if risky:
        names = ", ".join(sorted({cp.label or cp.address for cp in risky}))
        findings.append(
            Finding(
                id="wallet.risky_counterparty",
                severity="high",
                title="Direct dealings with risky addresses",
                detail=f"Recent transactions went to or came from: {names}.",
                source="Etherscan + local list",
            )
        )

    if activity and activity.sample_size >= 10 and (activity.failed_share or 0) > 0.3:
        findings.append(
            Finding(
                id="wallet.many_failed_txs",
                severity="low",
                title="Many failed transactions",
                detail=f"{int((activity.failed_share or 0) * 100)}% of recent transactions failed. "
                "This can point to a bot or to repeated attempts to use a broken contract.",
                source="Etherscan",
            )
        )

    if age is not None and age > 365 and (profile.transactions_sent or 0) >= 100:
        findings.append(
            Finding(
                id="wallet.established",
                severity="info",
                title="Long, active history",
                detail=f"Active for {int(age)} days with {profile.transactions_sent} sent "
                "transactions. An old, busy wallet is less likely to be a throwaway scam wallet.",
                source="Etherscan + RPC",
            )
        )
    return findings
