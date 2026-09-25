"""Token risk check: can you sell it, who controls it, and is there real liquidity?"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from web3_risk_mcp import labels
from web3_risk_mcp.analysis.common import Collector, days_between, flag, to_float
from web3_risk_mcp.chains import Chain
from web3_risk_mcp.models import (
    Finding,
    Holder,
    LiquidityPool,
    Severity,
    TaxInfo,
    TokenPowers,
    TokenRiskReport,
)
from web3_risk_mcp.services import Services

DEAD_OWNERS = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

# GoPlus flag -> (finding id, severity, title, plain explanation).
# These are the "powers" that let a token owner hurt holders.
_POWER_FLAGS: list[tuple[str, str, Severity, str, str]] = [
    (
        "owner_change_balance",
        "token.owner_can_change_balance",
        "critical",
        "Owner can change balances",
        "The owner can edit anyone's balance, for example set yours to zero.",
    ),
    (
        "hidden_owner",
        "token.hidden_owner",
        "high",
        "Hidden owner",
        "The contract has an owner-like role that is hidden from normal checks.",
    ),
    (
        "can_take_back_ownership",
        "token.can_take_back_ownership",
        "high",
        "Ownership can be taken back",
        "Even if ownership looks given up, the creator can reclaim it.",
    ),
    (
        "selfdestruct",
        "token.selfdestruct",
        "high",
        "Can self-destruct",
        "The contract can delete itself, which would make the token useless.",
    ),
    (
        "personal_slippage_modifiable",
        "token.per_wallet_tax",
        "high",
        "Tax can be set per wallet",
        "The owner can set a special tax for chosen wallets, for example 100% on yours.",
    ),
    (
        "slippage_modifiable",
        "token.tax_modifiable",
        "medium",
        "Tax can be changed",
        "The owner can raise the buy or sell tax at any time.",
    ),
    (
        "transfer_pausable",
        "token.transfer_pausable",
        "medium",
        "Transfers can be paused",
        "The owner can freeze all trading.",
    ),
    (
        "is_blacklisted",
        "token.blacklist",
        "medium",
        "Has a blacklist",
        "The owner can block chosen wallets from selling or moving tokens.",
    ),
    (
        "is_whitelisted",
        "token.whitelist",
        "low",
        "Has a whitelist",
        "Some wallets get special treatment, such as trading when others cannot.",
    ),
    (
        "trading_cooldown",
        "token.trading_cooldown",
        "low",
        "Trading cooldown",
        "Wallets must wait between trades. This can stop you selling quickly.",
    ),
    (
        "anti_whale_modifiable",
        "token.anti_whale_modifiable",
        "low",
        "Trade size limit can change",
        "The owner can change the maximum trade size, possibly to block sells.",
    ),
    (
        "external_call",
        "token.external_call",
        "low",
        "Calls other contracts on transfer",
        "Transfers call out to other contracts, which can change behaviour later.",
    ),
]


async def check_token_risk(
    services: Services, chain: Chain, token: str, *, now: datetime | None = None
) -> TokenRiskReport:
    now = now or datetime.now(UTC)
    c = Collector()
    security, pairs = await asyncio.gather(
        c.run("GoPlus", services.goplus.token_security(chain, token)),
        c.run("DexScreener", services.dexscreener.token_pairs(chain, token)),
    )

    report = TokenRiskReport(chain=chain.key, address=token)
    pools = _pools(token, pairs or [], now)
    report.pools = pools
    if pairs is not None:
        report.liquidity_usd = round(sum(p.liquidity_usd or 0 for p in pools), 2)
        if pairs:
            base = next(
                (
                    p["baseToken"]
                    for p in pairs
                    if _same(p.get("baseToken", {}).get("address"), token)
                ),
                None,
            )
            if base:
                report.name, report.symbol = base.get("name"), base.get("symbol")

    if security:
        _apply_goplus(report, security, {p.pair_address for p in pools})
    elif not c.failed("GoPlus"):
        report.data_gaps.append(
            "GoPlus has no security data for this address. It may not be a token, "
            "or it may be too new to have been scanned."
        )

    report.findings.extend(_liquidity_findings(report, pairs is not None, security))

    for name in ("GoPlus", "DexScreener"):
        if c.failed(name):
            what = "Contract security checks" if name == "GoPlus" else "Liquidity and pool data"
            report.data_gaps.append(f"{what} could not be loaded. Reason: {c.error(name)}")

    report.sources = c.statuses
    return report


def _same(a: str | None, b: str) -> bool:
    return bool(a) and a.lower() == b.lower()


def _pools(token: str, pairs: list[dict[str, Any]], now: datetime) -> list[LiquidityPool]:
    pools = []
    for p in pairs:
        base, quote = p.get("baseToken") or {}, p.get("quoteToken") or {}
        other = quote if _same(base.get("address"), token) else base
        created_ms = p.get("pairCreatedAt")
        created = datetime.fromtimestamp(created_ms / 1000, tz=UTC) if created_ms else None
        h24 = (p.get("txns") or {}).get("h24") or {}
        pools.append(
            LiquidityPool(
                dex=p.get("dexId") or "unknown",
                pair_address=(p.get("pairAddress") or "").lower(),
                paired_with=other.get("symbol"),
                liquidity_usd=to_float((p.get("liquidity") or {}).get("usd")),
                volume_24h_usd=to_float((p.get("volume") or {}).get("h24")),
                buys_24h=h24.get("buys"),
                sells_24h=h24.get("sells"),
                created_at=created,
                age_days=days_between(created, now),
                url=p.get("url"),
            )
        )
    pools.sort(key=lambda pool: pool.liquidity_usd or 0, reverse=True)
    return pools


def _pct(value: object) -> float | None:
    """GoPlus gives shares as fractions ("0.05"). Turn them into percent (5.0)."""
    number = to_float(value)
    return round(number * 100, 2) if number is not None else None


def _opt_flag(data: dict[str, Any], key: str) -> bool | None:
    value = data.get(key)
    if value in (None, ""):
        return None
    return flag(value)


def _apply_goplus(report: TokenRiskReport, data: dict[str, Any], pool_addresses: set[str]) -> None:
    report.name = report.name or data.get("token_name")
    report.symbol = report.symbol or data.get("token_symbol")
    report.holder_count = int(data["holder_count"]) if data.get("holder_count") else None
    report.is_honeypot = _opt_flag(data, "is_honeypot")
    report.is_open_source = _opt_flag(data, "is_open_source")
    report.is_proxy = _opt_flag(data, "is_proxy")
    report.on_trust_list = _opt_flag(data, "trust_list")

    owner = (data.get("owner_address") or "").lower()
    report.owner_address = owner or None
    report.owner_renounced = owner in DEAD_OWNERS if owner else None
    report.creator_address = (data.get("creator_address") or "").lower() or None
    report.owner_pct = _pct(data.get("owner_percent"))
    report.creator_pct = _pct(data.get("creator_percent"))

    report.powers = TokenPowers(
        can_mint=_opt_flag(data, "is_mintable"),
        can_blacklist=_opt_flag(data, "is_blacklisted"),
        can_pause_transfers=_opt_flag(data, "transfer_pausable"),
        owner_can_change_balances=_opt_flag(data, "owner_change_balance"),
        has_hidden_owner=_opt_flag(data, "hidden_owner"),
        can_take_back_ownership=_opt_flag(data, "can_take_back_ownership"),
        can_self_destruct=_opt_flag(data, "selfdestruct"),
        has_whitelist=_opt_flag(data, "is_whitelisted"),
        has_trading_cooldown=_opt_flag(data, "trading_cooldown"),
        tax_can_change=_opt_flag(data, "slippage_modifiable"),
        per_wallet_tax_can_change=_opt_flag(data, "personal_slippage_modifiable"),
    )
    report.taxes = TaxInfo(
        buy_tax_pct=_pct(data.get("buy_tax")),
        sell_tax_pct=_pct(data.get("sell_tax")),
        transfer_tax_pct=_pct(data.get("transfer_tax")),
    )

    # Pool addresses GoPlus knows about count as pools too.
    pool_addresses = pool_addresses | {
        (d.get("pair") or "").lower() for d in data.get("dex") or [] if d.get("pair")
    }
    report.top_holders = _holders(report.chain, data.get("holders") or [], pool_addresses)
    counted = [h.percent for h in report.top_holders if not h.excluded_from_concentration]
    report.top10_holder_pct = round(sum(counted[:10]), 2) if report.top_holders else None

    lp_holders = data.get("lp_holders") or []
    if lp_holders:
        locked = sum(
            (_pct(h.get("percent")) or 0)
            for h in lp_holders
            if flag(h.get("is_locked")) or (h.get("address") or "").lower() in DEAD_OWNERS
        )
        report.lp_locked_pct = round(min(locked, 100.0), 2)

    report.findings.extend(_goplus_findings(report, data))


def _holders(chain_key: str, raw: list[dict[str, Any]], pools: set[str]) -> list[Holder]:
    holders = []
    for h in raw:
        address = (h.get("address") or "").lower()
        known = labels.lookup(chain_key, address)
        reason = None
        if address in DEAD_OWNERS or (known and known.category == "burn"):
            reason = "burn address"
        elif flag(h.get("is_locked")):
            reason = "locked"
        elif address in pools:
            reason = "liquidity pool"
        holders.append(
            Holder(
                address=address,
                percent=_pct(h.get("percent")) or 0.0,
                is_contract=_opt_flag(h, "is_contract"),
                is_locked=_opt_flag(h, "is_locked"),
                tag=h.get("tag") or None,
                excluded_from_concentration=reason,
            )
        )
    holders.sort(key=lambda h: h.percent, reverse=True)
    return holders[:20]


def _finding(fid: str, severity: Severity, title: str, detail: str) -> Finding:
    return Finding(id=fid, severity=severity, title=title, detail=detail, source="GoPlus")


def _goplus_findings(report: TokenRiskReport, data: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    if report.is_honeypot:
        out.append(
            _finding(
                "token.honeypot",
                "critical",
                "Honeypot: you may not be able to sell",
                "A test sale failed. Buyers of this token are likely unable to sell it.",
            )
        )
    if flag(data.get("cannot_sell_all")):
        out.append(
            _finding(
                "token.cannot_sell_all",
                "high",
                "Cannot sell everything",
                "Holders cannot sell their full balance in one go.",
            )
        )
    if flag(data.get("cannot_buy")):
        out.append(_finding("token.cannot_buy", "medium", "Cannot be bought", "Buying is blocked."))
    if flag(data.get("is_airdrop_scam")):
        out.append(
            _finding(
                "token.airdrop_scam",
                "critical",
                "Airdrop scam",
                "This token is sent out for free to lure people to a scam site.",
            )
        )
    if data.get("is_true_token") == "0" or flag(data.get("fake_token")):
        out.append(
            _finding(
                "token.fake_token",
                "critical",
                "Fake token",
                "This copies the name of a well-known token but is not the real one.",
            )
        )
    if flag(data.get("honeypot_with_same_creator")):
        out.append(
            _finding(
                "token.creator_made_honeypots",
                "high",
                "Creator made honeypots before",
                "The same creator deployed other tokens that turned out to be honeypots.",
            )
        )
    if report.is_open_source is False:
        out.append(
            _finding(
                "token.not_open_source",
                "high",
                "Source code not verified",
                "Nobody can read what this contract really does.",
            )
        )
    if report.is_proxy:
        out.append(
            _finding(
                "token.proxy",
                "medium",
                "Upgradeable (proxy) contract",
                "The owner can swap the contract's code for new code at any time.",
            )
        )

    if report.powers.can_mint:
        renounced = report.owner_renounced is True
        out.append(
            _finding(
                "token.mintable_renounced" if renounced else "token.mintable",
                "low" if renounced else "medium",
                "Supply can be increased",
                "New tokens can be created, which dilutes holders."
                + (" The owner is renounced, which lowers the risk." if renounced else ""),
            )
        )
    for key, fid, severity, title, detail in _POWER_FLAGS:
        if flag(data.get(key)):
            out.append(_finding(fid, severity, title, detail))

    sell, buy = report.taxes.sell_tax_pct, report.taxes.buy_tax_pct
    if sell is not None and sell >= 50:
        out.append(
            _finding(
                "token.extreme_sell_tax",
                "critical",
                "Extreme sell tax",
                f"Selling costs {sell}% of the amount. You would lose most of your money.",
            )
        )
    elif sell is not None and sell >= 10:
        out.append(
            _finding("token.high_sell_tax", "medium", "High sell tax", f"Selling costs {sell}%.")
        )
    if buy is not None and buy >= 10:
        out.append(
            _finding("token.high_buy_tax", "medium", "High buy tax", f"Buying costs {buy}%.")
        )

    top10 = report.top10_holder_pct
    if top10 is not None and top10 >= 80:
        out.append(
            _finding(
                "token.extreme_concentration",
                "high",
                "Very few wallets own almost everything",
                f"The top 10 wallets hold {top10}% of the supply. They could crash the price.",
            )
        )
    elif top10 is not None and top10 >= 50:
        out.append(
            _finding(
                "token.high_concentration",
                "medium",
                "Supply is concentrated",
                f"The top 10 wallets hold {top10}% of the supply.",
            )
        )
    insider = (report.owner_pct or 0) + (report.creator_pct or 0)
    if insider >= 20:
        out.append(
            _finding(
                "token.insider_holds_large_share",
                "medium",
                "Owner or creator holds a large share",
                f"The owner and creator together hold {round(insider, 2)}% of the supply.",
            )
        )
    if report.on_trust_list:
        out.append(
            _finding(
                "token.trusted",
                "info",
                "On GoPlus trust list",
                "GoPlus lists this as a well-known, trusted token.",
            )
        )
    notes = [data.get("other_potential_risks"), data.get("note")]
    for text in filter(None, notes):
        out.append(_finding("token.goplus_note", "info", "Note from GoPlus", str(text)))
    return out


def _liquidity_findings(
    report: TokenRiskReport, have_dex_data: bool, security: dict[str, Any] | None
) -> list[Finding]:
    out: list[Finding] = []
    if not have_dex_data:
        return out
    pools = report.pools
    source = "DexScreener"
    in_dex = flag((security or {}).get("is_in_dex"))
    if not pools and not in_dex:
        if security:  # Only a finding if we know this is a token.
            out.append(
                Finding(
                    id="token.no_liquidity",
                    severity="high",
                    title="No trading pool found",
                    detail="There is no DEX pool for this token, so it may be impossible to sell.",
                    source=source,
                )
            )
        return out
    if report.liquidity_usd is not None and pools and report.liquidity_usd < 10_000:
        out.append(
            Finding(
                id="token.low_liquidity",
                severity="medium",
                title="Very little liquidity",
                detail=f"Only about ${report.liquidity_usd:,.0f} sits in trading pools. "
                "Prices can swing wildly and the pool is easy to drain.",
                source=source,
            )
        )
    if report.lp_locked_pct is not None and report.lp_locked_pct < 50 and not report.on_trust_list:
        out.append(
            Finding(
                id="token.liquidity_not_locked",
                severity="medium",
                title="Liquidity is not locked",
                detail=f"Only {report.lp_locked_pct}% of pool tokens are locked or burned. "
                "Whoever holds the rest can pull the liquidity (a 'rug pull').",
                source="GoPlus",
            )
        )
    main = pools[0] if pools else None
    if main and main.age_days is not None and not report.on_trust_list:
        if main.age_days < 1:
            out.append(
                Finding(
                    id="token.very_new_pool",
                    severity="medium",
                    title="Pool is less than a day old",
                    detail="Most rug pulls happen in the first hours or days of trading.",
                    source=source,
                )
            )
        elif main.age_days < 7:
            out.append(
                Finding(
                    id="token.new_pool",
                    severity="low",
                    title="Pool is less than a week old",
                    detail=f"The main pool was created {main.age_days} days ago.",
                    source=source,
                )
            )
    if main and (main.buys_24h or 0) >= 20 and (main.sells_24h or 0) == 0:
        out.append(
            Finding(
                id="token.no_sells",
                severity="high",
                title="Many buys but no sells",
                detail=f"{main.buys_24h} buys and zero sells in the last 24 hours. "
                "This is a classic honeypot pattern.",
                source=source,
            )
        )
    return out
