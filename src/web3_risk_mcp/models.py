"""Data models for everything the tools return.

Every report shares the same frame: which chain and address it is about,
which data sources answered, and a list of findings. A finding is one
observation, such as "the owner can mint new tokens", with a severity.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class SourceStatus(BaseModel):
    """Did one data source answer? If not, why?"""

    source: str
    ok: bool
    error: str | None = None


class Finding(BaseModel):
    """One observation about the address, with a stable ID used by the scorer."""

    id: str = Field(description="Stable ID, for example 'token.honeypot'.")
    severity: Severity
    title: str
    detail: str
    source: str = Field(description="Where the evidence came from.")


class Report(BaseModel):
    chain: str
    address: str
    findings: list[Finding] = Field(default_factory=list)
    sources: list[SourceStatus] = Field(default_factory=list)
    data_gaps: list[str] = Field(
        default_factory=list,
        description="What we could not check. Missing data is not proof of safety.",
    )


# --- Wallet ------------------------------------------------------------------


class KnownLabel(BaseModel):
    """A label from the local list of well-known addresses."""

    name: str
    category: Literal["mixer", "sanctioned", "exploit", "scam", "burn", "exchange", "protocol"]
    note: str | None = None


class Counterparty(BaseModel):
    address: str
    tx_count: int
    sent_to_them: float = Field(description="Native coin sent to this address, in whole coins.")
    received_from_them: float
    label: str | None = None
    label_category: str | None = None


class ActivityPattern(BaseModel):
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    age_days: float | None = None
    days_since_last_activity: float | None = None
    sample_size: int = Field(description="How many recent transactions the pattern is based on.")
    sample_is_complete: bool = Field(description="True if the sample covers the full history.")
    active_days_in_sample: int = 0
    outgoing_share: float | None = Field(None, description="Share of sample sent by this address.")
    contract_call_share: float | None = Field(None, description="Share that called a contract.")
    failed_share: float | None = Field(None, description="Share of transactions that failed.")
    busiest_hour_utc: int | None = None


class TokenActivity(BaseModel):
    token: str
    symbol: str
    transfers_in: int
    transfers_out: int


class WalletProfile(Report):
    is_contract: bool | None = None
    native_symbol: str
    native_balance: float | None = None
    transactions_sent: int | None = Field(
        None, description="Exact number of transactions this address has sent (its nonce)."
    )
    first_funded_by: str | None = None
    first_funded_by_label: str | None = None
    known_label: KnownLabel | None = None
    security_flags: list[str] = Field(
        default_factory=list, description="Bad-behaviour labels reported by GoPlus."
    )
    activity: ActivityPattern | None = None
    top_counterparties: list[Counterparty] = Field(default_factory=list)
    recent_tokens: list[TokenActivity] = Field(default_factory=list)


# --- Token -------------------------------------------------------------------


class TokenPowers(BaseModel):
    """Special powers written into the token contract. None means unknown."""

    can_mint: bool | None = Field(None, description="Someone can create new tokens.")
    can_blacklist: bool | None = Field(None, description="Someone can block wallets from trading.")
    can_pause_transfers: bool | None = None
    owner_can_change_balances: bool | None = None
    has_hidden_owner: bool | None = None
    can_take_back_ownership: bool | None = None
    can_self_destruct: bool | None = None
    has_whitelist: bool | None = None
    has_trading_cooldown: bool | None = None
    tax_can_change: bool | None = None
    per_wallet_tax_can_change: bool | None = None


class TaxInfo(BaseModel):
    """Fees charged on each trade, in percent. 10 means 10%."""

    buy_tax_pct: float | None = None
    sell_tax_pct: float | None = None
    transfer_tax_pct: float | None = None


class Holder(BaseModel):
    address: str
    percent: float
    is_contract: bool | None = None
    is_locked: bool | None = None
    tag: str | None = None
    excluded_from_concentration: str | None = Field(
        None, description="Why this holder does not count toward concentration, if it does not."
    )


class LiquidityPool(BaseModel):
    dex: str
    pair_address: str
    paired_with: str | None = None
    liquidity_usd: float | None = None
    volume_24h_usd: float | None = None
    buys_24h: int | None = None
    sells_24h: int | None = None
    created_at: datetime | None = None
    age_days: float | None = None
    url: str | None = None


class TokenRiskReport(Report):
    name: str | None = None
    symbol: str | None = None
    holder_count: int | None = None
    is_honeypot: bool | None = Field(
        None, description="True if the token can be bought but not sold."
    )
    is_open_source: bool | None = None
    is_proxy: bool | None = None
    owner_address: str | None = None
    owner_renounced: bool | None = Field(
        None, description="True if the owner gave up control by setting it to a dead address."
    )
    creator_address: str | None = None
    powers: TokenPowers = Field(default_factory=TokenPowers)
    taxes: TaxInfo = Field(default_factory=TaxInfo)
    top_holders: list[Holder] = Field(default_factory=list)
    top10_holder_pct: float | None = Field(
        None,
        description="Top 10 wallets' share, not counting burn, locked, or pool addresses.",
    )
    owner_pct: float | None = None
    creator_pct: float | None = None
    liquidity_usd: float | None = None
    lp_locked_pct: float | None = Field(
        None,
        description="Share of pool (LP) tokens locked or burned, so liquidity cannot be pulled.",
    )
    pools: list[LiquidityPool] = Field(default_factory=list)
    on_trust_list: bool | None = None


# --- Contract ----------------------------------------------------------------


class RiskyFunction(BaseModel):
    name: str
    category: str
    severity: Severity
    explanation: str
    found_by: Literal["verified source", "bytecode scan"]


class ProxyInfo(BaseModel):
    """A proxy is a contract that forwards calls to another "implementation"
    contract. Whoever controls the proxy can swap the implementation, which
    means they can change what the contract does."""

    is_proxy: bool = False
    implementation: str | None = None
    admin: str | None = None
    admin_controlled_by: str | None = None
    implementation_verified: bool | None = None


class Controller(BaseModel):
    """Who controls a contract, and what kind of account that is."""

    address: str | None = None
    kind: Literal["none", "renounced", "wallet", "multisig", "contract", "unknown"] = "unknown"
    multisig_threshold: int | None = Field(None, description="Signatures needed, for a multisig.")


class ContractReport(Report):
    is_contract: bool | None = None
    verified: bool | None = None
    contract_name: str | None = None
    compiler_version: str | None = None
    license: str | None = None
    bytecode_size_bytes: int | None = None
    creator: str | None = None
    creation_tx: str | None = None
    created_at: datetime | None = None
    owner: Controller = Field(default_factory=Controller)
    proxy: ProxyInfo = Field(default_factory=ProxyInfo)
    risky_functions: list[RiskyFunction] = Field(default_factory=list)
    summary: str = ""


# --- Fund tracing ------------------------------------------------------------


class FlowEdge(BaseModel):
    """Money that moved between two addresses in the sampled history."""

    from_address: str
    to_address: str
    transfers: int = Field(description="Number of transfers that carried value.")
    native_value: float = Field(description="Native coin moved, in whole coins.")
    token_transfers: int = 0
    hop: int


class TraceNode(BaseModel):
    address: str
    hop: int
    label: str | None = None
    label_category: str | None = None
    security_flags: list[str] = Field(default_factory=list)
    expanded: bool = False
    note: str | None = None


class RiskyLink(BaseModel):
    address: str
    hop: int
    relation: str = Field(description="How it connects, e.g. 'sent funds to the address'.")
    reason: str
    path: list[str] = Field(description="Addresses from the start address to this one.")


class FundTrace(Report):
    native_symbol: str
    hops: int
    direction: Literal["in", "out", "both"]
    nodes: list[TraceNode] = Field(default_factory=list)
    edges: list[FlowEdge] = Field(default_factory=list)
    risky_links: list[RiskyLink] = Field(default_factory=list)
