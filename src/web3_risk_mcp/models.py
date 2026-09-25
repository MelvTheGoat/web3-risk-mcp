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
