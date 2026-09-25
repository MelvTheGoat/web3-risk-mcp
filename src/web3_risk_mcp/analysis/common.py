"""Helpers shared by every analysis."""

from __future__ import annotations

import logging
from collections.abc import Awaitable
from datetime import UTC, datetime
from typing import TypeVar

from web3_risk_mcp.errors import SourceError
from web3_risk_mcp.models import SourceStatus

logger = logging.getLogger(__name__)

T = TypeVar("T")

WEI_PER_COIN = 10**18


class Collector:
    """Runs data-source calls and records which ones worked.

    A failing call returns None instead of raising. This is how one broken
    API never crashes a whole investigation: the report just says what is
    missing and why.
    """

    def __init__(self) -> None:
        self._status: dict[str, SourceStatus] = {}

    async def run(self, label: str, call: Awaitable[T]) -> T | None:
        try:
            result = await call
        except SourceError as exc:
            self._record(label, ok=False, error=exc.message)
            return None
        except Exception as exc:  # we must never crash the whole report
            logger.exception("Unexpected error in %s", label)
            self._record(label, ok=False, error=f"Unexpected error: {type(exc).__name__}: {exc}")
            return None
        self._record(label, ok=True)
        return result

    def _record(self, label: str, *, ok: bool, error: str | None = None) -> None:
        # If the same source is called twice, a failure wins over a success.
        existing = self._status.get(label)
        if existing is not None and not existing.ok:
            return
        self._status[label] = SourceStatus(source=label, ok=ok, error=error)

    def failed(self, label: str) -> bool:
        status = self._status.get(label)
        return status is not None and not status.ok

    def error(self, label: str) -> str | None:
        status = self._status.get(label)
        return status.error if status else None

    @property
    def statuses(self) -> list[SourceStatus]:
        return list(self._status.values())


def wei_to_coin(value: str | int | None) -> float:
    """Convert wei (the smallest unit) to whole coins. 1 ETH = 10^18 wei."""
    try:
        return int(value or 0) / WEI_PER_COIN
    except (TypeError, ValueError):
        return 0.0


def from_unix(value: str | int | None) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=UTC) if value else None
    except (TypeError, ValueError, OverflowError):
        return None


def days_between(start: datetime | None, end: datetime) -> float | None:
    if start is None:
        return None
    return round((end - start).total_seconds() / 86400, 1)


def flag(value: object) -> bool:
    """GoPlus sends booleans as the strings "1" and "0"."""
    return str(value).strip() == "1"


def to_float(value: object) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
