"""Recorded Arc mainnet responses for the Arc tests.

The tests replay real answers from Etherscan, GoPlus, DexScreener and the Arc
RPC, saved in tests/fixtures/arc_cassette.json.gz, so they never touch the
network. The cassette never stores API keys.

To record the responses again (needs ETHERSCAN_API_KEY in .env):
    uv run python -m tests.arc_fixtures

To keep the saved responses and only add requests that are missing (for
example after adding a new check), so existing test numbers do not move:
    uv run python -m tests.arc_fixtures --add-missing
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

from web3_risk_mcp.analysis.score import score_risk
from web3_risk_mcp.analysis.trace import trace_funds
from web3_risk_mcp.analysis.wallet import get_wallet_profile
from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.config import Settings, get_settings
from web3_risk_mcp.evaluation import Cassette, RecordingTransport, request_key
from web3_risk_mcp.services import Services

CASSETTE = Path(__file__).resolve().parent / "fixtures" / "arc_cassette.json.gz"
ARC = get_chain("arc")
# The moment the responses were recorded. Tests use it as "now" so ages stay fixed.
RECORDED_AT = datetime(2026, 10, 3, 9, 0, tzinfo=UTC)

# A wallet that Circle's USDC and EURC contracts both block, and that GoPlus
# labels as sanctioned. It was put on the USDC blocklist in Arc block 512007.
BLOCKED_WALLET = "0x7f367cc41522ce07553e823bf3be79a889debe1b"
# An ordinary wallet that receives USDC and bridges it out through Circle's CCTP.
ACTIVE_WALLET = "0x415a44b7649405fb824c606b8e1781f3ff264b4f"
EURC = "0xbef5f6d51cb62b58e6a8f77868681825c6fe21c1"
USDC = "0x3600000000000000000000000000000000000000"


async def run_all(services: Services) -> None:
    """Every call the tests make. Recording runs exactly these."""
    await score_risk(services, ARC, BLOCKED_WALLET, now=RECORDED_AT)
    await score_risk(services, ARC, ACTIVE_WALLET, now=RECORDED_AT)
    await get_wallet_profile(services, ARC, ACTIVE_WALLET, now=RECORDED_AT)
    await trace_funds(services, ARC, ACTIVE_WALLET, hops=2)
    await score_risk(services, ARC, EURC, now=RECORDED_AT)
    await score_risk(services, ARC, USDC, now=RECORDED_AT)


class _AddMissingTransport(RecordingTransport):
    """Answers from the cassette when it can, and records only what is missing."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        entry = self.cassette.entries.get(request_key(request))
        if entry is not None:
            return httpx.Response(
                entry["status"],
                content=entry["body"].encode(),
                headers={"content-type": "application/json"},
            )
        return await super().handle_async_request(request)


async def _record(add_missing: bool) -> None:
    settings: Settings = get_settings()
    if not Settings.secret(settings.etherscan_api_key):
        raise SystemExit("Set ETHERSCAN_API_KEY in .env first.")
    cassette = Cassette(CASSETTE)
    before = len(cassette.entries)
    if not add_missing:
        cassette.entries = {}
    transport = (_AddMissingTransport if add_missing else RecordingTransport)(cassette)
    async with httpx.AsyncClient(transport=transport) as client:
        await run_all(Services(settings, client=client))
    cassette.save()
    added = len(cassette.entries) - (before if add_missing else 0)
    print(f"Saved {len(cassette.entries)} responses ({added} new) to {CASSETTE}")


if __name__ == "__main__":
    asyncio.run(_record(add_missing="--add-missing" in sys.argv))
