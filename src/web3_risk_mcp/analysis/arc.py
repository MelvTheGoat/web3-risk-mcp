"""Checks that only apply on Arc, where the native coin is USDC.

Two things are different on Arc (see chains.py for the details):

1. USDC has two views of one balance: native (18 decimals) and an ERC-20
   contract (6 decimals). Every USDC move is logged once by a system address
   at 18 decimals, and ERC-20 transfers are logged a second time by the USDC
   contract at 6 decimals. We read only the system stream, so each move is
   counted once, and we never mix the two decimal systems.
2. The USDC and EURC contracts keep a public blocklist. A transfer to or from
   a blocked address is refused, and the sender still pays the fee.

The helpers here are driven by the chain settings, so they do nothing on
chains without these features.
"""

from __future__ import annotations

import asyncio
from typing import Any

from web3_risk_mcp.chains import Chain
from web3_risk_mcp.models import Finding

BLOCKLIST_SOURCE = "Blocklist"


async def blocklisted_by(services, chain: Chain, address: str) -> list[str]:
    """Symbols of the stablecoins whose contract blocks this address. Empty if none.

    Circle's token contracts put their own address on their own blocklist, so
    nobody can send tokens to the contract by mistake. That is not a risk
    signal, so a token is never checked against its own list.
    """
    tokens = [(s, t) for s, t in chain.blocklist_tokens if t != address.lower()]
    if not tokens:
        return []
    answers = await asyncio.gather(
        *(services.rpc.is_blocklisted(chain, token, address) for _, token in tokens)
    )
    return [symbol for (symbol, _), blocked in zip(tokens, answers, strict=True) if blocked]


def blocklist_findings(chain: Chain, symbols: list[str]) -> list[Finding]:
    """One finding per stablecoin contract that blocks the address."""
    return [
        Finding(
            id=f"address.{symbol.lower()}_blocklisted",
            severity="critical",
            title=f"Blocked by the {symbol} contract",
            detail=f"Circle's {symbol} contract on {chain.name} has put this address on its "
            f"blocklist. Any {symbol} sent to or from it is refused, and the sender still pays "
            "the fee. Circle blocks addresses for reasons such as sanctions or court orders.",
            source=f"{symbol} contract (RPC)",
        )
        for symbol in symbols
    ]


def without_value(txs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only transactions that moved no native coin.

    On Arc, every value-carrying transaction is also in the system Transfer
    stream. Keeping only the zero-value ones (contract calls) means nothing is
    counted twice.
    """
    return [tx for tx in txs if int(tx.get("value") or 0) == 0]


def other_tokens(chain: Chain, transfers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Token transfers that are not USDC.

    Etherscan lists Arc's system Transfer logs as a token, and an ERC-20 USDC
    transfer also appears under the USDC contract. Both are already in the
    system stream, so they are removed here.
    """
    skip = {a for a in (chain.native_transfer_emitter, chain.native_erc20) if a}
    return [tx for tx in transfers if (tx.get("contractAddress") or "").lower() not in skip]


def arc_history_note(chain: Chain) -> str:
    return (
        f"On {chain.name}, USDC is the native coin. Amounts use the native 18-decimal "
        "value, not the 6-decimal ERC-20 view of the same balance. USDC moves are read "
        "from the system Transfer logs (EIP-7708), which include plain sends, ERC-20 "
        "transfers, payouts from contracts, bridge mints and burns. Each move is counted once."
    )
