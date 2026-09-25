"""Client for the DexScreener API.

A DEX (decentralized exchange) is a smart contract where people trade tokens
without a company in the middle. A trading "pair" (or pool) holds two tokens,
for example PEPE and WETH. The money in the pool is its "liquidity". Low
liquidity means big price swings and makes it easy to drain the pool.

DexScreener tracks pairs on many DEXes. No key is needed.

Docs: https://docs.dexscreener.com/api/reference
"""

from __future__ import annotations

from typing import Any

from web3_risk_mcp.chains import Chain
from web3_risk_mcp.clients.http import HttpSource

BASE_URL = "https://api.dexscreener.com"
NAME = "DexScreener"


class DexScreenerClient:
    """Read-only calls to DexScreener."""

    def __init__(self, http: HttpSource) -> None:
        self.http = http

    async def token_pairs(self, chain: Chain, token: str) -> list[dict[str, Any]]:
        """All trading pairs that include this token on this chain.

        Uses GET /tokens/v1/{chainId}/{tokenAddresses} (limit: 300 requests per minute).
        """
        body = await self.http.request_json(
            "GET", f"{BASE_URL}/tokens/v1/{chain.dexscreener_id}/{token}"
        )
        if isinstance(body, list):
            pairs = body
        elif isinstance(body, dict):
            # Older endpoints wrap the list in {"pairs": [...]}.
            pairs = body.get("pairs") or []
        else:
            pairs = []
        return [
            p for p in pairs if isinstance(p, dict) and p.get("chainId") == chain.dexscreener_id
        ]
