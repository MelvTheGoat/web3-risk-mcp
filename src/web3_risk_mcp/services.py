"""Builds every data-source client from the settings.

One `Services` object is created when the server starts and closed when it
stops. All clients share one HTTP connection pool.
"""

from __future__ import annotations

import httpx

from web3_risk_mcp import __version__
from web3_risk_mcp.clients.dexscreener import DexScreenerClient
from web3_risk_mcp.clients.etherscan import EtherscanClient
from web3_risk_mcp.clients.goplus import GoPlusClient
from web3_risk_mcp.clients.http import HttpSource
from web3_risk_mcp.clients.rpc import RpcClient
from web3_risk_mcp.config import Settings


class Services:
    """All data-source clients in one place."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            timeout=settings.http_timeout_seconds,
            headers={"User-Agent": f"web3-risk-mcp/{__version__}"},
            follow_redirects=True,
        )

        def source(name: str, rps: float) -> HttpSource:
            return HttpSource(
                name,
                self.client,
                requests_per_second=rps,
                cache_ttl=settings.cache_ttl_seconds,
                max_retries=settings.http_max_retries,
            )

        self.etherscan = EtherscanClient(
            source("Etherscan", settings.etherscan_requests_per_second),
            Settings.secret(settings.etherscan_api_key),
        )
        self.goplus = GoPlusClient(
            source("GoPlus", settings.goplus_requests_per_second),
            Settings.secret(settings.goplus_app_key),
            Settings.secret(settings.goplus_app_secret),
        )
        self.dexscreener = DexScreenerClient(
            source("DexScreener", settings.dexscreener_requests_per_second)
        )
        self.rpc = RpcClient(source("RPC", settings.rpc_requests_per_second), settings)

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()
