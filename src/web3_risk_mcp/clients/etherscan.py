"""Client for the Etherscan V2 API.

Etherscan is a "block explorer": a website and API that indexes everything on
a chain. Its V2 API uses one URL and one key for many chains. You pick the
chain with the `chainid` parameter.

Docs: https://docs.etherscan.io
"""

from __future__ import annotations

from typing import Any

from web3_risk_mcp.chains import Chain
from web3_risk_mcp.clients.http import HttpSource
from web3_risk_mcp.errors import SourceError

BASE_URL = "https://api.etherscan.io/v2/api"
NAME = "Etherscan"

# Etherscan answers with status "0" for both real errors and "nothing found".
# These messages mean "nothing found", which is a normal, empty answer.
_EMPTY_MESSAGES = ("no transactions found", "no records found", "no data found")


def _validate(body: Any) -> None:
    if not isinstance(body, dict) or "status" not in body:
        # Proxy-module calls (JSON-RPC style) have no status field.
        if isinstance(body, dict) and "error" in body:
            raise SourceError(NAME, f"Request failed: {body['error']}")
        return
    if str(body.get("status")) == "1":
        return
    message = str(body.get("message", ""))
    result = body.get("result")
    if message.lower().startswith(_EMPTY_MESSAGES) or result == []:
        return
    detail = str(result) if isinstance(result, str) else message
    lowered = detail.lower()
    if "rate limit" in lowered:
        raise SourceError(NAME, f"Rate limit reached: {detail}", retryable=True)
    if "invalid api key" in lowered or ("missing" in lowered and "key" in lowered):
        raise SourceError(NAME, "The API key was rejected. Check ETHERSCAN_API_KEY in your .env.")
    if "not supported for this chain" in lowered or "upgrade your api plan" in lowered:
        raise SourceError(
            NAME,
            "Your Etherscan plan does not cover this data on this chain. "
            "The free plan leaves out account history on Base and BNB Chain.",
        )
    raise SourceError(NAME, f"Request failed: {detail or 'unknown error'}")


class EtherscanClient:
    """Read-only calls to Etherscan. Every method is a GET request."""

    def __init__(self, http: HttpSource, api_key: str | None) -> None:
        self.http = http
        self.api_key = api_key

    async def _call(self, chain: Chain, params: dict[str, Any]) -> Any:
        if not self.api_key:
            raise SourceError(
                NAME,
                "No API key set. Add ETHERSCAN_API_KEY to your .env file. "
                "You can get a free key at https://etherscan.io/myapikey",
            )
        query = {"chainid": chain.chain_id, **params, "apikey": self.api_key}
        body = await self.http.request_json("GET", BASE_URL, params=query, validate=_validate)
        result = body.get("result") if isinstance(body, dict) else None
        return result if result is not None else []

    async def transactions(
        self, chain: Chain, address: str, *, sort: str = "desc", limit: int = 100
    ) -> list[dict[str, Any]]:
        """Normal transactions sent from or to the address (newest first by default)."""
        return await self._call(
            chain,
            {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 9999999999,
                "page": 1,
                "offset": limit,
                "sort": sort,
            },
        )

    async def internal_transactions(
        self, chain: Chain, address: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Value moved by contracts on the address's behalf ("internal" transactions)."""
        return await self._call(
            chain,
            {
                "module": "account",
                "action": "txlistinternal",
                "address": address,
                "startblock": 0,
                "endblock": 9999999999,
                "page": 1,
                "offset": limit,
                "sort": "desc",
            },
        )

    async def token_transfers(
        self, chain: Chain, address: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """ERC-20 token transfers in and out of the address (newest first)."""
        return await self._call(
            chain,
            {
                "module": "account",
                "action": "tokentx",
                "address": address,
                "startblock": 0,
                "endblock": 9999999999,
                "page": 1,
                "offset": limit,
                "sort": "desc",
            },
        )

    async def source_code(self, chain: Chain, address: str) -> dict[str, Any]:
        """Verified source code and ABI for a contract.

        "Verified" means the author published the source and Etherscan checked
        that it compiles to the code on chain. Unverified contracts come back
        with an empty SourceCode field.
        """
        result = await self._call(
            chain, {"module": "contract", "action": "getsourcecode", "address": address}
        )
        if isinstance(result, list) and result:
            return result[0]
        return {}

    async def contract_creation(self, chain: Chain, address: str) -> dict[str, Any] | None:
        """Who created a contract, and in which transaction."""
        result = await self._call(
            chain,
            {"module": "contract", "action": "getcontractcreation", "contractaddresses": address},
        )
        if isinstance(result, list) and result:
            return result[0]
        return None
