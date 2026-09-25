"""Client for JSON-RPC endpoints.

An RPC endpoint is a server connected to the blockchain that answers direct
questions like "what is this address's balance?" or "what code lives at this
address?". Every EVM chain speaks the same JSON-RPC language.

This client only uses read methods. It never sends or signs transactions.
"""

from __future__ import annotations

from typing import Any

from web3_risk_mcp.chains import Chain
from web3_risk_mcp.clients.http import HttpSource
from web3_risk_mcp.config import Settings
from web3_risk_mcp.errors import SourceError

NAME = "RPC"

# Storage slots defined by EIP-1967, the standard for upgradeable "proxy"
# contracts. A proxy keeps the address of its real logic contract here.
EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

# Only these methods are allowed. This is a second safety net on top of the
# code simply never calling anything else.
READ_ONLY_METHODS = frozenset(
    {
        "eth_blockNumber",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_call",
        "eth_chainId",
    }
)


def _validate(body: Any) -> None:
    if not isinstance(body, dict):
        raise SourceError(NAME, "Unexpected response shape.")
    error = body.get("error")
    if error:
        message = error.get("message") if isinstance(error, dict) else str(error)
        retryable = "rate" in str(message).lower() or "limit" in str(message).lower()
        raise SourceError(NAME, f"Node returned an error: {message}", retryable=retryable)
    if "result" not in body:
        raise SourceError(NAME, "Node response has no result.")


def hex_to_int(value: str | None) -> int:
    if not value or value == "0x":
        return 0
    return int(value, 16)


def slot_to_address(value: str | None) -> str | None:
    """Storage slots are 32 bytes. An address is the last 20 bytes."""
    number = hex_to_int(value)
    if number == 0:
        return None
    return "0x" + f"{number:064x}"[-40:]


class RpcClient:
    """Read-only JSON-RPC calls, one endpoint per chain."""

    def __init__(self, http: HttpSource, settings: Settings) -> None:
        self.http = http
        self.settings = settings

    def url_for(self, chain: Chain) -> str:
        return self.settings.rpc_override(chain.key) or chain.default_rpc_url

    async def call(self, chain: Chain, method: str, params: list[Any]) -> Any:
        if method not in READ_ONLY_METHODS:
            raise SourceError(NAME, f"Method {method} is not allowed. This server is read-only.")
        body = await self.http.request_json(
            "POST",
            self.url_for(chain),
            json_body={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
            validate=_validate,
        )
        return body["result"]

    async def balance(self, chain: Chain, address: str) -> int:
        """Native coin balance in wei (1 ETH = 10^18 wei)."""
        return hex_to_int(await self.call(chain, "eth_getBalance", [address, "latest"]))

    async def nonce(self, chain: Chain, address: str) -> int:
        """How many transactions this address has sent."""
        return hex_to_int(await self.call(chain, "eth_getTransactionCount", [address, "latest"]))

    async def code(self, chain: Chain, address: str) -> str:
        """Contract bytecode. "0x" means the address is a normal wallet, not a contract."""
        return await self.call(chain, "eth_getCode", [address, "latest"]) or "0x"

    async def storage(self, chain: Chain, address: str, slot: str) -> str:
        return await self.call(chain, "eth_getStorageAt", [address, slot, "latest"])

    async def eth_call(self, chain: Chain, to: str, data: str) -> str:
        """Run a read-only function on a contract without creating a transaction."""
        return await self.call(chain, "eth_call", [{"to": to, "data": data}, "latest"])
