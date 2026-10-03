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

# isBlacklisted(address): the public read function on Circle's USDC and EURC
# contracts. It returns true if the address is on the token's blocklist.
IS_BLACKLISTED_SELECTOR = "0xfe575a87"

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


# A made-up sender used only inside simulations. eth_call never sends
# anything, and the balance we give it exists only inside that one call.
SIMULATION_SENDER = "0x000000000000000000000000000000000000beef"
_SIMULATION_BALANCE = hex(10**30)

# Node errors that mean "the transfer itself was refused", as opposed to the
# node being down or busy. Arc answers "Blocked address" for blocklisted
# addresses and "Zero address not allowed" for the zero address.
_REFUSAL_WORDS = ("revert", "blocked address", "not allowed")


def _validate_simulation(body: Any) -> None:
    """Like _validate, but a refused transfer is an answer, not a failure."""
    if not isinstance(body, dict):
        raise SourceError(NAME, "Unexpected response shape.")
    error = body.get("error")
    if not error:
        if "result" not in body:
            raise SourceError(NAME, "Node response has no result.")
        return
    message = str(error.get("message") if isinstance(error, dict) else error)
    if not any(word in message.lower() for word in _REFUSAL_WORDS):
        retryable = "rate" in message.lower() or "limit" in message.lower()
        raise SourceError(NAME, f"Node returned an error: {message}", retryable=retryable)


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


# EIP-7702 lets a normal wallet point at contract code it wants to run. Its
# code is then 0xef0100 followed by the 20-byte address it delegates to.
# The account is still a wallet controlled by a private key.
_DELEGATION_PREFIX = "0xef0100"


def delegation_target(code: str | None) -> str | None:
    """Return the address a wallet delegates to under EIP-7702, if any."""
    if code and code.lower().startswith(_DELEGATION_PREFIX) and len(code) == 48:
        return "0x" + code[8:].lower()
    return None


def is_contract_code(code: str) -> bool:
    """True if the code belongs to a real contract, not a wallet."""
    return code not in ("", "0x") and delegation_target(code) is None


class RpcClient:
    """Read-only JSON-RPC calls, one endpoint per chain."""

    def __init__(self, http: HttpSource, settings: Settings) -> None:
        self.http = http
        self.settings = settings

    def url_for(self, chain: Chain) -> str:
        return self.settings.rpc_override(chain.key) or chain.default_rpc_url

    async def _request(
        self, chain: Chain, method: str, params: list[Any], validate=_validate
    ) -> dict[str, Any]:
        if method not in READ_ONLY_METHODS:
            raise SourceError(NAME, f"Method {method} is not allowed. This server is read-only.")
        return await self.http.request_json(
            "POST",
            self.url_for(chain),
            json_body={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
            validate=validate,
        )

    async def call(self, chain: Chain, method: str, params: list[Any]) -> Any:
        return (await self._request(chain, method, params))["result"]

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

    async def simulate_transfer(self, chain: Chain, to: str, value_wei: int) -> str | None:
        """Pretend to send `value_wei` of the native coin to `to`. Nothing is sent.

        This is a plain eth_call from a made-up sender that is given a balance
        for this one call only (a "state override"). Returns None if the
        transfer would go through, or the node's reason if it would be refused.
        """
        body = await self._request(
            chain,
            "eth_call",
            [
                {"from": SIMULATION_SENDER, "to": to, "value": hex(value_wei)},
                "latest",
                {SIMULATION_SENDER: {"balance": _SIMULATION_BALANCE}},
            ],
            validate=_validate_simulation,
        )
        error = body.get("error")
        if not error:
            return None
        return str(error.get("message") if isinstance(error, dict) else error)

    async def is_blocklisted(self, chain: Chain, token: str, address: str) -> bool:
        """Ask a Circle stablecoin contract (USDC or EURC) if it blocks an address."""
        data = IS_BLACKLISTED_SELECTOR + address.lower().removeprefix("0x").rjust(64, "0")
        return hex_to_int(await self.eth_call(chain, token, data)) != 0
