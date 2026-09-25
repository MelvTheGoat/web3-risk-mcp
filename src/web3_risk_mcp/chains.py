"""The blockchains this server supports.

All of them are EVM chains. EVM means "Ethereum Virtual Machine": the same
kind of smart contracts and addresses work on all of them.
"""

import re
from dataclasses import dataclass

from web3_risk_mcp.errors import InvalidInputError


@dataclass(frozen=True)
class Chain:
    """Everything we need to know to talk about one chain."""

    key: str
    name: str
    chain_id: int
    native_symbol: str
    dexscreener_id: str
    default_rpc_url: str
    explorer_url: str
    # Etherscan's free plan does not include account history on every chain.
    etherscan_free_history: bool


CHAINS: dict[str, Chain] = {
    "ethereum": Chain(
        key="ethereum",
        name="Ethereum",
        chain_id=1,
        native_symbol="ETH",
        dexscreener_id="ethereum",
        default_rpc_url="https://ethereum-rpc.publicnode.com",
        explorer_url="https://etherscan.io",
        etherscan_free_history=True,
    ),
    "base": Chain(
        key="base",
        name="Base",
        chain_id=8453,
        native_symbol="ETH",
        dexscreener_id="base",
        default_rpc_url="https://base-rpc.publicnode.com",
        explorer_url="https://basescan.org",
        etherscan_free_history=False,
    ),
    "arbitrum": Chain(
        key="arbitrum",
        name="Arbitrum One",
        chain_id=42161,
        native_symbol="ETH",
        dexscreener_id="arbitrum",
        default_rpc_url="https://arbitrum-one-rpc.publicnode.com",
        explorer_url="https://arbiscan.io",
        etherscan_free_history=True,
    ),
    "polygon": Chain(
        key="polygon",
        name="Polygon PoS",
        chain_id=137,
        native_symbol="POL",
        dexscreener_id="polygon",
        default_rpc_url="https://polygon-bor-rpc.publicnode.com",
        explorer_url="https://polygonscan.com",
        etherscan_free_history=True,
    ),
    "bsc": Chain(
        key="bsc",
        name="BNB Chain",
        chain_id=56,
        native_symbol="BNB",
        dexscreener_id="bsc",
        default_rpc_url="https://bsc-rpc.publicnode.com",
        explorer_url="https://bscscan.com",
        etherscan_free_history=False,
    ),
}

# Other names people use for the same chains.
_ALIASES: dict[str, str] = {
    "eth": "ethereum",
    "mainnet": "ethereum",
    "1": "ethereum",
    "8453": "base",
    "arb": "arbitrum",
    "arbitrum one": "arbitrum",
    "arbitrum-one": "arbitrum",
    "42161": "arbitrum",
    "matic": "polygon",
    "pol": "polygon",
    "137": "polygon",
    "bnb": "bsc",
    "bnb chain": "bsc",
    "bnb-chain": "bsc",
    "binance": "bsc",
    "binance smart chain": "bsc",
    "56": "bsc",
}

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def get_chain(name: str | int) -> Chain:
    """Find a chain by name, alias, or chain ID.

    Raises InvalidInputError with the list of valid names if it is unknown.
    """
    key = str(name).strip().lower()
    key = _ALIASES.get(key, key)
    chain = CHAINS.get(key)
    if chain is None:
        valid = ", ".join(CHAINS)
        raise InvalidInputError(f"Unknown chain '{name}'. Use one of: {valid}.")
    return chain


def normalize_address(address: str) -> str:
    """Check that a string looks like an EVM address and return it in lower case.

    An EVM address is "0x" followed by 40 hex characters (0-9, a-f).
    """
    cleaned = address.strip()
    if not _ADDRESS_RE.match(cleaned):
        raise InvalidInputError(
            f"'{address}' is not a valid address. "
            "An address starts with 0x and has 40 hex characters after it."
        )
    return cleaned.lower()
