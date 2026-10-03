"""The blockchains this server supports.

All of them are EVM chains. EVM means "Ethereum Virtual Machine": the same
kind of smart contracts and addresses work on all of them.

Arc is Circle's own chain. It works like Ethereum, with a few differences
that matter for a risk check:

- Its native coin, used to pay fees, is USDC. The native balance has 18
  decimals. The same balance can also be used through an ERC-20 token
  contract at 0x3600...0000, which shows it with 6 decimals. They are one
  balance seen two ways, so we never add them up.
- Every USDC move (plain sends, ERC-20 transfers, mints and burns) is
  logged as a Transfer event by a "system emitter" address (EIP-7708). We
  read that one stream, so each move is counted once and none is missed.
- The USDC and EURC contracts keep a blocklist that anyone can read. A
  transfer to or from a blocked address fails, and still costs the fee.
"""

import re
from dataclasses import dataclass

from web3_risk_mcp.errors import InvalidInputError

# Arc mainnet addresses, from https://docs.arc.io/arc/references/contract-addresses
ARC_USDC = "0x3600000000000000000000000000000000000000"
ARC_EURC = "0xbef5f6d51cb62b58e6a8f77868681825c6fe21c1"
ARC_SYSTEM_EMITTER = "0xfffffffffffffffffffffffffffffffffffffffe"


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
    # Arc only: the address that logs every native coin move as a Transfer
    # event (EIP-7708). None on chains where plain sends leave no log.
    native_transfer_emitter: str | None = None
    # Arc only: the ERC-20 contract that shows the native coin balance.
    native_erc20: str | None = None
    # Stablecoin contracts with a public blocklist we can read: (symbol, address).
    blocklist_tokens: tuple[tuple[str, str], ...] = ()


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
    "arc": Chain(
        key="arc",
        name="Arc",
        chain_id=5042,
        native_symbol="USDC",
        dexscreener_id="arc",
        default_rpc_url="https://rpc.mainnet.arc.io",
        explorer_url="https://explorer.arc.io",
        etherscan_free_history=True,
        native_transfer_emitter=ARC_SYSTEM_EMITTER,
        native_erc20=ARC_USDC,
        blocklist_tokens=(("USDC", ARC_USDC), ("EURC", ARC_EURC)),
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
    "arc mainnet": "arc",
    "arc-mainnet": "arc",
    "5042": "arc",
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
