"""A catalog of risky functions, and a scanner that finds them.

A "function selector" is the first 4 bytes of the keccak-256 hash of a
function's signature, like `mint(address,uint256)`. Contracts use it to
decide which function to run. Because selectors are baked into the bytecode,
we can spot risky functions even when the source code is not published.
This is a heuristic: it can miss renamed functions, and very rarely a match
is a coincidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from Crypto.Hash import keccak

from web3_risk_mcp.models import Severity


def selector(signature: str) -> str:
    """Return the 4-byte selector for a signature, as 8 hex characters."""
    return keccak.new(digest_bits=256, data=signature.encode()).hexdigest()[:8]


@dataclass(frozen=True)
class RiskCategory:
    key: str
    severity: Severity
    explanation: str
    name_pattern: re.Pattern[str]
    signatures: tuple[str, ...]


CATEGORIES: tuple[RiskCategory, ...] = (
    RiskCategory(
        "balance_control",
        "critical",
        "Can directly set or wipe out someone's token balance.",
        re.compile(r"^(setbalance|updatebalance|changebalance|burnfrom_?admin)", re.I),
        ("setBalance(address,uint256)",),
    ),
    RiskCategory(
        "mint",
        "high",
        "Can create new tokens out of thin air, which dilutes every holder.",
        re.compile(r"^(mint|minttoken|mintto|_?issue)$", re.I),
        ("mint(address,uint256)", "mint(uint256)", "mintTo(address,uint256)"),
    ),
    RiskCategory(
        "blacklist",
        "high",
        "Can block chosen wallets from selling or moving tokens.",
        re.compile(r"(blacklist|blocklist|addbots?|setbots?|blockbots?|banaddress|isbot)", re.I),
        (
            "blacklist(address)",
            "addToBlacklist(address)",
            "setBlacklist(address,bool)",
            "blacklistAddress(address,bool)",
            "setBots(address[],bool)",
            "addBots(address[])",
        ),
    ),
    RiskCategory(
        "fees",
        "high",
        "Can change buy or sell fees, possibly up to 100%.",
        re.compile(r"^(set|update|change)\w*(fee|tax)", re.I),
        (
            "setFee(uint256)",
            "setFees(uint256,uint256)",
            "setTaxFeePercent(uint256)",
            "setBuyFee(uint256)",
            "setSellFee(uint256)",
            "updateFees(uint256,uint256)",
            "setTax(uint256)",
        ),
    ),
    RiskCategory(
        "pause",
        "medium",
        "Can freeze transfers or trading.",
        re.compile(r"^(pause|unpause|setpaused|settradingenabled|enabletrading|opentrading)", re.I),
        ("pause()", "unpause()", "setPaused(bool)", "enableTrading()", "openTrading()"),
    ),
    RiskCategory(
        "limits",
        "medium",
        "Can change the maximum trade or wallet size, which can be used to block sells.",
        re.compile(r"^(set|update)\w*max(tx|wallet|transaction|sell)", re.I),
        ("setMaxTxAmount(uint256)", "setMaxWalletSize(uint256)", "setMaxWallet(uint256)"),
    ),
    RiskCategory(
        "upgrade",
        "medium",
        "Can replace the contract's code with new code.",
        re.compile(r"^upgradeto", re.I),
        ("upgradeTo(address)", "upgradeToAndCall(address,bytes)"),
    ),
    RiskCategory(
        "withdraw",
        "medium",
        "Can move funds held by the contract out to an address the owner chooses.",
        re.compile(r"^(emergencywithdraw|withdrawall|rescue|sweep|drain|withdrawstuck)", re.I),
        ("emergencyWithdraw()", "withdrawAll()", "rescueTokens(address,uint256)", "sweep(address)"),
    ),
    RiskCategory(
        "ownership",
        "low",
        "Has an owner who can hand control to someone else.",
        re.compile(r"^(transferownership|renounceownership)$", re.I),
        ("transferOwnership(address)",),
    ),
)

_BY_SELECTOR: dict[str, tuple[RiskCategory, str]] = {
    selector(sig): (cat, sig) for cat in CATEGORIES for sig in cat.signatures
}


def scan_bytecode(bytecode: str) -> list[tuple[RiskCategory, str]]:
    """Find known risky selectors in bytecode.

    Solidity loads each selector with the PUSH4 opcode (0x63) followed by the
    4 bytes, so we look for "63" + selector.
    """
    code = bytecode.lower().removeprefix("0x")
    return [(cat, sig) for sel, (cat, sig) in _BY_SELECTOR.items() if f"63{sel}" in code]


def match_abi_name(name: str) -> RiskCategory | None:
    for cat in CATEGORIES:
        if cat.name_pattern.search(name):
            return cat
    return None
