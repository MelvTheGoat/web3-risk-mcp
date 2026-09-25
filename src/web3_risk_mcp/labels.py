"""Lookup for the local list of well-known addresses (mixers, exploiters, burn addresses)."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from web3_risk_mcp.models import KnownLabel

# Categories that mean "stay away" as opposed to "just context".
RISKY_CATEGORIES = frozenset({"mixer", "sanctioned", "exploit", "scam"})


@lru_cache(maxsize=1)
def _load() -> dict[tuple[str, str], KnownLabel]:
    raw = json.loads(
        resources.files("web3_risk_mcp.data").joinpath("known_addresses.json").read_text()
    )
    table: dict[tuple[str, str], KnownLabel] = {}
    for entry in raw["addresses"]:
        label = KnownLabel(name=entry["name"], category=entry["category"], note=entry.get("note"))
        for chain in entry["chains"]:
            table[(chain, entry["address"].lower())] = label
    return table


def lookup(chain_key: str, address: str) -> KnownLabel | None:
    """Return the label for an address on a chain, or None if it is not on the list."""
    table = _load()
    address = address.lower()
    return table.get((chain_key, address)) or table.get(("*", address))


def is_risky(label: KnownLabel | None) -> bool:
    return label is not None and label.category in RISKY_CATEGORIES
