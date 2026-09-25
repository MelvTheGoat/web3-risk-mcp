import pytest

from web3_risk_mcp.chains import CHAINS, get_chain, normalize_address
from web3_risk_mcp.errors import InvalidInputError


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ethereum", "ethereum"),
        ("ETH", "ethereum"),
        (1, "ethereum"),
        ("base", "base"),
        ("arb", "arbitrum"),
        ("42161", "arbitrum"),
        ("matic", "polygon"),
        ("BNB Chain", "bsc"),
        ("56", "bsc"),
    ],
)
def test_get_chain_accepts_names_aliases_and_ids(name, expected):
    assert get_chain(name).key == expected


def test_get_chain_rejects_unknown_chain_with_helpful_message():
    with pytest.raises(InvalidInputError, match="Use one of: ethereum, base"):
        get_chain("solana")


def test_all_five_chains_are_supported():
    assert set(CHAINS) == {"ethereum", "base", "arbitrum", "polygon", "bsc"}


def test_normalize_address_lowercases_valid_address():
    addr = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    assert normalize_address(f"  {addr} ") == addr.lower()


@pytest.mark.parametrize("bad", ["", "0x123", "vitalik.eth", "0x" + "g" * 40, "a0" * 21])
def test_normalize_address_rejects_bad_input(bad):
    with pytest.raises(InvalidInputError, match="not a valid address"):
        normalize_address(bad)
