import pytest

from web3_risk_mcp import labels
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
        ("arc", "arc"),
        ("Arc Mainnet", "arc"),
        (5042, "arc"),
    ],
)
def test_get_chain_accepts_names_aliases_and_ids(name, expected):
    assert get_chain(name).key == expected


def test_get_chain_rejects_unknown_chain_with_helpful_message():
    with pytest.raises(InvalidInputError, match="Use one of: ethereum, base"):
        get_chain("solana")


def test_all_six_chains_are_supported():
    assert set(CHAINS) == {"ethereum", "base", "arbitrum", "polygon", "bsc", "arc"}


def test_arc_uses_usdc_as_native_coin_and_logs_native_moves():
    arc = get_chain("arc")
    assert arc.chain_id == 5042
    assert arc.native_symbol == "USDC"
    assert arc.native_transfer_emitter == "0x" + "f" * 39 + "e"
    assert arc.native_erc20 == "0x36" + "0" * 38
    assert [symbol for symbol, _ in arc.blocklist_tokens] == ["USDC", "EURC"]
    # Every address in the table is stored in lower case, so lookups match.
    for _, token in arc.blocklist_tokens:
        assert token == token.lower()


def test_other_chains_have_no_arc_only_settings():
    for key in ("ethereum", "base", "arbitrum", "polygon", "bsc"):
        chain = get_chain(key)
        assert chain.native_transfer_emitter is None
        assert chain.blocklist_tokens == ()


def test_normalize_address_lowercases_valid_address():
    addr = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    assert normalize_address(f"  {addr} ") == addr.lower()


@pytest.mark.parametrize("bad", ["", "0x123", "vitalik.eth", "0x" + "g" * 40, "a0" * 21])
def test_normalize_address_rejects_bad_input(bad):
    with pytest.raises(InvalidInputError, match="not a valid address"):
        normalize_address(bad)


def test_arc_system_contracts_are_labelled_so_traces_skip_them():
    usdc = labels.lookup("arc", "0x3600000000000000000000000000000000000000")
    assert usdc.category == "protocol"
    minter = labels.lookup("arc", "0xfd78ee919681417d192449715b2594ab58f5d002")
    assert minter.name == "Circle CCTP: TokenMinterV2"
    # On Arc the zero address means "USDC was minted or burned", not "burn address".
    assert labels.lookup("arc", "0x" + "0" * 40).name == "USDC mint or burn (Arc)"
    assert labels.lookup("ethereum", "0x" + "0" * 40).name == "Null address"
