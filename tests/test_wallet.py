from datetime import UTC, datetime

import respx

from tests.mocks import etherscan_error, mock_etherscan, mock_goplus_address, mock_rpc
from web3_risk_mcp.analysis.wallet import get_wallet_profile
from web3_risk_mcp.chains import get_chain

ETH = get_chain("ethereum")
BASE = get_chain("base")
ME = "0x" + "11" * 20
FRIEND = "0x" + "22" * 20
SHOP = "0x" + "33" * 20
TORNADO = "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc"
NOW = datetime(2026, 9, 1, tzinfo=UTC)
DAY = 86400


def tx(frm, to, *, days_ago, value=10**18, error="0", data="0x"):
    ts = int(NOW.timestamp()) - int(days_ago * DAY)
    return {
        "from": frm,
        "to": to,
        "value": str(value),
        "timeStamp": str(ts),
        "isError": error,
        "input": data,
    }


def rpc_handlers(balance="0xde0b6b3a7640000", nonce="0x96", code="0x"):
    return {"eth_getBalance": balance, "eth_getTransactionCount": nonce, "eth_getCode": code}


@respx.mock
async def test_established_wallet_profile(services):
    history = [tx(ME, SHOP, days_ago=d, value=10**17, data="0xa9059cbb") for d in range(1, 41)]
    history += [tx(FRIEND, ME, days_ago=500)]
    mock_etherscan(
        {
            "txlist": lambda p: history if p["sort"] == "desc" else list(reversed(history)),
            "tokentx": [
                {"contractAddress": "0xusdc", "tokenSymbol": "USDC", "to": ME, "from": FRIEND},
                {"contractAddress": "0xusdc", "tokenSymbol": "USDC", "to": SHOP, "from": ME},
            ],
        }
    )
    mock_rpc(ETH, rpc_handlers())
    mock_goplus_address({"cybercrime": "0", "mixer": "0"})

    profile = await get_wallet_profile(services, ETH, ME, now=NOW)

    assert profile.native_balance == 1.0
    assert profile.transactions_sent == 150
    assert profile.is_contract is False
    assert profile.activity.age_days == 500
    assert profile.activity.contract_call_share > 0.9
    assert profile.first_funded_by == FRIEND
    assert profile.top_counterparties[0].address == SHOP
    assert profile.top_counterparties[0].tx_count == 40
    assert profile.recent_tokens[0].symbol == "USDC"
    assert [f.id for f in profile.findings] == ["wallet.established"]
    assert all(s.ok for s in profile.sources)
    assert profile.data_gaps == []


@respx.mock
async def test_new_wallet_funded_by_mixer_is_flagged(services):
    history = [tx(TORNADO, ME, days_ago=2), tx(ME, SHOP, days_ago=1)]
    mock_etherscan(
        {"txlist": lambda p: list(reversed(history)) if p["sort"] == "desc" else history}
    )
    mock_rpc(ETH, rpc_handlers(nonce="0x1"))
    mock_goplus_address({})

    profile = await get_wallet_profile(services, ETH, ME, now=NOW)
    ids = {f.id for f in profile.findings}

    assert {"wallet.very_new", "wallet.funded_by_risky", "wallet.risky_counterparty"} <= ids
    assert profile.first_funded_by_label == "Tornado Cash: 0.1 ETH pool"


@respx.mock
async def test_goplus_flags_become_findings(services):
    mock_etherscan({})
    mock_rpc(ETH, rpc_handlers(nonce="0x0"))
    mock_goplus_address({"phishing_activities": "1", "number_of_malicious_contracts_created": "3"})

    profile = await get_wallet_profile(services, ETH, ME, now=NOW)
    ids = {f.id for f in profile.findings}

    assert profile.security_flags == ["phishing_activities"]
    assert {"address.phishing_activities", "address.malicious_contracts_created"} <= ids
    assert "wallet.no_history" in ids


@respx.mock
async def test_missing_history_on_paid_chain_still_returns_rpc_data(services):
    mock_etherscan({"txlist": etherscan_error("Free API access is not supported for this chain.")})
    mock_rpc(BASE, rpc_handlers())
    mock_goplus_address({})

    profile = await get_wallet_profile(services, BASE, ME, now=NOW)

    assert profile.native_balance == 1.0
    assert profile.activity is None
    etherscan_status = next(s for s in profile.sources if s.source == "Etherscan")
    assert etherscan_status.ok is False
    assert "Transaction history" in profile.data_gaps[0]
    assert "free plan" in profile.data_gaps[0]


@respx.mock
async def test_contract_address_gets_a_hint(services):
    mock_etherscan({})
    mock_rpc(ETH, rpc_handlers(code="0x6080"))
    mock_goplus_address({})

    profile = await get_wallet_profile(services, ETH, ME, now=NOW)

    assert profile.is_contract is True
    assert any("inspect_contract" in gap for gap in profile.data_gaps)
