from datetime import UTC, datetime

import httpx
import respx

from tests.mocks import (
    etherscan_error,
    mock_dexscreener,
    mock_etherscan,
    mock_goplus_address,
    mock_goplus_token,
    mock_rpc,
)
from web3_risk_mcp.analysis.score import score_risk
from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.clients import goplus

ETH = get_chain("ethereum")
TOKEN = "0x" + "aa" * 20
WALLET = "0x" + "11" * 20
NOW = datetime(2026, 9, 1, tzinfo=UTC)


@respx.mock
async def test_honeypot_token_scores_critical(services):
    mock_rpc(ETH, {"eth_getCode": "0x6080", "eth_getStorageAt": "0x" + "0" * 64})
    mock_goplus_token(ETH, TOKEN, {"is_honeypot": "1", "is_open_source": "0", "sell_tax": "1"})
    mock_dexscreener(ETH, TOKEN, [])
    mock_goplus_address({})
    mock_etherscan(
        {"getsourcecode": [{"SourceCode": "", "ABI": "Contract source code not verified"}]}
    )

    result = await score_risk(services, ETH, TOKEN, now=NOW)

    assert result.address_type == "token"
    assert result.level == "critical"
    assert result.score >= 75
    assert set(result.checks_run) == {"check_token_risk", "inspect_contract", "address_labels"}
    counted = {c.finding_id for c in result.contributions if c.counted}
    assert {"token.honeypot", "token.extreme_sell_tax"} <= counted
    # Unverified source appears twice but counts once.
    unverified = [
        c
        for c in result.contributions
        if c.finding_id in ("token.not_open_source", "contract.unverified")
    ]
    assert sum(c.counted for c in unverified) == 1


@respx.mock
async def test_clean_wallet_scores_low(services):
    old = str(int(NOW.timestamp()) - 800 * 86400)
    friend = "0x" + "22" * 20
    mock_rpc(
        ETH, {"eth_getCode": "0x", "eth_getBalance": "0x0", "eth_getTransactionCount": "0x200"}
    )
    mock_etherscan(
        {
            "txlist": [
                {
                    "from": friend,
                    "to": WALLET,
                    "value": "1",
                    "timeStamp": old,
                    "isError": "0",
                    "input": "0x",
                }
            ]
        }
    )
    mock_goplus_address({})

    result = await score_risk(services, ETH, WALLET, now=NOW)

    assert result.address_type == "wallet"
    assert result.score == 0
    assert result.level == "low"
    assert result.confidence == "high"
    assert [c.finding_id for c in result.contributions] == ["wallet.established"]


@respx.mock
async def test_missing_sources_lower_confidence_not_score(services):
    mock_rpc(ETH, {"eth_getCode": "0x", "eth_getBalance": "0x0", "eth_getTransactionCount": "0x0"})
    mock_etherscan({"txlist": etherscan_error("Invalid API Key")})
    respx.get(url__regex=rf"{goplus.BASE_URL}/address_security/.*").mock(
        return_value=httpx.Response(503)
    )

    result = await score_risk(services, ETH, WALLET, include_trace=False, now=NOW)

    assert result.confidence == "low"
    assert result.data_gaps
    assert "may be higher" in result.verdict
