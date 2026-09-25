from datetime import UTC, datetime

import httpx
import respx

from tests.mocks import mock_dexscreener, mock_goplus_token
from web3_risk_mcp.analysis.token import check_token_risk
from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.clients import goplus

ETH = get_chain("ethereum")
TOKEN = "0x" + "aa" * 20
PAIR = "0x" + "bb" * 20
OWNER = "0x" + "cc" * 20
NOW = datetime(2026, 9, 1, tzinfo=UTC)
NOW_MS = int(NOW.timestamp() * 1000)


def pair(*, liquidity=500_000, age_hours=24 * 400, buys=100, sells=90):
    return {
        "chainId": "ethereum",
        "dexId": "uniswap",
        "pairAddress": PAIR,
        "baseToken": {"address": TOKEN, "name": "Test Token", "symbol": "TEST"},
        "quoteToken": {"address": "0xweth", "symbol": "WETH"},
        "liquidity": {"usd": liquidity},
        "volume": {"h24": 1000},
        "txns": {"h24": {"buys": buys, "sells": sells}},
        "pairCreatedAt": NOW_MS - age_hours * 3600 * 1000,
        "url": "https://dexscreener.com/ethereum/x",
    }


SCAM = {
    "token_name": "Scam",
    "token_symbol": "SCAM",
    "is_open_source": "0",
    "is_honeypot": "1",
    "is_mintable": "1",
    "owner_address": OWNER,
    "owner_percent": "0.30",
    "creator_percent": "0",
    "buy_tax": "0.05",
    "sell_tax": "0.99",
    "slippage_modifiable": "1",
    "is_blacklisted": "1",
    "holder_count": "12",
    "is_in_dex": "1",
    "holders": [
        {"address": OWNER, "percent": "0.30", "is_locked": 0, "is_contract": 0},
        {"address": PAIR, "percent": "0.40", "is_locked": 0, "is_contract": 1},
        {"address": "0x" + "d1" * 20, "percent": "0.29", "is_locked": 0, "is_contract": 0},
    ],
    "lp_holders": [{"address": OWNER, "percent": "1.0", "is_locked": 0}],
}

SAFE = {
    "token_name": "Good",
    "token_symbol": "GOOD",
    "is_open_source": "1",
    "is_honeypot": "0",
    "is_mintable": "0",
    "owner_address": "",
    "buy_tax": "0",
    "sell_tax": "0",
    "trust_list": "1",
    "holder_count": "1000000",
    "is_in_dex": "1",
    "holders": [
        {"address": "0x000000000000000000000000000000000000dead", "percent": "0.5", "is_locked": 0},
        {"address": "0x" + "e1" * 20, "percent": "0.05", "is_locked": 0},
        {"address": "0x" + "e2" * 20, "percent": "0.10", "is_locked": 1},
    ],
    "lp_holders": [{"address": "0x" + "f1" * 20, "percent": "0.9", "is_locked": 1}],
}


@respx.mock
async def test_scam_token_raises_many_flags(services):
    mock_goplus_token(ETH, TOKEN, SCAM)
    mock_dexscreener(ETH, TOKEN, [pair(liquidity=3000, age_hours=5, buys=50, sells=0)])

    report = await check_token_risk(services, ETH, TOKEN, now=NOW)
    ids = {f.id for f in report.findings}

    assert report.is_honeypot is True
    assert report.taxes.sell_tax_pct == 99.0
    assert report.powers.can_mint and report.powers.can_blacklist
    assert report.owner_renounced is False
    assert {
        "token.honeypot",
        "token.not_open_source",
        "token.mintable",
        "token.extreme_sell_tax",
        "token.tax_modifiable",
        "token.blacklist",
        "token.insider_holds_large_share",
        "token.low_liquidity",
        "token.liquidity_not_locked",
        "token.very_new_pool",
        "token.no_sells",
    } <= ids
    # The pool's 40% does not count as concentration, the other two wallets do.
    assert report.top10_holder_pct == 59.0
    assert "token.high_concentration" in ids
    assert report.lp_locked_pct == 0.0


@respx.mock
async def test_well_known_token_is_clean(services):
    mock_goplus_token(ETH, TOKEN, SAFE)
    mock_dexscreener(ETH, TOKEN, [pair()])

    report = await check_token_risk(services, ETH, TOKEN, now=NOW)

    assert [f.id for f in report.findings] == ["token.trusted"]
    assert report.name == "Test Token"
    assert report.liquidity_usd == 500_000
    assert report.lp_locked_pct == 90.0
    # Burned and locked holders are excluded from the concentration figure.
    assert report.top10_holder_pct == 5.0
    reasons = {h.address[:6]: h.excluded_from_concentration for h in report.top_holders}
    assert reasons["0x0000"] == "burn address"
    assert reasons["0xe2e2"] == "locked"


@respx.mock
async def test_goplus_failure_still_returns_liquidity(services):
    respx.get(f"{goplus.BASE_URL}/token_security/1").mock(return_value=httpx.Response(500))
    mock_dexscreener(ETH, TOKEN, [pair()])

    report = await check_token_risk(services, ETH, TOKEN, now=NOW)

    assert report.liquidity_usd == 500_000
    assert report.is_honeypot is None
    assert any("Contract security checks could not be loaded" in g for g in report.data_gaps)
    status = {s.source: s.ok for s in report.sources}
    assert status == {"GoPlus": False, "DexScreener": True}


@respx.mock
async def test_unknown_address_says_it_may_not_be_a_token(services):
    mock_goplus_token(ETH, TOKEN, None)
    mock_dexscreener(ETH, TOKEN, [])

    report = await check_token_risk(services, ETH, TOKEN, now=NOW)

    assert report.findings == []
    assert "may not be a token" in report.data_gaps[0]


@respx.mock
async def test_token_with_no_pool_is_flagged(services):
    mock_goplus_token(ETH, TOKEN, {**SAFE, "trust_list": "0", "is_in_dex": "0"})
    mock_dexscreener(ETH, TOKEN, [])

    report = await check_token_risk(services, ETH, TOKEN, now=NOW)

    assert "token.no_liquidity" in {f.id for f in report.findings}
