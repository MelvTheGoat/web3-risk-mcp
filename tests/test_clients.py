import json

import httpx
import pytest
import respx

from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.clients import etherscan, goplus
from web3_risk_mcp.clients.rpc import slot_to_address
from web3_risk_mcp.errors import SourceError

ETH = get_chain("ethereum")
BASE = get_chain("base")
ADDR = "0x" + "ab" * 20


# --- Etherscan ---------------------------------------------------------------


@respx.mock
async def test_etherscan_sends_chain_id_and_key(services):
    route = respx.get(etherscan.BASE_URL).mock(
        return_value=httpx.Response(
            200, json={"status": "1", "message": "OK", "result": [{"hash": "0x1"}]}
        )
    )
    txs = await services.etherscan.transactions(BASE, ADDR, limit=10)
    assert txs == [{"hash": "0x1"}]
    params = route.calls.last.request.url.params
    assert params["chainid"] == "8453"
    assert params["apikey"] == "TESTKEY"
    assert params["action"] == "txlist"
    assert params["offset"] == "10"


@respx.mock
async def test_etherscan_no_transactions_is_empty_not_error(services):
    respx.get(etherscan.BASE_URL).mock(
        return_value=httpx.Response(
            200, json={"status": "0", "message": "No transactions found", "result": []}
        )
    )
    assert await services.etherscan.transactions(ETH, ADDR) == []


@respx.mock
async def test_etherscan_paid_chain_error_is_explained(services):
    respx.get(etherscan.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "0",
                "message": "NOTOK",
                "result": (
                    "Free API access is not supported for this chain. "
                    "Please upgrade your api plan for full chain coverage."
                ),
            },
        )
    )
    with pytest.raises(SourceError, match="free plan leaves out account history"):
        await services.etherscan.transactions(BASE, ADDR)


@respx.mock
async def test_etherscan_rate_limit_is_retried(services):
    route = respx.get(etherscan.BASE_URL).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "status": "0",
                    "message": "NOTOK",
                    "result": "Max calls per sec rate limit reached (3/sec)",
                },
            ),
            httpx.Response(200, json={"status": "1", "message": "OK", "result": []}),
        ]
    )
    assert await services.etherscan.token_transfers(ETH, ADDR) == []
    assert route.call_count == 2


@respx.mock
async def test_etherscan_bad_key_is_explained(services):
    respx.get(etherscan.BASE_URL).mock(
        return_value=httpx.Response(
            200, json={"status": "0", "message": "NOTOK", "result": "Invalid API Key"}
        )
    )
    with pytest.raises(SourceError, match="ETHERSCAN_API_KEY"):
        await services.etherscan.source_code(ETH, ADDR)


async def test_etherscan_missing_key_fails_fast_without_network(services):
    services.etherscan.api_key = None
    with pytest.raises(SourceError, match="No API key set"):
        await services.etherscan.transactions(ETH, ADDR)


@respx.mock
async def test_etherscan_source_code_returns_first_item(services):
    respx.get(etherscan.BASE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "1",
                "message": "OK",
                "result": [{"ContractName": "Token", "SourceCode": "x"}],
            },
        )
    )
    assert (await services.etherscan.source_code(ETH, ADDR))["ContractName"] == "Token"


# --- GoPlus -------------------------------------------------------------------


@respx.mock
async def test_goplus_token_security_finds_result_by_address(services):
    respx.get(f"{goplus.BASE_URL}/token_security/1").mock(
        return_value=httpx.Response(
            200, json={"code": 1, "message": "OK", "result": {ADDR: {"is_honeypot": "1"}}}
        )
    )
    report = await services.goplus.token_security(ETH, ADDR.upper().replace("0X", "0x"))
    assert report == {"is_honeypot": "1"}


@respx.mock
async def test_goplus_token_security_returns_none_when_unknown(services):
    respx.get(f"{goplus.BASE_URL}/token_security/1").mock(
        return_value=httpx.Response(200, json={"code": 1, "message": "OK", "result": {}})
    )
    assert await services.goplus.token_security(ETH, ADDR) is None


@respx.mock
async def test_goplus_error_code_becomes_source_error(services):
    respx.get(f"{goplus.BASE_URL}/address_security/{ADDR}").mock(
        return_value=httpx.Response(200, json={"code": 4012, "message": "bad chain"})
    )
    with pytest.raises(SourceError, match="code 4012"):
        await services.goplus.address_security(ETH, ADDR)


@respx.mock
async def test_goplus_uses_signed_access_token_when_keys_set(services):
    services.goplus.app_key = "k"
    services.goplus.app_secret = "s"
    token_route = respx.post(f"{goplus.BASE_URL}/token").mock(
        return_value=httpx.Response(
            200, json={"code": 1, "result": {"access_token": "TOKEN", "expires_in": 7200}}
        )
    )
    data_route = respx.get(f"{goplus.BASE_URL}/address_security/{ADDR}").mock(
        return_value=httpx.Response(200, json={"code": 1, "result": {"mixer": "0"}})
    )
    await services.goplus.address_security(ETH, ADDR)
    sent = json.loads(token_route.calls.last.request.content)
    assert sent["sign"] == goplus.sign("k", "s", sent["time"])
    assert data_route.calls.last.request.headers["Authorization"] == "TOKEN"


def test_goplus_sign_matches_documented_formula():
    import hashlib

    assert goplus.sign("key", "secret", 123) == hashlib.sha1(b"key123secret").hexdigest()


# --- DexScreener --------------------------------------------------------------


@respx.mock
async def test_dexscreener_filters_pairs_to_requested_chain(services):
    respx.get(f"https://api.dexscreener.com/tokens/v1/ethereum/{ADDR}").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"chainId": "ethereum", "pairAddress": "0x1"},
                {"chainId": "bsc", "pairAddress": "0x2"},
            ],
        )
    )
    pairs = await services.dexscreener.token_pairs(ETH, ADDR)
    assert [p["pairAddress"] for p in pairs] == ["0x1"]


# --- RPC ----------------------------------------------------------------------


@respx.mock
async def test_rpc_balance_and_code(services):
    def reply(request):
        method = json.loads(request.content)["method"]
        result = {"eth_getBalance": "0xde0b6b3a7640000", "eth_getCode": "0x"}[method]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    respx.post(ETH.default_rpc_url).mock(side_effect=reply)
    assert await services.rpc.balance(ETH, ADDR) == 10**18
    assert await services.rpc.code(ETH, ADDR) == "0x"


@respx.mock
async def test_rpc_uses_custom_url_from_settings(services):
    services.settings.rpc_url_base = "https://my-node.example/rpc"
    route = respx.post("https://my-node.example/rpc").mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x5"})
    )
    assert await services.rpc.nonce(BASE, ADDR) == 5
    assert route.called


@respx.mock
async def test_rpc_error_is_reported(services):
    respx.post(ETH.default_rpc_url).mock(
        return_value=httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32000, "message": "execution reverted"},
            },
        )
    )
    with pytest.raises(SourceError, match="execution reverted"):
        await services.rpc.eth_call(ETH, ADDR, "0x8da5cb5b")


async def test_rpc_refuses_write_methods(services):
    with pytest.raises(SourceError, match="read-only"):
        await services.rpc.call(ETH, "eth_sendRawTransaction", ["0x00"])


def test_slot_to_address():
    slot = "0x000000000000000000000000" + "cd" * 20
    assert slot_to_address(slot) == "0x" + "cd" * 20
    assert slot_to_address("0x" + "0" * 64) is None
