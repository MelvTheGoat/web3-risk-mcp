from contextlib import asynccontextmanager

import httpx
import pytest
import respx
from mcp import Client

from tests.mocks import mock_etherscan, mock_goplus_address, mock_rpc
from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.server import create_server
from web3_risk_mcp.services import Services

ME = "0x" + "11" * 20


@pytest.fixture
def connect(settings):
    """Open an in-process MCP client. It must be opened inside the test itself,
    because the SDK's task groups must start and stop in the same task."""

    @asynccontextmanager
    async def _connect():
        async with httpx.AsyncClient() as http:
            server = create_server(lambda: Services(settings, client=http))
            async with Client(server) as client:
                yield client

    return _connect


async def test_tools_are_listed_and_marked_read_only(connect):
    async with connect() as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert {
            "get_wallet_profile",
            "check_token_risk",
            "inspect_contract",
            "list_supported_chains",
        } <= set(tools)
        for tool in tools.values():
            assert tool.annotations.read_only_hint is True
            assert tool.description


async def test_list_supported_chains(connect):
    async with connect() as client:
        result = await client.call_tool("list_supported_chains", {})
        keys = [c["key"] for c in result.structured_content["chains"]]
        assert keys == ["ethereum", "base", "arbitrum", "polygon", "bsc"]


async def test_bad_address_gives_clear_tool_error(connect):
    async with connect() as client:
        result = await client.call_tool("get_wallet_profile", {"address": "hello"})
        assert result.is_error
        assert "not a valid address" in result.content[0].text


async def test_unknown_chain_gives_clear_tool_error(connect):
    async with connect() as client:
        result = await client.call_tool("get_wallet_profile", {"address": ME, "chain": "solana"})
        assert result.is_error
        assert "Unknown chain" in result.content[0].text


@respx.mock
async def test_wallet_profile_through_mcp(connect):
    async with connect() as client:
        mock_etherscan({})
        mock_rpc(
            get_chain("ethereum"),
            {"eth_getBalance": "0x0", "eth_getTransactionCount": "0x0", "eth_getCode": "0x"},
        )
        mock_goplus_address({})
        result = await client.call_tool(
            "get_wallet_profile", {"address": ME.upper().replace("0X", "0x")}
        )
        assert not result.is_error
        assert result.structured_content["address"] == ME
        assert result.structured_content["native_symbol"] == "ETH"


async def test_scoring_method_resource(connect):
    async with connect() as client:
        resources = (await client.list_resources()).resources
        assert [str(r.uri) for r in resources] == ["risk://scoring-method"]
        result = await client.read_resource("risk://scoring-method")
        text = result.contents[0].text
        assert text.startswith("# How the risk score works")
        assert "`token.honeypot`" in text
