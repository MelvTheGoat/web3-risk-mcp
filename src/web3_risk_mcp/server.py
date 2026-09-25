"""The MCP server: tools, resources, and prompts.

MCP (Model Context Protocol) is a standard way for AI assistants to call
outside tools. This file tells an assistant which tools exist, what inputs
they take, and what they return.

Every tool here is read-only. None of them can sign, send, or approve
anything, and none of them ever asks for a private key.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import BaseModel, Field

from web3_risk_mcp import __version__
from web3_risk_mcp.analysis.token import check_token_risk as token_risk
from web3_risk_mcp.analysis.wallet import get_wallet_profile as wallet_profile
from web3_risk_mcp.chains import CHAINS, Chain, get_chain, normalize_address
from web3_risk_mcp.config import get_settings
from web3_risk_mcp.errors import InvalidInputError
from web3_risk_mcp.models import TokenRiskReport, WalletProfile
from web3_risk_mcp.services import Services

INSTRUCTIONS = """\
This server investigates EVM wallets, tokens, and smart contracts for risk.
It is read-only: it never asks for private keys and never signs or sends transactions.
Start with score_risk for a quick verdict, then use the other tools for detail.
Always tell the user which data sources failed (see `sources` and `data_gaps`):
missing data is not proof that something is safe.
"""

# Hints for MCP clients: these tools only read public data from the internet.
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

AddressArg = Annotated[str, Field(description="An EVM address: 0x followed by 40 hex characters.")]
ChainArg = Annotated[
    str,
    Field(description="Chain name or ID: ethereum, base, arbitrum, polygon, or bsc."),
]


@dataclass
class AppState:
    services: Services


class ChainInfo(BaseModel):
    key: str
    name: str
    chain_id: int
    native_symbol: str
    explorer_url: str
    full_history_on_free_etherscan_plan: bool


class ChainList(BaseModel):
    chains: list[ChainInfo]


def _parse(address: str, chain: str) -> tuple[str, Chain]:
    try:
        return normalize_address(address), get_chain(chain)
    except InvalidInputError as exc:
        raise ToolError(str(exc)) from exc


def _services(ctx: Context) -> Services:
    return ctx.request_context.lifespan_context.services


def create_server(services_factory: Callable[[], Services] | None = None) -> MCPServer:
    """Build the server. Tests pass their own `services_factory` with mocked HTTP."""

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[AppState]:
        services = services_factory() if services_factory else Services(get_settings())
        try:
            yield AppState(services=services)
        finally:
            await services.aclose()

    mcp = MCPServer(
        name="web3-risk-mcp",
        title="Web3 Risk Investigator",
        instructions=INSTRUCTIONS,
        version=__version__,
        lifespan=lifespan,
    )

    @mcp.tool(annotations=READ_ONLY)
    async def get_wallet_profile(
        address: AddressArg, ctx: Context, chain: ChainArg = "ethereum"
    ) -> WalletProfile:
        """Describe a wallet: age, balance, transaction count, top counterparties,
        tokens it used recently, activity patterns, and any known bad-actor labels.
        """
        addr, ch = _parse(address, chain)
        return await wallet_profile(_services(ctx), ch, addr)

    @mcp.tool(annotations=READ_ONLY)
    async def check_token_risk(
        token_address: AddressArg, ctx: Context, chain: ChainArg = "ethereum"
    ) -> TokenRiskReport:
        """Check an ERC-20 token for scam signs before buying it: honeypot (cannot sell),
        mint, blacklist, and pause powers, buy/sell tax, owner and holder concentration,
        liquidity size, and whether liquidity is locked.
        """
        addr, ch = _parse(token_address, chain)
        return await token_risk(_services(ctx), ch, addr)

    @mcp.tool(annotations=READ_ONLY)
    def list_supported_chains() -> ChainList:
        """List the chains this server can investigate."""
        return ChainList(
            chains=[
                ChainInfo(
                    key=c.key,
                    name=c.name,
                    chain_id=c.chain_id,
                    native_symbol=c.native_symbol,
                    explorer_url=c.explorer_url,
                    full_history_on_free_etherscan_plan=c.etherscan_free_history,
                )
                for c in CHAINS.values()
            ]
        )

    return mcp
