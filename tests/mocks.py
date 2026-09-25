"""Helpers that fake each API with respx, so tests never touch the network."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import respx

from web3_risk_mcp.chains import Chain
from web3_risk_mcp.clients import etherscan, goplus


def ok(result: Any) -> dict[str, Any]:
    return {"status": "1", "message": "OK", "result": result}


def mock_etherscan(handlers: dict[str, Any]) -> respx.Route:
    """Answer Etherscan calls by `action`. A value may be a result or a function of params.

    A value that is an httpx.Response is returned as is (use it for errors).
    Unknown actions get an empty list.
    """

    def reply(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        handler = handlers.get(params["action"], [])
        if callable(handler):
            handler = handler(params)
        if isinstance(handler, httpx.Response):
            return handler
        if isinstance(handler, dict) and "status" in handler:
            return httpx.Response(200, json=handler)
        return httpx.Response(200, json=ok(handler))

    return respx.get(etherscan.BASE_URL).mock(side_effect=reply)


def etherscan_error(text: str) -> dict[str, Any]:
    return {"status": "0", "message": "NOTOK", "result": text}


def mock_goplus_address(result: dict[str, Any] | None = None, *, code: int = 1) -> respx.Route:
    return respx.get(url__regex=rf"{goplus.BASE_URL}/address_security/0x[0-9a-f]+").mock(
        return_value=httpx.Response(
            200, json={"code": code, "message": "OK", "result": result or {}}
        )
    )


def mock_goplus_address_by(table: dict[str, dict[str, Any]]) -> respx.Route:
    def reply(request: httpx.Request) -> httpx.Response:
        addr = request.url.path.rsplit("/", 1)[-1].lower()
        return httpx.Response(200, json={"code": 1, "result": table.get(addr, {})})

    return respx.get(url__regex=rf"{goplus.BASE_URL}/address_security/0x[0-9a-f]+").mock(
        side_effect=reply
    )


def mock_goplus_token(chain: Chain, token: str, result: dict[str, Any] | None) -> respx.Route:
    body = {"code": 1, "message": "OK", "result": {token.lower(): result} if result else {}}
    return respx.get(f"{goplus.BASE_URL}/token_security/{chain.chain_id}").mock(
        return_value=httpx.Response(200, json=body)
    )


def mock_dexscreener(chain: Chain, token: str, pairs: list[dict[str, Any]]) -> respx.Route:
    return respx.get(f"https://api.dexscreener.com/tokens/v1/{chain.dexscreener_id}/{token}").mock(
        return_value=httpx.Response(200, json=pairs)
    )


RpcHandler = Callable[[list[Any]], Any] | Any


def mock_rpc(chain: Chain, handlers: dict[str, RpcHandler]) -> respx.Route:
    """Answer JSON-RPC calls by method. Unknown methods return an error."""

    def reply(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        method, params = payload["method"], payload["params"]
        if method not in handlers:
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": 1, "error": {"message": "execution reverted"}}
            )
        handler = handlers[method]
        result = handler(params) if callable(handler) else handler
        if isinstance(result, Exception):
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": 1, "error": {"message": str(result)}}
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    return respx.post(chain.default_rpc_url).mock(side_effect=reply)
