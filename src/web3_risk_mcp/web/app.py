"""The Arc Safe Send web app.

Routes:
    GET  /             the single-page front end
    POST /api/check    run the risk check for one address
    GET  /api/config   chains and settings the page needs
    GET  /healthz      a simple "I am up" answer for the host

The server only reads public data. It never asks for a private key and never
signs or sends a transaction. Payments in the page are signed by the user's
own browser wallet.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from web3_risk_mcp import __version__
from web3_risk_mcp.analysis.score import RiskScore, score_risk
from web3_risk_mcp.chains import CHAINS, Chain, get_chain, normalize_address
from web3_risk_mcp.config import get_settings
from web3_risk_mcp.errors import InvalidInputError
from web3_risk_mcp.scoring import RULES_VERSION
from web3_risk_mcp.services import Services
from web3_risk_mcp.web.advice import SendAdvice, send_advice
from web3_risk_mcp.web.limits import ResultCache, WindowLimiter, client_ip
from web3_risk_mcp.web.settings import WebSettings

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEFAULT_CHAIN = "arc"
# Results where a data source failed are kept only this long, so a short
# outage does not stick.
DEGRADED_CACHE_SECONDS = 60

# The page loads nothing from other sites, so the browser can block anything else.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


class CheckRequest(BaseModel):
    address: str = Field(max_length=100, description="The address to check (0x + 40 hex).")
    chain: str = Field(default=DEFAULT_CHAIN, max_length=40)


class CheckResponse(BaseModel):
    result: RiskScore
    explorer_url: str
    checked_at: datetime
    cached: bool = Field(description="True if this answer came from the cache.")
    send_advice: SendAdvice


class _Checker:
    """Runs checks with a cache, per-visitor limits, and a cap on parallel work."""

    def __init__(self, web: WebSettings) -> None:
        self.web = web
        self.services: Services | None = None
        self.cache = ResultCache()
        self.inflight: dict[str, asyncio.Task] = {}
        self.parallel = asyncio.Semaphore(web.web_max_parallel_checks)
        self.limits = [
            (
                WindowLimiter(web.web_checks_per_minute, 60),
                False,
                f"You can run {web.web_checks_per_minute} new checks per minute.",
            ),
            (
                WindowLimiter(web.web_checks_per_hour, 3600),
                False,
                f"You can run {web.web_checks_per_hour} new checks per hour.",
            ),
            (
                WindowLimiter(web.web_checks_per_day, 86400),
                True,
                "This free demo has used its daily check limit. Please try again tomorrow, "
                "or run the open-source tool yourself.",
            ),
        ]

    def blocked(self, ip: str) -> tuple[float, str]:
        """How long this visitor must wait, and why. (0, "") means go ahead."""
        for limiter, shared, message in self.limits:
            wait = limiter.wait_time("all" if shared else ip)
            if wait > 0:
                return wait, message
        return 0.0, ""

    def record(self, ip: str) -> None:
        for limiter, shared, _ in self.limits:
            limiter.record("all" if shared else ip)

    async def run(self, key: str, chain: Chain, address: str) -> tuple[RiskScore, datetime]:
        assert self.services is not None
        async with self.parallel:
            result = await score_risk(self.services, chain, address)
        checked_at = datetime.now(UTC)
        ttl = self.web.web_result_cache_seconds
        if result.confidence != "high":
            ttl = min(ttl, DEGRADED_CACHE_SECONDS)
        self.cache.set(key, (result, checked_at), ttl)
        return result, checked_at


def _error(status: int, message: str, **extra) -> JSONResponse:
    headers = {"Retry-After": str(extra["retry_after"])} if "retry_after" in extra else None
    return JSONResponse({"error": message, **extra}, status_code=status, headers=headers)


def create_app(
    web: WebSettings | None = None,
    services_factory: Callable[[], Services] | None = None,
) -> FastAPI:
    """Build the app. Tests pass their own settings and mocked services."""
    web = web or WebSettings()
    checker = _Checker(web)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        checker.services = services_factory() if services_factory else Services(get_settings())
        try:
            yield
        finally:
            await checker.services.aclose()

    app = FastAPI(
        title="Arc Safe Send",
        description="A read-only risk check to run before you send USDC on Arc.",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(RequestValidationError)
    async def bad_request(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return _error(400, 'Send JSON like {"address": "0x...", "chain": "arc"}.')

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/api/config")
    async def config() -> dict:
        arc = CHAINS["arc"]
        return {
            "version": __version__,
            "rules_version": RULES_VERSION,
            "default_chain": DEFAULT_CHAIN,
            "chains": [
                {
                    "key": c.key,
                    "name": c.name,
                    "chain_id": c.chain_id,
                    "native_symbol": c.native_symbol,
                    "explorer_url": c.explorer_url,
                }
                # Arc first: it is what this app is built for.
                for c in sorted(CHAINS.values(), key=lambda c: c.key != DEFAULT_CHAIN)
            ],
            # What a browser wallet needs to add Arc. Always the public RPC, never a
            # private URL from the server settings, which could contain a key.
            "arc": {
                "chain_id": arc.chain_id,
                "chain_id_hex": hex(arc.chain_id),
                "name": arc.name,
                "rpc_url": arc.default_rpc_url,
                "explorer_url": arc.explorer_url,
                "native_symbol": arc.native_symbol,
                "native_decimals": 18,
            },
            "attestation_contract": web.attestation_contract or None,
        }

    @app.post("/api/check", response_model=CheckResponse)
    async def check(body: CheckRequest, request: Request):
        try:
            address = normalize_address(body.address)
            chain = get_chain(body.chain)
        except InvalidInputError as exc:
            return _error(400, str(exc))

        key = f"{chain.key}:{address}"
        cached = checker.cache.get(key)
        if cached is not None:
            result, checked_at = cached
            from_cache = True
        else:
            task = checker.inflight.get(key)
            if task is None:
                # Only new checks count toward the limits.
                ip = client_ip(request, web.web_client_ip_header)
                wait, reason = checker.blocked(ip)
                if wait > 0:
                    return _error(429, reason, retry_after=math.ceil(wait))
                checker.record(ip)
                task = asyncio.create_task(checker.run(key, chain, address))
                checker.inflight[key] = task
                task.add_done_callback(lambda _t: checker.inflight.pop(key, None))
            try:
                result, checked_at = await asyncio.shield(task)
            except Exception:
                logger.exception("Check failed for %s", key)
                return _error(500, "The check failed unexpectedly. Please try again.")
            from_cache = False

        return CheckResponse(
            result=result,
            explorer_url=f"{chain.explorer_url}/address/{address}",
            checked_at=checked_at,
            cached=from_cache,
            send_advice=send_advice(result, chain),
        )

    return app
