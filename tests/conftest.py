import httpx
import pytest
from pydantic import SecretStr

from web3_risk_mcp.config import Settings
from web3_risk_mcp.services import Services


@pytest.fixture
def settings():
    return Settings(
        _env_file=None,
        etherscan_api_key=SecretStr("TESTKEY"),
        http_max_retries=1,
        cache_ttl_seconds=60,
        etherscan_requests_per_second=1000,
        goplus_requests_per_second=1000,
        dexscreener_requests_per_second=1000,
        rpc_requests_per_second=1000,
    )


@pytest.fixture
async def services(settings):
    async with httpx.AsyncClient() as client:
        svc = Services(settings, client=client)
        for source in (svc.etherscan.http, svc.goplus.http, svc.dexscreener.http, svc.rpc.http):
            source.backoff_base = 0.001
        yield svc
